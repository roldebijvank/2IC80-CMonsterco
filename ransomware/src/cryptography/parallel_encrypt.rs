use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use std::path::PathBuf;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use anyhow::Result;
use sodiumoxide::crypto::aead::xchacha20poly1305_ietf as aead;
use sodiumoxide::crypto::box_::PublicKey;

use crate::cryptography::chunk::{
    ReadMessage, FileTask, EncryptedChunk, CHUNK_SIZE, CHANNEL_BOUND, EncryptionStats
};
use crate::cryptography::keys::{generate_sym_key, encrypt_key};
use crate::debug_println;

// ============================================================================
// FILE READER FUNCTIONS
// ============================================================================

/// Reads a file and sends chunks to the encryption pipeline
/// 
/// This function:
/// 1. Opens the file asynchronously
/// 2. Reads CHUNK_SIZE bytes at a time
/// 3. Sends chunks via mpsc channel (automatically blocks on backpressure)
/// 4. Sends FileComplete message when done
/// 5. Handles both chunked (large) and non-chunked (small) files
///
/// # Arguments
/// * `task` - File metadata including path and whether to chunk
/// * `tx` - Sender for the read channel (bounded channel provides backpressure)
/// * `stats` - Optional statistics tracker
///
/// # Returns
/// * `Ok(())` if file was read successfully
/// * `Err` if file reading failed
///
/// # Backpressure
/// The bounded channel automatically provides backpressure - if encryption workers
/// are slower than reading, the `tx.send().await` will block until space is available.
async fn file_reader_task(
    task: FileTask,
    tx: mpsc::Sender<ReadMessage>,
    stats: Option<Arc<EncryptionStats>>,
) -> Result<()> {
    debug_println!("Reader: Starting file {:?} (size: {} bytes, chunk: {})", 
                   task.original_path, task.size, task.should_chunk);
    
    let mut file = File::open(&task.original_path).await?;
    
    if !task.should_chunk {
        // Small file: read entire file as single chunk
        debug_println!("Reader: Reading small file {:?} as single chunk", task.original_path);
        
        let mut data = Vec::with_capacity(task.size as usize);
        file.read_to_end(&mut data).await?;
        
        tx.send(ReadMessage::Chunk {
            file_id: task.file_id,
            sequence: 0,
            data,
            is_last: true,
        }).await.map_err(|_| anyhow::anyhow!("Read channel closed"))?;
        
    } else {
        // Large file: chunk it
        debug_println!("Reader: Chunking large file {:?}", task.original_path);
        
        let mut sequence = 0u32;
        let mut buffer = vec![0u8; CHUNK_SIZE];
        
        loop {
            let bytes_read = file.read(&mut buffer).await?;
            
            if bytes_read == 0 {
                // EOF reached
                break;
            }
            
            let is_last = bytes_read < CHUNK_SIZE;
            let chunk_data = buffer[..bytes_read].to_vec();
            
            debug_println!("Reader: Sending chunk {} for file {} ({} bytes, last: {})",
                          sequence, task.file_id, bytes_read, is_last);
            
            tx.send(ReadMessage::Chunk {
                file_id: task.file_id,
                sequence,
                data: chunk_data,
                is_last,
            }).await.map_err(|_| anyhow::anyhow!("Read channel closed"))?;
            
            sequence += 1;
            
            if is_last {
                break;
            }
        }
    }
    
    // Send completion message
    tx.send(ReadMessage::FileComplete {
        file_id: task.file_id,
        original_path: task.original_path.clone(),
    }).await.map_err(|_| anyhow::anyhow!("Read channel closed"))?;
    
    debug_println!("Reader: Completed file {:?}", task.original_path);
    
    Ok(())
}

/// Spawns multiple file reader tasks
/// 
/// # Arguments
/// * `tasks` - Vector of file tasks to process
/// * `tx` - Sender for the read channel
/// * `stats` - Optional statistics tracker
///
/// # Returns
/// * JoinHandle that completes when all readers finish
pub fn spawn_file_readers(
    tasks: Vec<FileTask>,
    tx: mpsc::Sender<ReadMessage>,
    stats: Option<Arc<EncryptionStats>>,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        debug_println!("Spawning {} file readers", tasks.len());
        
        let mut handles = Vec::new();
        
        for task in tasks {
            let tx_clone = tx.clone();
            let stats_clone = stats.clone();
            let handle = tokio::spawn(async move {
                if let Err(e) = file_reader_task(task.clone(), tx_clone, stats_clone).await {
                    eprintln!("Error reading file {:?}: {}", task.original_path, e);
                    return Err(e);
                }
                Ok(())
            });
            handles.push(handle);
        }
        
        // Wait for all readers to complete
        for handle in handles {
            handle.await??;
        }
        
        // Drop the sender to signal no more messages
        drop(tx);
        
        debug_println!("All file readers completed");
        Ok(())
    })
}

// ============================================================================
// ENCRYPTION WORKER FUNCTIONS
// ============================================================================

/// Per-file encryption context
/// Stores the symmetric key and tracks metadata for each file being encrypted
#[derive(Clone)]
pub struct FileEncryptionContext {
    /// Symmetric key for this file (same key for all chunks)
    pub sym_key: aead::Key,
    /// Encrypted version of the symmetric key (for storage in header)
    pub encrypted_sym_key: Vec<u8>,
    /// Total chunks seen so far
    pub chunks_processed: u32,
}

/// Encryption worker that processes chunks from the read channel
///
/// This function:
/// 1. Receives ReadMessages from the channel
/// 2. Generates symmetric key on first chunk of each file
/// 3. Encrypts chunks with unique nonces
/// 4. Sends encrypted chunks downstream
/// 5. Uses spawn_blocking for CPU-intensive encryption
///
/// # Arguments
/// * `worker_id` - Identifier for this worker (for debugging)
/// * `rx` - Receiver for read messages
/// * `tx` - Sender for encrypted chunks
/// * `pk` - Public key for encrypting symmetric keys
/// * `file_contexts` - Shared map of file encryption contexts
/// * `stats` - Optional statistics tracker
///
/// # Implementation Notes
/// - Uses Arc<Mutex<HashMap>> to track per-file contexts across all workers
/// - Each file gets a single symmetric key, but each chunk gets a unique nonce
/// - CPU-intensive encryption happens in spawn_blocking to avoid blocking async runtime
async fn encryption_worker(
    worker_id: usize,
    mut rx: mpsc::Receiver<ReadMessage>,
    tx: mpsc::Sender<EncryptedChunk>,
    pk: PublicKey,
    file_contexts: Arc<Mutex<HashMap<u64, FileEncryptionContext>>>,
    stats: Option<Arc<EncryptionStats>>,
) -> Result<()> {
    debug_println!("Encryption worker {} started", worker_id);
    
    while let Some(message) = rx.recv().await {
        match message {
            ReadMessage::Chunk { file_id, sequence, data, is_last } => {
                debug_println!("Worker {}: Processing chunk {} for file {} ({} bytes)",
                              worker_id, sequence, file_id, data.len());
                
                // Get or create encryption context for this file
                let (sym_key, encrypted_sym_key) = {
                    let mut contexts = file_contexts.lock().await;
                    
                    let context = contexts.entry(file_id).or_insert_with(|| {
                        debug_println!("Worker {}: Generating new key for file {}", worker_id, file_id);
                        
                        // First chunk for this file - generate keys
                        let (key, _) = generate_sym_key().expect("Failed to generate key");
                        let encrypted_key = encrypt_key(&pk, key.clone())
                            .expect("Failed to encrypt key");
                        
                        FileEncryptionContext {
                            sym_key: key,
                            encrypted_sym_key: encrypted_key,
                            chunks_processed: 0,
                        }
                    });
                    
                    context.chunks_processed += 1;
                    (context.sym_key.clone(), context.encrypted_sym_key.clone())
                };
                
                // Generate unique nonce for this chunk
                let nonce = aead::gen_nonce();
                let nonce_bytes = *nonce.as_ref();
                
                // Perform encryption in blocking thread pool (CPU-intensive)
                let sym_key_clone = sym_key.clone();
                let nonce_clone = nonce.clone();
                let data_len = data.len();
                
                let encrypted_data = tokio::task::spawn_blocking(move || {
                    aead::seal(&data, None, &nonce_clone, &sym_key_clone)
                }).await?;
                
                debug_println!("Worker {}: Encrypted chunk {} for file {} ({} -> {} bytes)",
                              worker_id, sequence, file_id, data_len, encrypted_data.len());
                
                // Update stats
                if let Some(ref stats) = stats {
                    stats.increment_bytes(data_len as u64);
                }
                
                // Send encrypted chunk
                tx.send(EncryptedChunk {
                    file_id,
                    sequence,
                    data: encrypted_data,
                    nonce: nonce_bytes,
                    is_last,
                }).await.map_err(|_| anyhow::anyhow!("Encrypt channel closed"))?;
            }
            
            ReadMessage::FileComplete { file_id, original_path } => {
                debug_println!("Worker {}: File {} complete notification", worker_id, file_id);
                // Keep context for the writer to use
                // Don't forward anything for now as per requirements
            }
        }
    }
    
    debug_println!("Encryption worker {} finished", worker_id);
    Ok(())
}

/// Spawns multiple encryption worker tasks
///
/// # Arguments
/// * `num_workers` - Number of parallel encryption workers
/// * `rx` - Receiver for read messages
/// * `tx` - Sender for encrypted chunks
/// * `pk` - Public key for encrypting symmetric keys
/// * `file_contexts` - Shared map for file encryption contexts
/// * `stats` - Optional statistics tracker
///
/// # Returns
/// * JoinHandle that completes when all workers finish
pub fn spawn_encryption_workers(
    num_workers: usize,
    mut rx: mpsc::Receiver<ReadMessage>,
    tx: mpsc::Sender<EncryptedChunk>,
    pk: PublicKey,
    file_contexts: Arc<Mutex<HashMap<u64, FileEncryptionContext>>>,
    stats: Option<Arc<EncryptionStats>>,
) -> tokio::task::JoinHandle<Result<()>> {
    debug_println!("Spawning {} encryption workers", num_workers);
    
    tokio::spawn(async move {
        let mut handles = Vec::new();
        
        // Create channels for each worker
        let (worker_txs, worker_rxs): (Vec<_>, Vec<_>) = (0..num_workers)
            .map(|_| mpsc::channel(CHANNEL_BOUND))
            .unzip();
        
        // Spawn workers
        for (worker_id, worker_rx) in worker_rxs.into_iter().enumerate() {
            let tx_clone = tx.clone();
            let pk_clone = pk.clone();
            let contexts_clone = file_contexts.clone();
            let stats_clone = stats.clone();
            
            let handle = tokio::spawn(async move {
                if let Err(e) = encryption_worker(
                    worker_id,
                    worker_rx,
                    tx_clone,
                    pk_clone,
                    contexts_clone,
                    stats_clone,
                ).await {
                    eprintln!("Encryption worker {} error: {}", worker_id, e);
                    return Err(e);
                }
                Ok(())
            });
            handles.push(handle);
        }
        
        // Dispatcher: round-robin messages to workers
        let mut next_worker = 0;
        while let Some(message) = rx.recv().await {
            // For FileComplete messages, broadcast to all workers
            // For Chunk messages, send to next worker in round-robin
            match &message {
                ReadMessage::FileComplete { .. } => {
                    // Broadcast to all workers
                    for worker_tx in &worker_txs {
                        let _ = worker_tx.send(message.clone()).await;
                    }
                }
                ReadMessage::Chunk { .. } => {
                    if let Err(_) = worker_txs[next_worker].send(message).await {
                        eprintln!("Worker {} channel closed", next_worker);
                        return Err(anyhow::anyhow!("Worker channel closed"));
                    }
                    next_worker = (next_worker + 1) % num_workers;
                }
            }
        }
        
        // Drop all worker senders to signal completion
        drop(worker_txs);
        
        // Wait for all workers
        for handle in handles {
            handle.await??;
        }
        
        drop(tx);
        
        debug_println!("All encryption workers completed");
        Ok(())
    })
}

// ============================================================================
// FILE WRITER FUNCTIONS
// ============================================================================

use std::collections::BTreeMap;
use tokio::io::AsyncWriteExt;
use crate::cryptography::chunk::{FileHeader, ChunkInfo};

/// Tracks the state of a file being written
pub struct FileWriteState {
    /// Output path for encrypted file
    pub output_path: PathBuf,
    /// Original path (for deletion after successful write)
    pub original_path: PathBuf,
    /// Original filename (relative to encryption root)
    pub original_filename: String,
    /// Original file size
    pub original_size: u64,
    /// Encrypted symmetric key for this file
    pub encrypted_sym_key: Vec<u8>,
    /// Buffered chunks waiting to be written (sequence -> chunk)
    pub buffered_chunks: BTreeMap<u32, EncryptedChunk>,
    /// Next expected sequence number
    pub next_sequence: u32,
    /// Total number of chunks for this file
    pub total_chunks: Option<u32>,
    /// All chunk metadata collected so far
    pub chunk_metadata: Vec<ChunkInfo>,
}

impl FileWriteState {
    pub fn new(
        output_path: PathBuf,
        original_path: PathBuf,
        original_filename: String,
        original_size: u64,
        encrypted_sym_key: Vec<u8>,
    ) -> Self {
        Self {
            output_path,
            original_path,
            original_filename,
            original_size,
            encrypted_sym_key,
            buffered_chunks: BTreeMap::new(),
            next_sequence: 0,
            total_chunks: None,
            chunk_metadata: Vec::new(),
        }
    }
    
    /// Adds a chunk to the buffer
    pub fn add_chunk(&mut self, chunk: EncryptedChunk) -> Result<()> {
        debug_println!("Writer: Buffering chunk {} for file {} (is_last: {})",
                      chunk.sequence, chunk.file_id, chunk.is_last);
        
        if chunk.is_last {
            self.total_chunks = Some(chunk.sequence + 1);
            debug_println!("Writer: File {} has {} total chunks", chunk.file_id, chunk.sequence + 1);
        }
        
        // Store chunk metadata
        let chunk_info = ChunkInfo {
            sequence: chunk.sequence,
            encrypted_size: chunk.data.len(),
            nonce: chunk.nonce,
        };
        self.chunk_metadata.push(chunk_info);
        
        self.buffered_chunks.insert(chunk.sequence, chunk);
        self.next_sequence += 1;
        
        Ok(())
    }
    
    /// Finalizes the file: writes header + all chunks, verifies completion, then deletes original
    pub async fn finalize(&mut self) -> Result<()> {
        debug_println!("Writer: Finalizing file {:?}", self.output_path);
        
        // Verify completion BEFORE writing
        if !self.is_complete() {
            return Err(anyhow::anyhow!(
                "Cannot finalize incomplete file: expected {} chunks, have {}",
                self.total_chunks.unwrap_or(0),
                self.buffered_chunks.len()
            ));
        }
        
        // Create header
        let header = FileHeader {
            original_filename: self.original_filename.clone(),
            original_size: self.original_size,
            chunk_count: self.total_chunks.ok_or("Total chunks not set")?,
            chunks: self.chunk_metadata.clone(),
            encrypted_sym_key: self.encrypted_sym_key.clone(),
        };
        
        let header_bytes = header.to_bytes()?;
        
        debug_println!("Writer: Writing {} chunks to {:?}", self.buffered_chunks.len(), self.output_path);
        
        // Open file for writing
        let mut file = File::create(&self.output_path).await?;
        
        // Write header
        file.write_all(&header_bytes).await?;
        
        // Write all chunks in order
        for (seq, chunk) in self.buffered_chunks.iter() {
            file.write_all(&chunk.data).await?;
            debug_println!("Writer: Wrote chunk {} ({} bytes)", seq, chunk.data.len());
        }
        
        // Ensure all data is flushed
        file.flush().await?;
        
        debug_println!("Writer: Successfully wrote file {:?}", self.output_path);
        
        // Verify file was written correctly before deleting original
        let written_metadata = tokio::fs::metadata(&self.output_path).await?;
        let expected_size = header_bytes.len() + 
                           self.buffered_chunks.values().map(|c| c.data.len()).sum::<usize>();
        
        if written_metadata.len() != expected_size as u64 {
            return Err(anyhow::anyhow!(
                "Written file size mismatch: expected {}, got {}",
                expected_size,
                written_metadata.len()
            ));
        }
        
        // Delete original file only after verification
        tokio::fs::remove_file(&self.original_path).await?;
        
        debug_println!("Writer: Deleted original file {:?}", self.original_path);
        
        Ok(())
    }
    
    /// Check if this file is complete and ready to finalize
    pub fn is_complete(&self) -> bool {
        if let Some(total) = self.total_chunks {
            let all_chunks_present = self.buffered_chunks.len() == total as usize;
            let sequential = self.next_sequence == total;
            
            debug_println!("Writer: Checking completion - chunks: {}/{}, sequential: {}",
                          self.buffered_chunks.len(), total, sequential);
            
            all_chunks_present && sequential
        } else {
            false
        }
    }
}
