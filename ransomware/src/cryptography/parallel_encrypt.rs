//! Parallel encryption pipeline for files.
//!
//! This module provides functions for reading, encrypting, and writing files
//! in a parallel pipeline architecture to maximize throughput.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use sodiumoxide::crypto::aead::xchacha20poly1305_ietf as aead;
use sodiumoxide::crypto::box_::PublicKey;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::sync::{mpsc, Mutex};

use crate::cryptography::chunk::{
    ReadMessage, EncryptedChunk, FileTask, EncryptionStats,
    CHUNK_SIZE, CHANNEL_BOUND, DEBUG_ENABLED,
};
use crate::cryptography::keys::{generate_sym_key, encrypt_key};
use crate::debug_log;

// ============================================================================
// File Reader
// ============================================================================

/// Reads a file and sends chunks to the encryption pipeline.
///
/// This function:
/// 1. Opens the file asynchronously
/// 2. Reads CHUNK_SIZE bytes at a time (or entire file if should_chunk is false)
/// 3. Sends chunks via mpsc channel (automatically blocks on backpressure)
/// 4. Sends FileComplete message when done
///
/// # Arguments
/// * `task` - File metadata including path and whether to chunk
/// * `tx` - Sender for the read channel (bounded channel provides backpressure)
/// * `stats` - Optional statistics tracker
///
/// # Returns
/// * `Ok(())` if file was read successfully
/// * `Err` if file reading failed (stops encryption on first error per requirements)
///
/// # Backpressure
/// The bounded channel automatically provides backpressure - if encryption workers
/// are slower than reading, the `tx.send().await` will block until space is available.
pub async fn file_reader_task(
    task: FileTask,
    tx: mpsc::Sender<ReadMessage>,
    stats: Option<Arc<EncryptionStats>>,
) -> Result<()> {
    debug_log!("Reader: Opening file {:?} (size: {} bytes, chunked: {})",
               task.original_path, task.size, task.should_chunk);

    let mut file = File::open(&task.original_path).await
        .map_err(|e| anyhow::anyhow!("Failed to open file {:?}: {}", task.original_path, e))?;

    if !task.should_chunk {
        // Small file: read entire file as single chunk
        debug_log!("Reader: Reading small file {:?} as single chunk", task.original_path);

        let mut data = Vec::with_capacity(task.size as usize);
        file.read_to_end(&mut data).await
            .map_err(|e| anyhow::anyhow!("Failed to read file {:?}: {}", task.original_path, e))?;

        let bytes_read = data.len();

        tx.send(ReadMessage::Chunk {
            file_id: task.file_id,
            sequence: 0,
            data,
            is_last: true,
        }).await.map_err(|_| anyhow::anyhow!("Read channel closed unexpectedly"))?;

        // Update stats
        if let Some(ref s) = stats {
            s.add_bytes_processed(bytes_read as u64);
        }

        debug_log!("Reader: Completed small file {:?}", task.original_path);
    } else {
        // Large file: chunk it
        debug_log!("Reader: Chunking large file {:?}", task.original_path);

        let mut sequence = 0u32;
        let mut buffer = vec![0u8; CHUNK_SIZE];
        let mut total_bytes_read = 0usize;

        loop {
            // Read up to CHUNK_SIZE bytes
            let bytes_read = read_exact_or_eof(&mut file, &mut buffer).await?;

            if bytes_read == 0 {
                // EOF reached with no data - file was exactly divisible by CHUNK_SIZE
                // We already sent the last chunk in previous iteration
                debug_log!("Reader: EOF reached after {} chunks for {:?}",
                          sequence, task.original_path);
                break;
            }

            total_bytes_read += bytes_read;
            let is_last = bytes_read < CHUNK_SIZE;

            // Create chunk data (only copy the bytes we read)
            let chunk_data = buffer[..bytes_read].to_vec();

            debug_log!("Reader: Sending chunk {} for file {} ({} bytes, is_last: {})",
                      sequence, task.file_id, bytes_read, is_last);

            tx.send(ReadMessage::Chunk {
                file_id: task.file_id,
                sequence,
                data: chunk_data,
                is_last,
            }).await.map_err(|_| anyhow::anyhow!("Read channel closed unexpectedly"))?;

            // Update stats
            if let Some(ref s) = stats {
                s.add_bytes_processed(bytes_read as u64);
            }

            sequence += 1;

            if is_last {
                debug_log!("Reader: Completed large file {:?} ({} chunks, {} bytes)",
                          task.original_path, sequence, total_bytes_read);
                break;
            }
        }
    }

    // Send completion message
    tx.send(ReadMessage::FileComplete {
        file_id: task.file_id,
        original_path: task.original_path.clone(),
    }).await.map_err(|_| anyhow::anyhow!("Read channel closed unexpectedly"))?;

    debug_log!("Reader: Sent FileComplete for file {}", task.file_id);

    Ok(())
}

/// Helper to read exactly buffer.len() bytes or until EOF.
/// Returns the number of bytes actually read.
async fn read_exact_or_eof(file: &mut File, buffer: &mut [u8]) -> Result<usize> {
    let mut total_read = 0;

    while total_read < buffer.len() {
        let bytes_read = file.read(&mut buffer[total_read..]).await?;
        if bytes_read == 0 {
            // EOF reached
            break;
        }
        total_read += bytes_read;
    }

    Ok(total_read)
}

/// Spawns file reader tasks for all files.
///
/// # Arguments
/// * `tasks` - Vector of file tasks to process
/// * `tx` - Sender for the read channel
/// * `stats` - Optional statistics tracker
///
/// # Returns
/// * `Ok(JoinHandle)` that completes when all readers finish
/// * Returns `Err` immediately if any file fails (stops on first error)
pub fn spawn_file_readers(
    tasks: Vec<FileTask>,
    tx: mpsc::Sender<ReadMessage>,
    stats: Option<Arc<EncryptionStats>>,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        debug_log!("Readers: Starting {} file reader tasks", tasks.len());

        for task in tasks {
            let tx_clone = tx.clone();
            let stats_clone = stats.clone();
            let task_path = task.original_path.clone();

            // Process files sequentially to stop on first error
            // (could be parallelized if we wanted to continue on errors)
            if let Err(e) = file_reader_task(task, tx_clone, stats_clone).await {
                // Stop on first error per requirements
                if let Some(ref s) = stats {
                    s.inc_files_failed();
                }
                return Err(anyhow::anyhow!("Failed to read file {:?}: {}", task_path, e));
            }
        }

        debug_log!("Readers: All file reader tasks completed");

        // Drop the sender to signal no more messages
        drop(tx);

        Ok(())
    })
}

// ============================================================================
// Encryption Worker
// ============================================================================

/// Per-file encryption context.
/// Stores the symmetric key and tracks state for each file being encrypted.
#[derive(Debug)]
pub struct FileEncryptionContext {
    /// Symmetric key for this file (same key for all chunks of a file).
    pub sym_key: aead::Key,
    /// Encrypted version of the symmetric key (for storage in file header).
    pub encrypted_sym_key: Vec<u8>,
    /// Number of chunks processed so far.
    pub chunks_processed: u32,
}

/// Encryption worker that processes chunks from the read channel.
///
/// This function:
/// 1. Receives ReadMessages from the channel
/// 2. Generates symmetric key on first chunk of each file
/// 3. Encrypts chunks with unique random nonces
/// 4. Sends encrypted chunks downstream
/// 5. Uses spawn_blocking for CPU-intensive encryption
///
/// # Arguments
/// * `worker_id` - Identifier for this worker (for debugging)
/// * `rx` - Receiver for read messages
/// * `tx` - Sender for encrypted chunks
/// * `pk` - Public key for encrypting symmetric keys
/// * `file_contexts` - Shared map of file encryption contexts
///
/// # Returns
/// * `Ok(())` when channel closes (no more messages)
/// * `Err` if encryption fails (stops on first error)
pub async fn encryption_worker(
    worker_id: usize,
    mut rx: mpsc::Receiver<ReadMessage>,
    tx: mpsc::Sender<EncryptedChunk>,
    pk: PublicKey,
    file_contexts: Arc<Mutex<HashMap<u64, FileEncryptionContext>>>,
) -> Result<()> {
    debug_log!("Worker {}: Started", worker_id);

    while let Some(message) = rx.recv().await {
        match message {
            ReadMessage::Chunk { file_id, sequence, data, is_last } => {
                debug_log!("Worker {}: Processing chunk {} for file {} ({} bytes)",
                          worker_id, sequence, file_id, data.len());

                // Get or create encryption context for this file
                let sym_key = {
                    let mut contexts = file_contexts.lock().await;

                    let context = contexts.entry(file_id).or_insert_with(|| {
                        debug_log!("Worker {}: Creating new encryption context for file {}",
                                  worker_id, file_id);

                        // First chunk for this file - generate keys
                        let (key, _nonce) = generate_sym_key()
                            .expect("Failed to generate symmetric key");
                        let encrypted_key = encrypt_key(&pk, key.clone())
                            .expect("Failed to encrypt symmetric key");

                        FileEncryptionContext {
                            sym_key: key,
                            encrypted_sym_key: encrypted_key,
                            chunks_processed: 0,
                        }
                    });

                    context.chunks_processed += 1;
                    context.sym_key.clone()
                };

                // Generate unique random nonce for this chunk
                let nonce = aead::gen_nonce();
                let nonce_bytes: [u8; 24] = (*nonce.0).as_ref().try_into().expect("Nonce has incorrect length");

                // Perform encryption in blocking thread pool (CPU-intensive)
                let sym_key_clone = sym_key;
                let nonce_clone = nonce;
                let encrypted_data = tokio::task::spawn_blocking(move || {
                    aead::seal(&data, None, &nonce_clone, &sym_key_clone)
                }).await
                    .map_err(|e| anyhow::anyhow!("Encryption task panicked: {}", e))?;

                debug_log!("Worker {}: Encrypted chunk {} for file {} ({} -> {} bytes)",
                          worker_id, sequence, file_id, data.len(), encrypted_data.len());

                // Send encrypted chunk
                tx.send(EncryptedChunk {
                    file_id,
                    sequence,
                    data: encrypted_data,
                    nonce: nonce_bytes,
                    is_last,
                }).await.map_err(|_| anyhow::anyhow!("Encrypt channel closed unexpectedly"))?;
            }

            ReadMessage::FileComplete { file_id, original_path } => {
                // Currently not forwarding this message - kept empty per requirements
                // The writer relies on is_last flag instead
                debug_log!("Worker {}: Received FileComplete for file {} ({:?})",
                          worker_id, file_id, original_path);
            }
        }
    }

    debug_log!("Worker {}: Channel closed, shutting down", worker_id);
    Ok(())
}

/// Spawns multiple encryption worker tasks with a dispatcher.
///
/// Architecture:
/// - Single dispatcher receives from main rx channel
/// - Dispatcher round-robins Chunk messages to workers
/// - Each worker has its own receiver channel
///
/// # Arguments
/// * `num_workers` - Number of parallel encryption workers
/// * `rx` - Receiver for read messages from file readers
/// * `tx` - Sender for encrypted chunks to file writer
/// * `pk` - Public key for encrypting symmetric keys
/// * `file_contexts` - Shared map of file encryption contexts
///
/// # Returns
/// * JoinHandle that completes when all workers finish
pub fn spawn_encryption_workers(
    num_workers: usize,
    mut rx: mpsc::Receiver<ReadMessage>,
    tx: mpsc::Sender<EncryptedChunk>,
    pk: PublicKey,
    file_contexts: Arc<Mutex<HashMap<u64, FileEncryptionContext>>>,
) -> tokio::task::JoinHandle<Result<()>> {
    debug_log!("Dispatcher: Spawning {} encryption workers", num_workers);

    tokio::spawn(async move {
        // Create channels for each worker
        let (worker_txs, worker_rxs): (Vec<_>, Vec<_>) = (0..num_workers)
            .map(|_| mpsc::channel::<ReadMessage>(CHANNEL_BOUND))
            .unzip();

        // Spawn worker tasks
        let mut worker_handles = Vec::new();
        for (worker_id, worker_rx) in worker_rxs.into_iter().enumerate() {
            let tx_clone = tx.clone();
            let pk_clone = pk.clone();
            let contexts_clone = file_contexts.clone();

            let handle = tokio::spawn(async move {
                encryption_worker(
                    worker_id,
                    worker_rx,
                    tx_clone,
                    pk_clone,
                    contexts_clone,
                ).await
            });
            worker_handles.push(handle);
        }

        // Drop our clone of tx - workers have their own clones
        drop(tx);

        // Dispatcher loop: round-robin messages to workers
        let mut next_worker = 0;
        let mut error_occurred: Option<anyhow::Error> = None;

        while let Some(message) = rx.recv().await {
            match &message {
                ReadMessage::FileComplete { .. } => {
                    // Broadcast FileComplete to all workers
                    debug_log!("Dispatcher: Broadcasting FileComplete to all workers");
                    for worker_tx in &worker_txs {
                        // Clone the message for each worker
                        let _ = worker_tx.send(message.clone()).await;
                    }
                }
                ReadMessage::Chunk { file_id, sequence, .. } => {
                    debug_log!("Dispatcher: Sending chunk {} of file {} to worker {}",
                              sequence, file_id, next_worker);

                    if worker_txs[next_worker].send(message).await.is_err() {
                        error_occurred = Some(anyhow::anyhow!(
                            "Worker {} channel closed unexpectedly", next_worker
                        ));
                        break;
                    }
                    next_worker = (next_worker + 1) % num_workers;
                }
            }
        }

        debug_log!("Dispatcher: Input channel closed, waiting for workers");

        // Drop all worker senders to signal completion
        drop(worker_txs);

        // Wait for all workers and collect any errors
        for (worker_id, handle) in worker_handles.into_iter().enumerate() {
            match handle.await {
                Ok(Ok(())) => {
                    debug_log!("Dispatcher: Worker {} completed successfully", worker_id);
                }
                Ok(Err(e)) => {
                    debug_log!("Dispatcher: Worker {} failed: {}", worker_id, e);
                    if error_occurred.is_none() {
                        error_occurred = Some(e);
                    }
                }
                Err(e) => {
                    debug_log!("Dispatcher: Worker {} panicked: {}", worker_id, e);
                    if error_occurred.is_none() {
                        error_occurred = Some(anyhow::anyhow!("Worker {} panicked: {}", worker_id, e));
                    }
                }
            }
        }

        debug_log!("Dispatcher: All workers completed");

        if let Some(e) = error_occurred {
            return Err(e);
        }

        Ok(())
    })
}

// ============================================================================
// File Write State (partial implementation - structure only)
// ============================================================================

use std::collections::BTreeMap;

/// Tracks the state of a file being written.
/// Buffers out-of-order chunks until they can be written sequentially.
#[derive(Debug)]
pub struct FileWriteState {
    /// Output path for encrypted file.
    pub output_path: PathBuf,
    /// Original path (for deletion after successful write).
    pub original_path: PathBuf,
    /// Original filename (relative to encryption root).
    pub original_filename: String,
    /// Original file size.
    pub original_size: u64,
    /// Encrypted symmetric key for this file.
    pub encrypted_sym_key: Vec<u8>,
    /// Buffered chunks waiting to be written (sequence -> chunk).
    /// BTreeMap keeps chunks sorted by sequence number.
    pub buffered_chunks: BTreeMap<u32, EncryptedChunk>,
    /// Next expected sequence number.
    pub next_sequence: u32,
    /// Total number of chunks for this file (known when is_last chunk arrives).
    pub total_chunks: Option<u32>,
}

impl FileWriteState {
    /// Create a new FileWriteState.
    ///
    /// # Arguments
    /// * `output_path` - Path where encrypted file will be written
    /// * `original_path` - Original file path (for deletion after encryption)
    /// * `original_filename` - Relative filename for storage in header
    /// * `original_size` - Size of original file in bytes
    /// * `encrypted_sym_key` - Symmetric key encrypted with public key
    pub fn new(
        output_path: PathBuf,
        original_path: PathBuf,
        original_filename: String,
        original_size: u64,
        encrypted_sym_key: Vec<u8>,
    ) -> Self {
        debug_log!("FileWriteState: Creating state for {:?}", original_path);

        Self {
            output_path,
            original_path,
            original_filename,
            original_size,
            encrypted_sym_key,
            buffered_chunks: BTreeMap::new(),
            next_sequence: 0,
            total_chunks: None,
        }
    }

    /// Check if all chunks have been received and buffered.
    ///
    /// # Returns
    /// * `true` if we know the total chunk count and have received all chunks
    /// * `false` if still waiting for chunks or don't know total count yet
    pub fn is_complete(&self) -> bool {
        if let Some(total) = self.total_chunks {
            // Check if we have all chunks from 0 to total-1
            if self.buffered_chunks.len() as u32 != total {
                return false;
            }
            // Verify sequence numbers are contiguous from 0 to total-1
            for (i, (seq, _)) in self.buffered_chunks.iter().enumerate() {
                if *seq != i as u32 {
                    return false;
                }
            }
            true
        } else {
            false
        }
    }

    /// Add a chunk to the buffer.
    ///
    /// # Arguments
    /// * `chunk` - Encrypted chunk to buffer
    pub fn add_chunk(&mut self, chunk: EncryptedChunk) {
        debug_log!("FileWriteState: Adding chunk {} (is_last: {}) for {:?}",
                  chunk.sequence, chunk.is_last, self.original_path);

        if chunk.is_last {
            self.total_chunks = Some(chunk.sequence + 1);
            debug_log!("FileWriteState: Total chunks for {:?} is {}",
                      self.original_path, chunk.sequence + 1);
        }

        self.buffered_chunks.insert(chunk.sequence, chunk);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_file_write_state_is_complete() {
        let mut state = FileWriteState::new(
            PathBuf::from("test.enc"),
            PathBuf::from("test.txt"),
            "test.txt".to_string(),
            1024,
            vec![1, 2, 3],
        );

        // Initially not complete
        assert!(!state.is_complete());

        // Add first chunk (not last)
        state.add_chunk(EncryptedChunk {
            file_id: 0,
            sequence: 0,
            data: vec![1, 2, 3],
            nonce: [0u8; 24],
            is_last: false,
        });
        assert!(!state.is_complete());

        // Add last chunk
        state.add_chunk(EncryptedChunk {
            file_id: 0,
            sequence: 1,
            data: vec![4, 5, 6],
            nonce: [0u8; 24],
            is_last: true,
        });
        assert!(state.is_complete());
    }

    #[test]
    fn test_file_write_state_single_chunk() {
        let mut state = FileWriteState::new(
            PathBuf::from("small.enc"),
            PathBuf::from("small.txt"),
            "small.txt".to_string(),
            100,
            vec![1, 2, 3],
        );

        // Single chunk file (is_last = true, sequence = 0)
        state.add_chunk(EncryptedChunk {
            file_id: 0,
            sequence: 0,
            data: vec![1, 2, 3],
            nonce: [0u8; 24],
            is_last: true,
        });

        assert!(state.is_complete());
        assert_eq!(state.total_chunks, Some(1));
    }
}
