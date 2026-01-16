// parallel encryption pipeline

use std::collections::{HashMap, BTreeMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::pin::Pin;
use std::future::Future;

use anyhow::Result;
use sodiumoxide::crypto::aead::xchacha20poly1305_ietf as aead;
use sodiumoxide::crypto::box_::PublicKey;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};

use crate::cryptography::chunk::{
    ReadMessage, EncryptedChunk, FileTask, ChunkInfo, FileHeader,
    CHUNK_SIZE, CHANNEL_BOUND, SMALL_FILE_THRESHOLD,
};
use crate::cryptography::keys::{generate_sym_key, encrypt_key};
use crate::debug_log;

// 4 main "parts": recursive file discovery, file reader, encryption worker, file writer.

// ================= FILE DISCOVERY ==================
// basically just recursive traversal, but for each file
// a file encryption task is created (see below)

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FileSearchMode {
    ForEncryption,  // find regular files, skip .enc
    ForDecryption,  // find .enc files only
}

// discovers files recursively based on mode
pub async fn discover_files(
    folder_path: &Path,
    mode: FileSearchMode,
) -> Result<Vec<FileTask>> {
    let mut tasks = Vec::new();
    let mut file_id = 0u64;
    discover_files_recursive(folder_path, folder_path, mode, &mut tasks, &mut file_id).await?;
    Ok(tasks)
}

// for each file found, create a FileTask
fn discover_files_recursive<'a>(
    root: &'a Path,
    current: &'a Path,
    mode: FileSearchMode,
    tasks: &'a mut Vec<FileTask>,
    file_id: &'a mut u64,
) -> Pin<Box<dyn Future<Output = Result<()>> + 'a>> {
    Box::pin(async move {
        if current.is_file() {
            let is_enc = current.extension().map_or(false, |e| e == "enc");
            
            let should_consider = match mode {
                FileSearchMode::ForEncryption => !is_enc,
                FileSearchMode::ForDecryption => is_enc,
            };
            
            if should_consider {
                let metadata = tokio::fs::metadata(current).await?;
                let size = metadata.len();
                
                let output_path = match mode {
                    FileSearchMode::ForEncryption => {
                        PathBuf::from(format!("{}.enc", current.to_string_lossy()))
                    }
                    FileSearchMode::ForDecryption => {
                        // output determined by header, use placeholder
                        current.with_extension("")
                    }
                };
                
                let should_chunk = size > SMALL_FILE_THRESHOLD;
                
                tasks.push(FileTask {
                    file_id: *file_id,
                    original_path: current.to_path_buf(),
                    output_path,
                    size,
                    should_chunk,
                });
                
                *file_id += 1;
            }
        } else if current.is_dir() {
            let mut entries = tokio::fs::read_dir(current).await?;
            while let Some(entry) = entries.next_entry().await? {
                discover_files_recursive(root, &entry.path(), mode, tasks, file_id).await?;
            }
        }
        
        Ok(())
    })
}

// ================== FILE READER ==================
// code for file reading workers.

// reads a file and sends chunks to encryption pipeline
pub async fn worker_read(
    task: FileTask,
    tx: mpsc::Sender<ReadMessage>,
) -> Result<()> {
    debug_log!("reader: opening {:?}", task.original_path);

    let mut file = File::open(&task.original_path).await?;

    if !task.should_chunk {
        // small file - single chunk
        let mut data = Vec::with_capacity(task.size as usize);
        file.read_to_end(&mut data).await?;

        debug_log!("READER: sending chunk file_id={} seq=0 is_last=true size={}", task.file_id, data.len());
        tx.send(ReadMessage::Chunk {
            file_id: task.file_id,
            sequence: 0,
            data,
            is_last: true,
        }).await.map_err(|_| anyhow::anyhow!("channel closed"))?;
    } else {
        // large file - chunk it
        let mut sequence = 0u32;
        let mut buffer = vec![0u8; CHUNK_SIZE];

        loop {
            let bytes_read = read_full(&mut file, &mut buffer).await?;
            if bytes_read == 0 {
                // If the file size is an exact multiple of CHUNK_SIZE, send a final empty chunk with is_last=true
                if sequence > 0 {
                    debug_log!("READER: sending FINAL empty chunk file_id={} seq={} is_last=true size=0", task.file_id, sequence);
                    tx.send(ReadMessage::Chunk {
                        file_id: task.file_id,
                        sequence,
                        data: Vec::new(),
                        is_last: true,
                    }).await.map_err(|_| anyhow::anyhow!("channel closed"))?;
                }
                break;
            }

            let is_last = bytes_read < CHUNK_SIZE;
            let chunk_data = buffer[..bytes_read].to_vec();

            debug_log!("READER: sending chunk file_id={} seq={} is_last={} size={}", task.file_id, sequence, is_last, bytes_read);

            tx.send(ReadMessage::Chunk {
                file_id: task.file_id,
                sequence,
                data: chunk_data,
                is_last,
            }).await.map_err(|_| anyhow::anyhow!("channel closed"))?;

            sequence += 1;
            if is_last {
                break;
            }
        }
    }

    tx.send(ReadMessage::FileComplete {
        file_id: task.file_id,
        original_path: task.original_path.clone(),
    }).await.map_err(|_| anyhow::anyhow!("channel closed"))?;

    debug_log!("reader: done with file {}", task.file_id);
    Ok(())
}

// reads as much of the file as possible into a buffer
async fn read_full(file: &mut File, buffer: &mut [u8]) -> Result<usize> {
    let mut total = 0;
    while total < buffer.len() {
        let n = file.read(&mut buffer[total..]).await?;
        if n == 0 {
            break;
        }
        total += n;
    }
    Ok(total)
}

// spawns readers for all files, stops on first error
pub fn spawn_workers_read(
    tasks: Vec<FileTask>,
    tx: mpsc::Sender<ReadMessage>,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        debug_log!("readers: starting {} tasks", tasks.len());

        for task in tasks {
            let tx_clone = tx.clone();
            let path = task.original_path.clone();

            if let Err(e) = worker_read(task, tx_clone).await {
                return Err(anyhow::anyhow!("failed reading {:?}: {}", path, e));
            }
        }

        debug_log!("readers: all done");
        drop(tx);
        Ok(())
    })
}

// ================== ENCRYPTION WORKER ==================

// per-file encryption state
pub struct FileEncryptionContext {
    pub sym_key: aead::Key,
    pub encrypted_sym_key: Vec<u8>,
    pub chunks_processed: u32,
}

// encrypts chunks from rx, sends to tx
pub async fn worker_encrypt(
    id: usize,
    mut rx: mpsc::Receiver<ReadMessage>,
    tx: mpsc::Sender<EncryptedChunk>,
    pk: PublicKey,
    contexts: Arc<Mutex<HashMap<u64, FileEncryptionContext>>>,
) -> Result<()> {
    debug_log!("encrypt worker {}: started", id);

    while let Some(msg) = rx.recv().await {
        match msg {
            ReadMessage::Chunk { file_id, sequence, data, is_last } => {
                debug_log!("ENCRYPT: got chunk file_id={} seq={} is_last={} size={}", file_id, sequence, is_last, data.len());
                let sym_key = {
                    let mut ctx = contexts.lock().await;
                    let entry = ctx.entry(file_id).or_insert_with(|| {
                        debug_log!("encrypt worker {}: new context for file {}", id, file_id);
                        let (key, _) = generate_sym_key().expect("keygen failed");
                        let enc_key = encrypt_key(&pk, key.clone()).expect("key encrypt failed");
                        FileEncryptionContext {
                            sym_key: key,
                            encrypted_sym_key: enc_key,
                            chunks_processed: 0,
                        }
                    });
                    entry.chunks_processed += 1;
                    entry.sym_key.clone()
                };

                let nonce = aead::gen_nonce();
                let nonce_bytes: [u8; 24] = nonce.as_ref().try_into().expect("nonce must be 24 bytes");

                let key_clone = sym_key;
                let nonce_clone = nonce;
                let encrypted = tokio::task::spawn_blocking(move || {
                    aead::seal(&data, None, &nonce_clone, &key_clone)
                }).await?;

                debug_log!("encrypt worker {}: chunk {} of file {} done", id, sequence, file_id);

                tx.send(EncryptedChunk {
                    file_id,
                    sequence,
                    data: encrypted,
                    nonce: nonce_bytes,
                    is_last,
                }).await.map_err(|_| anyhow::anyhow!("channel closed"))?;
                debug_log!("ENCRYPT: sent chunk file_id={} seq={} is_last={}", file_id, sequence, is_last);
            }
            ReadMessage::FileComplete { .. } => {
                // ignored - writer uses is_last flag
            }
        }
    }

    debug_log!("encrypt worker {}: done", id);
    Ok(())
}

// spawns encryption workers with round-robin dispatcher
pub fn spawn_workers_encrypt(
    num_workers: usize,
    mut rx: mpsc::Receiver<ReadMessage>,
    tx: mpsc::Sender<EncryptedChunk>,
    pk: PublicKey,
    contexts: Arc<Mutex<HashMap<u64, FileEncryptionContext>>>,
) -> tokio::task::JoinHandle<Result<()>> {
    debug_log!("encrypt dispatcher: spawning {} workers", num_workers);

    tokio::spawn(async move {

        let (worker_txs, worker_rxs): (Vec<_>, Vec<_>) = (0..num_workers)
            .map(|_| mpsc::channel::<ReadMessage>(CHANNEL_BOUND))
            .unzip();

        let mut handles = Vec::new();
        for (i, worker_rx) in worker_rxs.into_iter().enumerate() {
            let tx_clone = tx.clone();
            let pk_clone = pk.clone();
            let ctx_clone = contexts.clone();
            handles.push(tokio::spawn(async move {
                worker_encrypt(i, worker_rx, tx_clone, pk_clone, ctx_clone).await
            }));
        }
        drop(tx);

        // consistent hashing: always send the same file_id to the same worker
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        while let Some(msg) = rx.recv().await {
            match &msg {
                ReadMessage::FileComplete { file_id, .. } => {
                    // send FileComplete to the same worker as the file's chunks
                    let mut hasher = DefaultHasher::new();
                    file_id.hash(&mut hasher);
                    let idx = (hasher.finish() as usize) % worker_txs.len();
                    let _ = worker_txs[idx].send(msg.clone()).await;
                }
                ReadMessage::Chunk { file_id, .. } => {
                    let mut hasher = DefaultHasher::new();
                    file_id.hash(&mut hasher);
                    let idx = (hasher.finish() as usize) % worker_txs.len();
                    if worker_txs[idx].send(msg).await.is_err() {
                        return Err(anyhow::anyhow!("worker {} channel closed", idx));
                    }
                }
            }
        }

        drop(worker_txs);

        // collect results
        let mut first_err = None;
        for (i, h) in handles.into_iter().enumerate() {
            match h.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    if first_err.is_none() {
                        first_err = Some(anyhow::anyhow!("worker {} failed: {}", i, e));
                    }
                }
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(anyhow::anyhow!("worker {} panicked: {}", i, e));
                    }
                }
            }
        }

        if let Some(e) = first_err {
            return Err(e);
        }
        Ok(())
    })
}

// ================== FILE WRITER ==================
// tracks state for a file being written
pub struct FileWriteState {
    pub output_path: PathBuf,
    pub original_path: PathBuf,
    pub relative_name: String,
    pub original_size: u64,
    pub encrypted_sym_key: Vec<u8>,
    pub chunks: BTreeMap<u32, EncryptedChunk>,
    pub total_chunks: Option<u32>,
}

impl FileWriteState {
    pub fn new(
        output_path: PathBuf,
        original_path: PathBuf,
        relative_name: String,
        original_size: u64,
        encrypted_sym_key: Vec<u8>,
    ) -> Self {
        Self {
            output_path,
            original_path,
            relative_name,
            original_size,
            encrypted_sym_key,
            chunks: BTreeMap::new(),
            total_chunks: None,
        }
    }

    pub fn add_chunk(&mut self, chunk: EncryptedChunk) {
        if chunk.is_last {
            self.total_chunks = Some(chunk.sequence + 1);
        }
        self.chunks.insert(chunk.sequence, chunk);
    }

    pub fn is_complete(&self) -> bool {
        match self.total_chunks {
            Some(total) => {
                if self.chunks.len() as u32 != total {
                    return false;
                }
                for (i, (seq, _)) in self.chunks.iter().enumerate() {
                    if *seq != i as u32 {
                        return false;
                    }
                }
                true
            }
            None => false,
        }
    }

    // writes header + chunks to output file
    pub async fn finalize(&self) -> Result<()> {
        debug_log!("writer: finalizing {:?}", self.original_path);

        let chunk_infos: Vec<ChunkInfo> = self.chunks.iter().map(|(seq, c)| {
            ChunkInfo {
                sequence: *seq,
                encrypted_size: c.data.len(),
                nonce: c.nonce,
            }
        }).collect();

        let header = FileHeader {
            original_filename: self.relative_name.clone(),
            original_size: self.original_size,
            chunk_count: self.chunks.len() as u32,
            chunks: chunk_infos,
            encrypted_sym_key: self.encrypted_sym_key.clone(),
        };

        let header_bytes = header.to_bytes()?;

        let mut file = File::create(&self.output_path).await?;
        file.write_all(&header_bytes).await?;

        for (_, chunk) in &self.chunks {
            file.write_all(&chunk.data).await?;
        }

        file.flush().await?;

        // delete original only after successful write
        tokio::fs::remove_file(&self.original_path).await?;

        debug_log!("writer: done with {:?}", self.original_path);
        Ok(())
    }
}

// file metadata: (output_path, original_path, relative_name, size)
pub type FileMetadata = HashMap<u64, (PathBuf, PathBuf, String, u64)>;

// writes encrypted chunks to files
pub async fn worker_write(
    mut rx: mpsc::Receiver<EncryptedChunk>,
    metadata: Arc<Mutex<FileMetadata>>,
    contexts: Arc<Mutex<HashMap<u64, FileEncryptionContext>>>,
) -> Result<()> {
    debug_log!("writer: started");

    let mut states: HashMap<u64, FileWriteState> = HashMap::new();

    while let Some(chunk) = rx.recv().await {
        let file_id = chunk.file_id;

        debug_log!("WRITER: got chunk file_id={} seq={} is_last={}", file_id, chunk.sequence, chunk.is_last);

        // create state if needed
        if !states.contains_key(&file_id) {
            let meta = metadata.lock().await;
            let (output, original, relative, size) = meta.get(&file_id)
                .ok_or_else(|| anyhow::anyhow!("no metadata for file {}", file_id))?
                .clone();

            let ctx = contexts.lock().await;
            let enc_key = ctx.get(&file_id)
                .ok_or_else(|| anyhow::anyhow!("no context for file {}", file_id))?
                .encrypted_sym_key.clone();

            states.insert(file_id, FileWriteState::new(output, original, relative, size, enc_key));
        }

        let state = states.get_mut(&file_id).unwrap();
        state.add_chunk(chunk);

        debug_log!("WRITER: file_id={} chunk_count={} total_chunks={:?}", file_id, state.chunks.len(), state.total_chunks);

        if state.is_complete() {
            debug_log!("WRITER: file_id={} is complete, finalizing", file_id);
            state.finalize().await?;
            states.remove(&file_id);

            let mut ctx = contexts.lock().await;
            ctx.remove(&file_id);
        }
    }

    // check for incomplete files
    if !states.is_empty() {
        let incomplete: Vec<_> = states.keys().collect();
        return Err(anyhow::anyhow!("incomplete files: {:?}", incomplete));
    }

    debug_log!("writer: done");
    Ok(())
}

pub fn spawn_workers_write(
    rx: mpsc::Receiver<EncryptedChunk>,
    metadata: Arc<Mutex<FileMetadata>>,
    contexts: Arc<Mutex<HashMap<u64, FileEncryptionContext>>>,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        worker_write(rx, metadata, contexts).await
    })
}

// ================== ENCRYPTION ENTRYPOINT ==================

pub async fn encrypt_folder_parallel(
    folder_path: &Path,
    pk: &PublicKey,
    num_workers: Option<usize>,
) -> Result<()> {
    if !folder_path.exists() || !folder_path.is_dir() {
        return Err(anyhow::anyhow!("invalid folder path"));
    }

    let num_workers = num_workers.unwrap_or_else(|| {
        num_cpus::get().saturating_sub(1).max(1)
    });

    debug_log!("orchestrator: encrypting {:?} with {} workers", folder_path, num_workers);

    // discover files
    let tasks = discover_files(folder_path, FileSearchMode::ForEncryption).await?;
    if tasks.is_empty() {
        debug_log!("orchestrator: no files to encrypt");
        return Ok(());
    }

    debug_log!("orchestrator: found {} files", tasks.len());

    // shared state
    let metadata: Arc<Mutex<FileMetadata>> = Arc::new(Mutex::new(HashMap::new()));
    let contexts: Arc<Mutex<HashMap<u64, FileEncryptionContext>>> = Arc::new(Mutex::new(HashMap::new()));

    // populate metadata
    {
        let mut m = metadata.lock().await;
        for t in &tasks {
            let relative = t.original_path
                .strip_prefix(folder_path)
                .unwrap_or(&t.original_path)
                .to_string_lossy()
                .to_string();
            m.insert(t.file_id, (t.output_path.clone(), t.original_path.clone(), relative, t.size));
        }
    }

    // channels
    let (read_tx, read_rx) = mpsc::channel(CHANNEL_BOUND * num_workers);
    let (encrypt_tx, encrypt_rx) = mpsc::channel(CHANNEL_BOUND * num_workers);

    // spawn pipeline
    let reader_handle = spawn_workers_read(tasks, read_tx);
    let encrypt_handle = spawn_workers_encrypt(num_workers, read_rx, encrypt_tx, pk.clone(), contexts.clone());
    let writer_handle = spawn_workers_write(encrypt_rx, metadata.clone(), contexts.clone());

    // wait for completion
    reader_handle.await??;
    debug_log!("orchestrator: readers done");

    encrypt_handle.await??;
    debug_log!("orchestrator: encrypters done");

    writer_handle.await??;
    debug_log!("orchestrator: writer done");

    println!("encryption completed for {:?}", folder_path);
    Ok(())
}


// a couple tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_write_state_complete() {
        let mut state = FileWriteState::new(
            PathBuf::from("out.enc"),
            PathBuf::from("in.txt"),
            "in.txt".to_string(),
            100,
            vec![1, 2, 3],
        );

        assert!(!state.is_complete());

        state.add_chunk(EncryptedChunk {
            file_id: 0,
            sequence: 0,
            data: vec![1, 2, 3],
            nonce: [0u8; 24],
            is_last: true,
        });

        assert!(state.is_complete());
    }

    #[test]
    fn test_file_write_state_multi_chunk() {
        let mut state = FileWriteState::new(
            PathBuf::from("out.enc"),
            PathBuf::from("in.txt"),
            "in.txt".to_string(),
            100,
            vec![1, 2, 3],
        );

        state.add_chunk(EncryptedChunk {
            file_id: 0,
            sequence: 1,
            data: vec![4, 5],
            nonce: [0u8; 24],
            is_last: true,
        });
        assert!(!state.is_complete()); // missing chunk 0

        state.add_chunk(EncryptedChunk {
            file_id: 0,
            sequence: 0,
            data: vec![1, 2, 3],
            nonce: [0u8; 24],
            is_last: false,
        });
        assert!(state.is_complete());
    }
}
