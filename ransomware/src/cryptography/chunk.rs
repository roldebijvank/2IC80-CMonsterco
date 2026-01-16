// data structures for parallel encryption

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use uuid::Uuid;

// set to false in production
pub const DEBUG_ENABLED: bool = true;

// debug logging macro that can be disabled in prod
#[macro_export]
macro_rules! debug_log {
    ($($arg:tt)*) => {
        if $crate::cryptography::chunk::DEBUG_ENABLED {
            eprintln!("[DEBUG] {}", format!($($arg)*));
        }
    };
}

// =================== CONFIG ===================

pub const CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4 MB
pub const SMALL_FILE_THRESHOLD: u64 = 10 * 1024 * 1024; // 10 MB
pub const CHANNEL_BOUND: usize = 8;

// =================== CHUNK META ===================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkInfo {
    pub sequence: u32,
    pub encrypted_size: usize,
    pub nonce: [u8; 24],
}

// =================== FILE HEADER ===================
// format: [4 bytes: header_len][json header][chunk0][chunk1]...
#[derive(Debug, Serialize, Deserialize)]
pub struct FileHeader {
    pub original_filename: String,
    pub original_size: u64,
    pub chunk_count: u32,
    pub chunks: Vec<ChunkInfo>,
    pub encrypted_sym_key: Vec<u8>,
}

impl FileHeader {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let json = serde_json::to_vec(self)?;
        let len = json.len() as u32;

        let mut out = Vec::with_capacity(4 + json.len());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&json);

        Ok(out)
    }

    // returns (header, bytes_consumed)
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize)> {
        if bytes.len() < 4 {
            return Err(anyhow::anyhow!("buffer too small"));
        }

        let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;

        if bytes.len() < 4 + len {
            return Err(anyhow::anyhow!(
                "need {} bytes, have {}",
                4 + len,
                bytes.len()
            ));
        }

        let header: FileHeader = serde_json::from_slice(&bytes[4..4 + len])?;
        Ok((header, 4 + len))
    }
}

// =================== PIPELINE MESSAGES ===================

#[derive(Debug)]
pub enum ReadMessage {
    Chunk {
        file_id: Uuid,
        sequence: u32,
        data: Vec<u8>,
        is_last: bool,
    },
    FileComplete {
        file_id: Uuid,
        original_path: PathBuf,
    },
}

impl Clone for ReadMessage {
    fn clone(&self) -> Self {
        match self {
            ReadMessage::Chunk {
                file_id,
                sequence,
                data,
                is_last,
            } => ReadMessage::Chunk {
                file_id: *file_id,
                sequence: *sequence,
                data: data.clone(),
                is_last: *is_last,
            },
            ReadMessage::FileComplete {
                file_id,
                original_path,
            } => ReadMessage::FileComplete {
                file_id: *file_id,
                original_path: original_path.clone(),
            },
        }
    }
}

#[derive(Debug)]
pub struct EncryptedChunk {
    pub file_id: Uuid,
    pub sequence: u32,
    pub data: Vec<u8>,
    pub nonce: [u8; 24],
    pub is_last: bool,
}

// =================== FILE TASK ===================

#[derive(Debug, Clone)]
pub struct FileTask {
    pub file_id: Uuid,
    pub original_path: PathBuf,
    pub output_path: PathBuf,
    pub size: u64,
    pub should_chunk: bool,
}

// stats (unused for now)
// #[derive(Debug, Default)]
// pub struct EncryptionStats {
//     pub files_processed: AtomicU64,
//     pub bytes_processed: AtomicU64,
//     pub files_failed: AtomicU64,
// }

// impl EncryptionStats {
//     pub fn new() -> Self {
//         Self::default()
//     }

//     pub fn inc_files_processed(&self) {
//         self.files_processed
//             .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
//     }

//     pub fn add_bytes_processed(&self, bytes: u64) {
//         self.bytes_processed
//             .fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
//     }

//     pub fn inc_files_failed(&self) {
//         self.files_failed
//             .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
//     }

//     pub fn snapshot(&self) -> (u64, u64, u64) {
//         (
//             self.files_processed
//                 .load(std::sync::atomic::Ordering::Relaxed),
//             self.bytes_processed
//                 .load(std::sync::atomic::Ordering::Relaxed),
//             self.files_failed.load(std::sync::atomic::Ordering::Relaxed),
//         )
//     }
// }

// // progress callback
// // set to None to disable
// pub type ProgressCallback = Option<Box<dyn Fn(u64, u64, u64) + Send + Sync>>;