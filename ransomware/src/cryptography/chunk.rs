use std::path::PathBuf;
use serde::{Serialize, Deserialize};

// Debug flag - set to false to disable debug output
pub const DEBUG_ENABLED: bool = true;

// Macro for conditional debug printing
#[macro_export]
macro_rules! debug_println {
    ($($arg:tt)*) => {
        if $crate::cryptography::chunk::DEBUG_ENABLED {
            println!("[DEBUG] {}", format!($($arg)*));
        }
    };
}

/// Configuration constants
pub const CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4MB
pub const SMALL_FILE_THRESHOLD: u64 = 10 * 1024 * 1024; // 10MB
pub const CHANNEL_BOUND: usize = 8; // Number of chunks that can be buffered

/// Metadata for a single chunk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkInfo {
    /// Sequence number (0-indexed)
    pub sequence: u32,
    /// Size of the encrypted chunk in bytes
    pub encrypted_size: usize,
    /// Nonce used for this chunk (24 bytes for XChaCha20-Poly1305)
    pub nonce: [u8; 24],
}

/// File header stored at the beginning of each encrypted file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHeader {
    /// Original filename (relative path from encryption root)
    pub original_filename: String,
    /// Original file size in bytes
    pub original_size: u64,
    /// Total number of chunks
    pub chunk_count: u32,
    /// Metadata for each chunk (sequence, size, nonce)
    pub chunks: Vec<ChunkInfo>,
    /// Symmetric key encrypted with the public key
    pub encrypted_sym_key: Vec<u8>,
}

impl FileHeader {
    /// Serialize header to bytes with length prefix
    /// Format: [4 bytes: header_len][header_bytes]
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let header_json = serde_json::to_vec(self)?;
        let header_len = header_json.len() as u32;
        
        let mut result = Vec::with_capacity(4 + header_json.len());
        result.extend_from_slice(&header_len.to_le_bytes());
        result.extend_from_slice(&header_json);
        
        debug_println!("Serialized header: {} bytes (payload: {} bytes)", result.len(), header_json.len());
        
        Ok(result)
    }
    
    /// Deserialize header from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), Box<dyn std::error::Error>> {
        if bytes.len() < 4 {
            return Err("Buffer too small for header length".into());
        }
        
        let header_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        
        debug_println!("Reading header: {} bytes", header_len);
        
        if bytes.len() < 4 + header_len {
            return Err("Buffer too small for complete header".into());
        }
        
        let header_bytes = &bytes[4..4 + header_len];
        let header: FileHeader = serde_json::from_slice(header_bytes)?;
        
        Ok((header, 4 + header_len))
    }
}

/// Message types for the read channel
#[derive(Debug, Clone)]
pub enum ReadMessage {
    /// A chunk of data from a file
    Chunk {
        file_id: u64,
        sequence: u32,
        data: Vec<u8>,
        is_last: bool,
    },
    /// Indicates all chunks for a file have been read
    FileComplete {
        file_id: u64,
        original_path: PathBuf,
    },
}

/// Message types for the encryption channel
#[derive(Debug)]
pub struct EncryptedChunk {
    /// Unique file identifier
    pub file_id: u64,
    /// Chunk sequence number
    pub sequence: u32,
    /// Encrypted data
    pub data: Vec<u8>,
    /// Nonce used for encryption (24 bytes)
    pub nonce: [u8; 24],
    /// Whether this is the last chunk
    pub is_last: bool,
}

/// Metadata about a file to be encrypted
#[derive(Debug, Clone)]
pub struct FileTask {
    /// Unique identifier for this file
    pub file_id: u64,
    /// Original path
    pub original_path: PathBuf,
    /// Output path for encrypted file
    pub output_path: PathBuf,
    /// File size in bytes
    pub size: u64,
    /// Whether to chunk this file (false for small files)
    pub should_chunk: bool,
}

/// Statistics for tracking progress
#[derive(Debug, Default)]
pub struct EncryptionStats {
    pub files_processed: std::sync::atomic::AtomicU64,
    pub bytes_processed: std::sync::atomic::AtomicU64,
    pub files_failed: std::sync::atomic::AtomicU64,
}

impl EncryptionStats {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn increment_files(&self) {
        self.files_processed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    
    pub fn increment_bytes(&self, bytes: u64) {
        self.bytes_processed.fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
    }
    
    pub fn increment_failed(&self) {
        self.files_failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    
    pub fn get_files_processed(&self) -> u64 {
        self.files_processed.load(std::sync::atomic::Ordering::Relaxed)
    }
    
    pub fn get_bytes_processed(&self) -> u64 {
        self.bytes_processed.load(std::sync::atomic::Ordering::Relaxed)
    }
    
    pub fn get_files_failed(&self) -> u64 {
        self.files_failed.load(std::sync::atomic::Ordering::Relaxed)
    }
}
