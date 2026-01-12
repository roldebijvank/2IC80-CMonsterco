//! Data structures for parallel encryption chunking and pipeline messages.
//!
//! This module contains configuration constants, metadata structures for file chunks,
//! and message types used in the encryption/decryption pipeline.

use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use serde::{Serialize, Deserialize};

// ============================================================================
// Debug Configuration
// ============================================================================

/// Enable debug output for the parallel encryption pipeline.
/// Set to `false` in production to disable all debug messages.
pub const DEBUG_ENABLED: bool = true;

/// Macro for debug printing that can be disabled via DEBUG_ENABLED.
/// Usage: `debug_log!("Processing file: {:?}", path);`
#[macro_export]
macro_rules! debug_log {
    ($($arg:tt)*) => {
        if $crate::cryptography::chunk::DEBUG_ENABLED {
            eprintln!("[DEBUG] {}", format!($($arg)*));
        }
    };
}

// ============================================================================
// Configuration Constants
// ============================================================================

/// Size of each chunk for large files (4 MB).
pub const CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Files smaller than this threshold are processed as a single chunk (10 MB).
/// Files >= this size are split into multiple chunks for parallel processing.
pub const SMALL_FILE_THRESHOLD: u64 = 10 * 1024 * 1024;

/// Number of chunks that can be buffered in each pipeline channel.
/// Higher values use more memory but can improve throughput.
pub const CHANNEL_BOUND: usize = 8;

// ============================================================================
// Chunk Metadata
// ============================================================================

/// Metadata for a single encrypted chunk.
/// Stored in the file header to enable decryption of each chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkInfo {
    /// Sequence number (0-indexed, determines order during reconstruction).
    pub sequence: u32,
    /// Size of the encrypted chunk data in bytes.
    pub encrypted_size: usize,
    /// Nonce used for encrypting this chunk (24 bytes for XChaCha20-Poly1305).
    /// Each chunk must have a unique nonce.
    pub nonce: [u8; 24],
}

// ============================================================================
// File Header
// ============================================================================

/// Header stored at the beginning of each encrypted file.
/// Contains all metadata needed to reconstruct the original file during decryption.
///
/// File format:
/// ```text
/// [4 bytes: header_length (little-endian u32)]
/// [header_length bytes: JSON-serialized FileHeader]
/// [chunk 0 encrypted data]
/// [chunk 1 encrypted data]
/// ...
/// [chunk N encrypted data]
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct FileHeader {
    /// Original filename (relative path from encryption root).
    /// Used to reconstruct the file in its original location.
    pub original_filename: String,
    /// Original file size in bytes.
    /// Used for verification after decryption.
    pub original_size: u64,
    /// Total number of chunks in this file.
    pub chunk_count: u32,
    /// Metadata for each chunk (sequence, size, nonce).
    /// Length should equal chunk_count.
    pub chunks: Vec<ChunkInfo>,
    /// Symmetric key encrypted with the public key.
    /// Decrypted using the secret key during decryption.
    pub encrypted_sym_key: Vec<u8>,
}

impl FileHeader {
    /// Serialize header to bytes with length prefix.
    ///
    /// Format: [4 bytes: header_len (little-endian)][header_json_bytes]
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Serialized header bytes
    /// * `Err` - If JSON serialization fails
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let header_json = serde_json::to_vec(self)?;
        let header_len = header_json.len() as u32;

        let mut result = Vec::with_capacity(4 + header_json.len());
        result.extend_from_slice(&header_len.to_le_bytes());
        result.extend_from_slice(&header_json);

        Ok(result)
    }

    /// Deserialize header from bytes.
    ///
    /// # Arguments
    /// * `bytes` - Buffer containing the serialized header (must start at offset 0)
    ///
    /// # Returns
    /// * `Ok((FileHeader, usize))` - Parsed header and total bytes consumed (header_len + 4)
    /// * `Err` - If buffer is too small or JSON parsing fails
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), Box<dyn std::error::Error>> {
        // Need at least 4 bytes for the length prefix
        if bytes.len() < 4 {
            return Err("Buffer too small for header length prefix".into());
        }

        // Read header length (first 4 bytes, little-endian)
        let header_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;

        // Check if buffer contains the complete header
        if bytes.len() < 4 + header_len {
            return Err(format!(
                "Buffer too small for complete header: need {}, have {}",
                4 + header_len,
                bytes.len()
            ).into());
        }

        // Parse JSON from header bytes
        let header_bytes = &bytes[4..4 + header_len];
        let header: FileHeader = serde_json::from_slice(header_bytes)?;

        // Return header and total bytes consumed
        Ok((header, 4 + header_len))
    }
}

// ============================================================================
// Pipeline Messages
// ============================================================================

/// Messages sent from file readers to encryption workers.
#[derive(Debug)]
pub enum ReadMessage {
    /// A chunk of plaintext data from a file.
    Chunk {
        /// Unique identifier for the source file.
        file_id: u64,
        /// Sequence number of this chunk (0-indexed).
        sequence: u32,
        /// Plaintext data to encrypt.
        data: Vec<u8>,
        /// True if this is the last chunk of the file.
        is_last: bool,
    },
    /// Indicates all chunks for a file have been sent.
    FileComplete {
        /// Unique identifier for the completed file.
        file_id: u64,
        /// Original path of the file (for deletion after encryption).
        original_path: PathBuf,
    },
}

// Implement Clone for ReadMessage to allow broadcasting to workers
impl Clone for ReadMessage {
    fn clone(&self) -> Self {
        match self {
            ReadMessage::Chunk { file_id, sequence, data, is_last } => {
                ReadMessage::Chunk {
                    file_id: *file_id,
                    sequence: *sequence,
                    data: data.clone(),
                    is_last: *is_last,
                }
            }
            ReadMessage::FileComplete { file_id, original_path } => {
                ReadMessage::FileComplete {
                    file_id: *file_id,
                    original_path: original_path.clone(),
                }
            }
        }
    }
}

/// Encrypted chunk ready to be written to disk.
#[derive(Debug)]
pub struct EncryptedChunk {
    /// Unique identifier for the source file.
    pub file_id: u64,
    /// Sequence number of this chunk (0-indexed).
    pub sequence: u32,
    /// Encrypted data (ciphertext).
    pub data: Vec<u8>,
    /// Nonce used for encryption (24 bytes).
    pub nonce: [u8; 24],
    /// True if this is the last chunk of the file.
    pub is_last: bool,
}

// ============================================================================
// File Task
// ============================================================================

/// Metadata about a file to be encrypted.
/// Created during file discovery and used by the pipeline.
#[derive(Debug, Clone)]
pub struct FileTask {
    /// Unique identifier for this file.
    pub file_id: u64,
    /// Original path of the file.
    pub original_path: PathBuf,
    /// Output path for the encrypted file (typically original_path + ".enc").
    pub output_path: PathBuf,
    /// File size in bytes.
    pub size: u64,
    /// Whether to chunk this file (true for files >= SMALL_FILE_THRESHOLD).
    pub should_chunk: bool,
}

// ============================================================================
// Statistics
// ============================================================================

/// Statistics for tracking encryption progress.
/// All fields are atomic for thread-safe updates from multiple workers.
#[derive(Debug, Default)]
pub struct EncryptionStats {
    /// Number of files successfully processed.
    pub files_processed: AtomicU64,
    /// Total bytes processed (encrypted or decrypted).
    pub bytes_processed: AtomicU64,
    /// Number of files that failed processing.
    pub files_failed: AtomicU64,
}

impl EncryptionStats {
    /// Create a new stats instance with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment files_processed by 1.
    pub fn inc_files_processed(&self) {
        self.files_processed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Add bytes to bytes_processed.
    pub fn add_bytes_processed(&self, bytes: u64) {
        self.bytes_processed.fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
    }

    /// Increment files_failed by 1.
    pub fn inc_files_failed(&self) {
        self.files_failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Get current snapshot of all stats.
    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.files_processed.load(std::sync::atomic::Ordering::Relaxed),
            self.bytes_processed.load(std::sync::atomic::Ordering::Relaxed),
            self.files_failed.load(std::sync::atomic::Ordering::Relaxed),
        )
    }
}

// ============================================================================
// Progress Callback
// ============================================================================

/// Type alias for progress callback function.
/// 
/// The callback receives:
/// - files_processed: Number of files completed
/// - bytes_processed: Total bytes encrypted/decrypted
/// - files_failed: Number of files that failed
///
/// Set to None in production to disable progress reporting.
pub type ProgressCallback = Option<Box<dyn Fn(u64, u64, u64) + Send + Sync>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_header_serialization() {
        let header = FileHeader {
            original_filename: "test/file.txt".to_string(),
            original_size: 1024,
            chunk_count: 1,
            chunks: vec![ChunkInfo {
                sequence: 0,
                encrypted_size: 1040, // 1024 + 16 auth tag
                nonce: [0u8; 24],
            }],
            encrypted_sym_key: vec![1, 2, 3, 4],
        };

        let bytes = header.to_bytes().expect("Serialization should succeed");
        let (parsed, consumed) = FileHeader::from_bytes(&bytes).expect("Deserialization should succeed");

        assert_eq!(parsed.original_filename, header.original_filename);
        assert_eq!(parsed.original_size, header.original_size);
        assert_eq!(parsed.chunk_count, header.chunk_count);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn test_file_header_from_bytes_too_small() {
        let bytes = vec![0, 0, 0]; // Only 3 bytes, need 4 for length
        assert!(FileHeader::from_bytes(&bytes).is_err());
    }
}
