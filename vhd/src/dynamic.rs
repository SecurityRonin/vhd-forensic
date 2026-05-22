//! Dynamic VHD Block Allocation Table (BAT) parsing (MS-VHD §2.3).

use crate::error::{Result, VhdError};

pub const DYNAMIC_HEADER_COOKIE: &[u8; 8] = b"cxsparse";
pub const DYNAMIC_HEADER_SIZE: usize = 1024;
pub const BAT_ENTRY_UNUSED: u32 = 0xFFFF_FFFF;
/// Sector bitmap size in sectors (always 1 sector = 512 bytes per block).
pub const BITMAP_SECTORS: u64 = 1;

/// Parsed dynamic header fields.
pub struct DynamicHeader {
    pub bat_offset: u64,
    pub block_size: u32,
    pub max_bat_entries: u32,
}

impl DynamicHeader {
    pub fn parse(data: &[u8], offset: u64) -> Result<Self> {
        let start = offset as usize;
        let end = start + DYNAMIC_HEADER_SIZE;
        if end > data.len() {
            return Err(VhdError::BatOutOfBounds);
        }
        let hdr = &data[start..end];
        if &hdr[0..8] != DYNAMIC_HEADER_COOKIE {
            return Err(VhdError::BadCookie);
        }
        let bat_offset     = u64::from_be_bytes(hdr[16..24].try_into().unwrap());
        let block_size     = u32::from_be_bytes(hdr[32..36].try_into().unwrap());
        let max_bat_entries = u32::from_be_bytes(hdr[28..32].try_into().unwrap());
        Ok(DynamicHeader { bat_offset, block_size, max_bat_entries })
    }
}

/// In-memory Block Allocation Table.
pub struct BlockAllocationTable {
    /// File-sector offset for each block (BAT_ENTRY_UNUSED if not present).
    entries: Vec<u32>,
    pub block_size: u32,
}

impl BlockAllocationTable {
    pub fn parse(data: &[u8], hdr: &DynamicHeader) -> Result<Self> {
        let start = hdr.bat_offset as usize;
        let entry_count = hdr.max_bat_entries as usize;
        let end = start + entry_count * 4;
        if end > data.len() {
            return Err(VhdError::BatOutOfBounds);
        }
        let entries = (0..entry_count)
            .map(|i| u32::from_be_bytes(data[start + i * 4..start + i * 4 + 4].try_into().unwrap()))
            .collect();
        Ok(BlockAllocationTable { entries, block_size: hdr.block_size })
    }

    /// Resolve a virtual byte offset to a file byte offset.
    ///
    /// Returns `None` if the block is not present (sparse / unwritten region,
    /// reads should return zeroes).
    pub fn file_offset_for_byte(&self, virtual_byte: u64) -> Result<Option<u64>> {
        let block_size = u64::from(self.block_size);
        let block_index = (virtual_byte / block_size) as usize;
        if block_index >= self.entries.len() {
            return Err(VhdError::BlockOutOfBounds);
        }
        let bat_entry = self.entries[block_index];
        if bat_entry == BAT_ENTRY_UNUSED {
            return Ok(None);
        }
        // BAT entry is in 512-byte sectors; each block is preceded by a 1-sector bitmap.
        let block_file_offset = u64::from(bat_entry) * 512 + BITMAP_SECTORS * 512;
        let offset_in_block = virtual_byte % block_size;
        Ok(Some(block_file_offset + offset_in_block))
    }
}
