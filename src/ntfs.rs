#![allow(dead_code)]
use crate::util::{u16_le, u32_le, u64_le};

/* Links:
 * https://flatcap.org/linux-ntfs/ntfs/index.html
 * wiki: NTFS
 * original scrounge-ntfs
 */

pub const STD_SECTOR:u64 = 512;

pub const MFT_ID_ROOT:u32 = 0x5;

pub trait FromByteSlice {
    fn from_bytes(slice: &[u8]) -> &Self;
}

// copy is added for better manipulation with packed structs

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BootSector {
    /// Jump to the boot loader routine
    pub jmp: [u8; 3],
    /// System Id: "NTFS    "
    pub sys_id: [u8; 8],
    /// Bytes per sector
    pub bytes_per_sec: u16_le,

    /// Sectors per cluster
    pub sec_per_clus: u8,
    pub padding_1: [u8; 7],

    /// Media descriptor (a)
    pub media_descriptor: u8,
    pub padding_2: [u8; 2],

    /// Sectors per track
    pub sec_per_track: u16_le,
    /// Number of heads
    pub num_heads: u16_le,
    pub padding_3: [u8; 8],
    /// Always 80 00 80 00
    pub signature: u32_le,
    /// Number of sectors in the volume 
    pub sector_count: u64_le,
    /// LCN of VCN 0 of the $MFT
    pub off_mft: u64_le,
    /// LCN of VCN 0 of the $MFTMirr
    pub off_mft_mirr: u64_le,
    /// Positive value: size in clusters
    /// Negative value: size in bytes, 2^(-n)
    pub mftr_size: i8,
    pub padding_4: [u8; 3],
    /// Size of the index record, see mtfr_size for format
    pub index_size: i8,
    pub padding_5: [u8; 3],
    /// Volume serial number
	pub serial_num: u64_le,
}

impl BootSector {
    pub fn is_valid(&self) -> bool {
        return (self.sys_id == *BOOT_SECTOR_ID) && (self.bytes_per_sec.val() == 512);
    }
}

impl FromByteSlice for BootSector {
    fn from_bytes(slice: &[u8]) -> &Self {
        assert!(slice.len() >= std::mem::size_of::<Self>());
        unsafe { &*(slice as *const [u8] as *const Self) }
    }
}

pub const BOOT_SECTOR_ID: &[u8; 8] = b"NTFS    ";

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MftRecord {
    /// Magic number 'FILE'
    pub magic: u32_le,
    /// Offset to the update sequence
    pub update_sequence_offset: u16_le,
    /// Size in words of Update Sequence Number & Array (S)
    pub update_sequence_words: u16_le,
    /// $LogFile Sequence Number (LSN)
    pub log_file_seqn: u64_le,
    /// Sequence number
    pub seqn: u16_le,
    /// Hard link count
    pub hard_link_count: u16_le,
    /// Offset to Attributes
    pub attributes_offset: u16_le,
    /// Flags
    pub flags: u16_le,
    /// Real size of the FILE record
    pub record_size_bytes: u32_le,
    /// Allocated size of the FILE record
    pub allocated_size_bytes: u32_le,
    /// File reference to the base FILE record
    pub ref_base_record: u64_le,
    /// Next Attribute Id
    pub next_attr_id: u16_le,
    /// (XP) Align to 4 byte boundary
    pub padding: u16_le,
    /// (XP) Number of this MFT Record
	pub record_num: u32_le,
}

impl FromByteSlice for MftRecord {
    fn from_bytes(slice: &[u8]) -> &Self {
        assert!(slice.len() >= std::mem::size_of::<Self>());
        unsafe { &*(slice as *const [u8] as *const Self) }
    }
}

pub const MFT_REC_MAGIC: u32 = u32::from_le_bytes(*b"FILE");
pub const MFT_REC_END: u32  = 0xFFFFFFFF;
pub const MFT_REC_HEADER_LEN: usize = 0x30;
pub const MFT_REC_FLAG_USE: u16 = 0x01;
pub const MFT_REC_FLAG_DIR: u16 = 0x02;

pub const ATTR_COMPRESSED: u16 = 0x0001;
pub const ATTR_ENCRYPTED: u16 = 0x0002;
pub const ATTR_SPARSE: u16 = 0x0004;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct AttrHeader {
    /// Attribute Type (e.g. 0x10, 0x60)
    pub attr_type: u32_le,
    /// Length (including this header)
    pub attr_size: u32_le,
    /// Non-resident flag
    pub non_resident: u8,
    /// Name Length
    pub name_length: u8,
    /// Offset to the Attribute
    pub offset_name: u16_le,
    pub flag: u16_le,
    pub attr_id: u16_le,
}

impl FromByteSlice for AttrHeader {
    fn from_bytes(slice: &[u8]) -> &Self {
        assert!(slice.len() >= std::mem::size_of::<Self>());
        unsafe { &*(slice as *const [u8] as *const Self) }
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct AttrResident
{
    pub header: AttrHeader,
    /// Length of the Attribute
    pub attr_data_len: u32_le,
    /// Offset to the Attribute
    pub off_attrib_data: u16_le,
    /// Indexed flag
    pub indexed_flag: u8,
    /// 0x00 Padding
	pub padding: u8,
}

impl FromByteSlice for AttrResident {
    fn from_bytes(slice: &[u8]) -> &Self {
        assert!(slice.len() >= std::mem::size_of::<Self>());
        unsafe { &*(slice as *const [u8] as *const Self) }
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct AttrNonResident
{
	pub header: AttrHeader,
    
    /// Starting VCN
    pub start_vcn: u64_le,
    /// Last VCN
    pub last_vcn: u64_le,
    /// Offset to the Data Runs
    pub data_runs_offset: u16_le,
    /// Compression Unit Size (b)
    pub compression_unit_size: u16_le,
    pub padding: u32_le,
    /// Allocated size of the attribute (c)
    pub allocated_size: u64_le,
    /// Real size of the attribute
    pub data_size: u64,
    /// Initialized data size of the stream (d)
	pub initialized_size: u64,
}

impl FromByteSlice for AttrNonResident {
    fn from_bytes(slice: &[u8]) -> &Self {
        assert!(slice.len() >= std::mem::size_of::<Self>());
        unsafe { &*(slice as *const [u8] as *const Self) }
    }
}

pub const ATTRT_ATTRIBUTE_LIST: u32 = 0x20;
pub const ATTRT_FILENAME: u32 = 0x30;
pub const ATTRT_DATA: u32 = 0x80;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct AttrFileName
{
    /// File reference to the parent directory.
    pub ref_parent: u64_le,
    /// C Time - File Creation
    pub time_created: u64_le,
    /// A Time - File Altered
    pub time_altered: u64_le,
    /// M Time - MFT Changed
    pub time_modified: u64_le,
    /// R Time - File Read
    pub time_read: u64_le,
    /// Allocated size of the file
    pub allocated_size: u64_le,
    /// Real size of the file
    pub file_size: u64_le,
    /// Flags, e.g. Directory, compressed, hidden
    pub flags: u32_le,
    /// Used by EAs and Reparse
    pub ea_reparse: u32_le,
    /// Filename length in characters (L)
    pub file_name_length: u8,
    /// Filename namespace
	pub namespace: u8,
    /* File Name comes here */
}

impl FromByteSlice for AttrFileName {
    fn from_bytes(slice: &[u8]) -> &Self {
        assert!(slice.len() >= std::mem::size_of::<Self>());
        unsafe { &*(slice as *const [u8] as *const Self) }
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct AttrListRecord
{
    /// Type
    pub attr_type: u32_le,
    /// Record length
    pub attr_size: u16_le,
    /// Name length (N)
    pub name_size: u8,
    /// Offset to Name (a)
    pub name_offset: u8,
    /// Starting VCN (b)
    pub start_vcn: u64_le,
    /// Base File Reference of the attribute
    pub ref_attrib: u64_le,
    // Attribute Id (c)
    pub attr_id: u16_le,
    /* Attribute name here */
}

impl FromByteSlice for AttrListRecord {
    fn from_bytes(slice: &[u8]) -> &Self {
        assert!(slice.len() >= std::mem::size_of::<Self>());
        unsafe { &*(slice as *const [u8] as *const Self) }
    }
}

/*
#define kNTFS_FFLAG_FILE_READ_ONLY      0x0001
#define kNTFS_FileHidden        0x0002
#define kNTFS_FileSystem        0x0004
#define kNTFS_FileArchive       0x0020
#define kNTFS_FileDevice        0x0040
#define kNTFS_FileNormal        0x0080
#define kNTFS_FileTemorary      0x0100
#define kNTFS_FileSparse        0x0200
#define kNTFS_FileReparse       0x0400
#define kNTFS_FileCompressed    0x0800
#define kNTFS_FileOffline       0x1000
#define kNTFS_FileNotIndexed    0x2000
#define kNTFS_FileEncrypted     0x4000
*/

pub const NS_POSIX: u8 = 0x00;
pub const NS_WIN32: u8 = 0x01;
pub const NS_DOS: u8 = 0x02;
pub const NS_WINDOS: u8 = 0x03;

const MTF_FILE_NAME: &str = "$MFT";
const SYS_PREFIX: char = '$';

#[cfg(test)]
mod test {
    use std::mem::size_of;
    use super::*;

    #[test]
    pub fn assert_sizes() {
        assert_eq!(size_of::<MftRecord>(), 0x30);
        assert_eq!(size_of::<AttrHeader>(), 0x10);
        assert_eq!(size_of::<AttrNonResident>(), 0x40);
        assert_eq!(size_of::<AttrResident>(), 0x18);
        assert_eq!(size_of::<AttrFileName>(), 0x42);
    }
}