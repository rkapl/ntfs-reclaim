use structopt::StructOpt;
use std::{cell::Cell, cell::RefCell, fmt::Display, fs::File, mem::size_of, path::{Path, PathBuf}, rc::Rc};
use image::{Image, ImageData, ImageDataSlice, ImageDataMutSlice};
use std::io::{Write, BufRead, Result, Seek, SeekFrom, BufWriter};
use std::collections::HashMap;
use std::convert::{TryInto};
use itertools::Itertools;
use error::{ParsingError, ParsingResult};

mod util;
mod ntfs;
mod image;
mod error;
mod data_runs;

pub const PROGRAM_NAME: &str = "restore-ntfs";

#[derive(Debug, StructOpt)]
struct Opts {
    #[structopt(parse(from_os_str))]
    disk_image: PathBuf,

    #[structopt(parse(from_os_str))]
    working_dir: PathBuf,

    #[structopt(short="-o", long)]
    partition_offset: u64,

    #[structopt(long="--partition-size", help="Size of the partition in bytes, default is autodetected from boot record")]
    partition_size: Option<u64>,

    #[structopt(short="-m", long="--map", parse(from_os_str))]
    ddrescue_map: Option<PathBuf>,

    #[structopt(short="-c", long="--cluster")]
    cluster_size: Option<u8>,

    #[structopt(short="-s", long="--sector")]
    sector_size: Option<u16>,

    #[structopt(long, help="Size of the MFT entry in bytes, default is either autodetected from boot record, or 1024 is used")]
    mft_entry: Option<u64>,

    #[structopt(long, help="Size of the index entry in bytes, default is either autodetected from boot record, or 1024 is used")]
    index_entry: Option<u64>,

    #[structopt(short, help="Be more verbose")]
    verbose: bool,

    #[structopt(short, help="Dump al processed data structures")]
    print_structures: bool,

    #[structopt(long, help="Re-use saved signatures")]
    reuse_sigs: bool,

    #[structopt(long, help="Try to parse indices, which may resolve some extra file names")]
    parse_indices: bool,

    #[structopt(long, help="Create stub files even if the file data is not unavailable, but the file's existence was deduced")]
    stub_files: bool,
}

fn parse_rel_size(rel_size: i8, cluster_size: u64) -> u64 {
    if rel_size < 0 {
        1 << (-rel_size)
    } else {
        cluster_size* (rel_size as u64)
    }
}

fn ignore_err(r: Result<()>, kind: std::io::ErrorKind) -> Result<()>{
    match r {
        Err(e) if e.kind() == kind => Ok(()),
        _ => r,
    }
}

fn mkdirs(path: &Path) -> std::io::Result<()> {
    ignore_err(std::fs::create_dir_all(path), std::io::ErrorKind::AlreadyExists)
}

fn div_up(a: u64, b: u64) -> u64 {
    (a + b - 1) / b
}

fn main() {
    let opts: Opts = Opts::from_args();
    
    let img = image::Image::new(
        &opts.disk_image, opts.ddrescue_map.as_deref()).unwrap();

    let boot_sect_offset = ntfs::STD_SECTOR * opts.partition_offset;
    let boot_sect_data = img.read(boot_sect_offset, 512).unwrap();
    let boot_sect = boot_sect_data.whole().parse::<ntfs::BootSector>().unwrap();

    let valid_boot_sect;
    if !boot_sect.is_valid() {
        valid_boot_sect = None;
        println!("Warning: boot sector does not appear to be valid, are partition offset specified correctly?");
    } else {
        valid_boot_sect = Some(boot_sect);
    }

    println!("{:?}", boot_sect);

    let sector_size = opts.sector_size
        .or_else(|| valid_boot_sect.map(|b| b.bytes_per_sec.val()))
        .unwrap_or_else(|| panic!("Sector size could not be auto-detected, specify it manually"));
    println!("Sector size: {}", sector_size);

    let cluster_factor = opts.cluster_size
        .or_else(|| valid_boot_sect.map(|b| b.sec_per_clus))
        .unwrap_or_else(|| panic!("Cluster size could not be auto-detected, specify it manually")) as u64;
    let cluster_size = cluster_factor * (sector_size as u64);
    println!("Cluster size: {}", cluster_size);

    let mftr_size = opts.mft_entry
        .or_else(|| valid_boot_sect.map(|b| parse_rel_size(b.mftr_size, cluster_size)))
        .unwrap_or(1024);
    println!("Using MFT record size: {}", mftr_size);

    let index_size = opts.index_entry
        .or_else(|| valid_boot_sect.map(|b| parse_rel_size(b.index_size, cluster_size)))
        .unwrap_or(1024);
    println!("Using Index record size: {}", index_size);

    let partition_size = opts.partition_size
        .or_else(|| valid_boot_sect.map(|b| b.sector_count.val()*(sector_size as u64)))
        .unwrap_or_else(|| panic!("Partition size could not be aut-detected, specify it manually"));
    if boot_sect_offset + partition_size > img.size()  {
        println!("Warning: boot sector indicates that the partition is larger than the disk image, is the image complete?");
    }

    if opts.print_structures {
        println!("{:#X?}", boot_sect);
    }
    let scan_unit_size = cluster_size.max(mftr_size).max(index_size).max(1024*64);
    let scan_units = div_up(partition_size,scan_unit_size);

    if  scan_unit_size % mftr_size!= 0 {
        panic!("Determined scan unit size: {:#x}, but that is not multiple of MTF record size {:#x}", scan_unit_size, mftr_size);
    }

    if  scan_unit_size % index_size != 0 {
        panic!("Determined scan unit size: {:#x}, but that is not multiple of index record size {:#x}", scan_unit_size, index_size);
    }

    ignore_err(std::fs::create_dir(&opts.working_dir), std::io::ErrorKind::AlreadyExists).unwrap();
    
    let mut context = DumpContext {
        opts, cluster_size, cluster_factor, sector_size, mftr_size, index_size,
        scan_unit_size, scan_units: scan_units,
        image: img,
        partition_offset: boot_sect_offset,
        mft_records: Vec::new(),
        mftr_by_id: HashMap::new(),
    };

    if context.opts.reuse_sigs {
        println!("=== Loading MFT records");
        context.scan_by_signatures();
    } else {
        println!("=== Searching for MFT records");
        context.linear_image_scan();
    }

    println!("=== Analysis");
    context.link_children();
    context.assign_names();
    println!("=== Writing files");
    context.dump().unwrap();
}

/// Helper data structure to store information about either resident or non-resident data
#[derive(Clone, Debug)]
pub enum Residency<R, N> {
    Resident(R),
    NonResident(N),
}

impl<R, N> Residency<R, N> {
    pub fn resident(&self) -> Option<&R> {
        match self {
            Residency::Resident(x) => Some(x),
            _ => None,
        } 
    }
    pub fn non_resident(&self) -> Option<&N> {
        match self {
            Residency::NonResident(x) => Some(x),
            _ => None,
        } 
    }
}

/// ID is index inside the MFT (record number)
#[derive(Debug, Clone, Copy, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub struct MtfId(u32);

/// Index is index into the table
#[derive(Debug, Clone, Copy, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub struct MtfIdx(usize);

#[derive(Clone, Debug)]
pub struct CombinedMftRecord {
    /// NTFS ID of the MFT
    pub mft_id: MtfId,
    /// Our internal index in the MFT array
    pub mtf_idx: MtfIdx,
    /// Data parsed from the MFT
    pub parsed: Option<ParsedMftRecord>,
    /// Data parsed from indices
    pub parsed_indices: Vec<FileInfo>,

    // Based on the above data we construct these links
    pub seen_children: Vec<MtfIdx>,
    pub seen_parents: Vec<(String, MtfIdx)>,

    /// If root (no parents), name will eventually be assigned
    pub root_name: Option<String>,
}

impl Display for CombinedMftRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(p) = &self.parsed {
            if !p.names.is_empty() {
                write!(f, "MFT {:#X} {}", self.mft_id.0, p.names.first().unwrap().name)?;
                return Ok(());
            }
        }
        write!(f, "MFT {:#X}", self.mft_id.0)?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ParsedNonResident {
    length: u64,
    runs: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ParsedMftRecord {
    pub mft_data_offset: u64,
    pub names: Vec<FileInfo>,
    pub is_dir: bool,
    /// Either the data itself or the RunData
    pub data: Option<Residency<Vec<u8>, ParsedNonResident>>,
}

#[derive(Clone, Debug)]
pub struct FileInfo {
    pub namespace: u8,
    pub name: String,
    pub parent_ref: u64,
}

#[derive(Clone, Debug)]
pub struct UsnInfo {
    offset: u16,
    size: u16,
}

/// A disk image with some information
pub struct DumpContext {
    image: Image,
    opts: Opts,
    /// Size of cluster in bytes
    cluster_size: u64,
    /// Number of clusters in sector
    #[allow(unused)]
    cluster_factor: u64,
    /// Size of sector in bytes
    sector_size: u16,
    /// Number of bytes per MFT Record
    mftr_size: u64,
    /// Number of bytes per Index Record
    index_size: u64,
    partition_offset: u64,

    scan_unit_size: u64,
    scan_units: u64,

    mft_records: Vec<Rc<RefCell<CombinedMftRecord>>>,
    mftr_by_id: HashMap<MtfId, MtfIdx>,
}

pub trait Reporter {
    fn report(&self, msg: &str) -> Result<()>;
}

impl<F> Reporter for F
    where F: Fn(&str) -> Result<()> 
{
    fn report(&self, msg: &str) -> Result<()> {
        self(msg)
    }
}

fn from_utf16(slice: &[u8]) -> String {
    let mut buf = Vec::new();
    for i in 0..(slice.len()/2) {
        let c = u16::from_le_bytes(slice[i*2..(i*2+2)].try_into().unwrap());
        buf.push(c);
    }
    String::from_utf16_lossy(&buf)
}

fn rank_namespace(ns: u8) -> u8 {
    match ns {
        ntfs::NS_POSIX => 1,
        ntfs::NS_DOS => 2,
        ntfs::NS_WINDOS => 3,
        ntfs::NS_WIN32 => 3,
        _ => 0,
    }
}

fn filter_names(names: &mut Vec<FileInfo>) {
    let tmp = names.drain(..).collect_vec();
    names.sort_by(|a, b| a.parent_ref.cmp(&b.parent_ref));
    for (_key, group) in tmp.into_iter().group_by(|f| f.parent_ref).into_iter() {
        names.push(group.max_by_key(|f| rank_namespace(f.namespace)).unwrap())
    }
}

fn create_hardlink_set(base_path: &Path, paths: &Vec<PathBuf>, suffix: &Option<PathBuf>) -> std::io::Result<Option<File>> {
    let mut iter = paths.iter().map(|p| {
        if let Some(suffix) = suffix {
            p.join(suffix)
        } else {
            p.clone()
        }
    });
    if let Some(first) = iter.next() {
        println!("Writing file {}", first.to_string_lossy());
        let primary_path_full = base_path.join(first);
        let file = std::fs::File::create(&primary_path_full)?;
        for p in iter {
            println!("Hardlink at {}", p.to_string_lossy());
            std::fs::hard_link(&primary_path_full, base_path.join(p))?;
        }
        Ok(Some(file))
    } else {
        Ok(None)
    }
}

impl DumpContext {
    pub fn get_mftr(&mut self, id: MtfId) -> Rc<RefCell<CombinedMftRecord>> {
        if let Some(idx) = self.mftr_by_id.get(&id) {
            self.mft_records[idx.0].clone()
        } else {
            let idx = MtfIdx(self.mft_records.len());
            let rec = Rc::new(RefCell::new(CombinedMftRecord {
                mft_id: id, mtf_idx: idx,
                parsed: None,
                seen_children: Vec::new(),
                seen_parents: Vec::new(),
                parsed_indices: Vec::new(),
                root_name: None,
            }));
            self.mft_records.push(rec.clone());
            self.mftr_by_id.insert(id, idx);
            return rec;
        }
    }

    pub fn load_scan_unit(&self, idx: u64) -> Result<ImageData> {
        // check that at least that the beginning is not oob
        assert!(idx < self.scan_units);
        let size;
        if idx == self.scan_units - 1 {
            size = self.image.size() % self.scan_unit_size;
        } else {
            size = self.scan_unit_size;
        }
        self.image.read(self.scan_unit_size * idx, size as usize)
    }

    /// Scan the file to find MFT Records and Index Records
    pub fn linear_image_scan(&mut self) {
        let sig_file = std::fs::File::create(self.opts.working_dir.join("sig_list.txt")).unwrap();
        let mut sig_file = std::io::BufWriter::new(sig_file);

        // the basic logic is to go by scan units, then 
        for i in 0..self.scan_units {
            let data = self.load_scan_unit(i).unwrap();
            let off = data.whole().offset();
            self.scan_one_unit(data, Some(&mut sig_file));
           
            if off % (32*1024*1024) == 0 {
                println!("Progress: offset {:X}", off)
            }
        }
    }

    /// Go through the possible locations in the scan unit data where indices might be located.
    /// Any found indices are recorded to self, and possibly stored to the signature file.
    ///
    /// Errors are printed to scre
    pub fn scan_one_unit(&mut self, mut data: ImageData, mut sig_output: Option<&mut impl Write>) {
        let report = |msg, area: &mut ImageDataMutSlice, r: ParsingResult<()>| {
            if let Err(e) = r {
                println!("{}", e.with_context(area.borrow().as_const().err_ctx(msg)));
            }
        };
        let data_len = data.whole().len() as u64;

        for j in 0..(data_len/self.mftr_size) {
            let mut area = data.whole_mut().sub((self.mftr_size  * j) as usize, self.mftr_size as usize).unwrap();
            let off = area.offset();
            let hdr=  area.borrow().as_const().parse::<ntfs::MftRecord>().unwrap();
            if hdr.magic.val() == ntfs::MFT_REC_MAGIC && ((hdr.flags.val() & ntfs::MFT_REC_FLAG_USE) != 0) {
                if self.opts.verbose {
                    println!("Potential MFT entry {} found at offset {:X}", hdr.record_num.val(), off);
                }
                sig_output.as_mut().map(|sig_output| {
                    writeln!(sig_output, "FILE {:X}", off).unwrap();
                });
                let err = self.parse_mftr(&mut area);
                report( "MFT Entry", &mut area, err);
            } 
        }

        for j in 0..(data_len/self.index_size) {
            let mut area = data.whole_mut().sub((self.index_size  * j) as usize, self.index_size as usize).unwrap();
            let off = area.offset();
            let hdr=  area.borrow().as_const().parse::<ntfs::IndexRecord>().unwrap();
            if hdr.magic.val() == ntfs::INDEX_REC_MAGIC {
                if self.opts.verbose {
                    println!("Potential Index entry found at offset {:X}", off);
                }
                sig_output.as_mut().map(|sig_output| {
                    writeln!(sig_output, "INDX {:X}", off).unwrap();
                });
                let err = self.parse_index(&mut area);
                report( "Index Entry", &mut area, err);
            }
        }
    }

    pub fn scan_by_signatures(&mut self) {
        let sig_file = std::fs::File::open(self.opts.working_dir.join("sig_list.txt")).unwrap();
        let mut sig_file = std::io::BufReader::new(sig_file);
        let mut line_nr = 0;
        loop {
            let mut line = String::new();
            sig_file.read_line(&mut line).unwrap();
            if line.is_empty() {
                break;
            }
            line_nr += 1;
            let panic = || panic!("Signature file malformed at line {}", line_nr);
            let line: Vec<_> = line.split_ascii_whitespace().collect();
            if line.is_empty() {
                continue
            }
            if line.len() < 2 {
                panic();
            }
            let sig = line[0];
            let offset = u64::from_str_radix(line[1], 16).unwrap_or_else(|_| panic());
            if sig == "FILE" {
                let mftr_data = self.image.read(offset, self.mftr_size as usize);
                if let Ok(mut mftr_data) = mftr_data {
                    if let Err(e) = self.parse_mftr(&mut mftr_data.whole_mut()) {
                        println!("{}", e);
                    }
                } else {
                    println!("Saved MFT entry at {} can not be loaded", offset);
                }
            } else if sig == "INDX" {
                let index_data = self.image.read(offset, self.index_size as usize);
                if let Ok(mut index_data) = index_data {
                    if let Err(e) = self.parse_index(&mut index_data.whole_mut()) {
                        println!("{}", e);
                    }
                } else {
                    println!("Saved Index entry at {} can not be loaded", offset);
                }
            } 
            else {
                panic();
            }
        }
    }

    pub fn parse_fn_attr(&self, data: ImageDataSlice) -> ParsingResult<FileInfo> {
        let mk_err = |m| ParsingError::new(m).with_context(data.err_ctx("File Name attribute"));
        let attr_fn = data.parse::<ntfs::AttrFileName>().map_err(|_| mk_err("FileName attribute is too short"))?;
        let fname = data.sub(size_of::<ntfs::AttrFileName>(),  (attr_fn.file_name_length as usize)*2)
            .map_err(|_| mk_err("FileName out of attribute data bounds"))?;
        let fname = from_utf16(&*fname);
        if self.opts.print_structures {
            println!("{:X?}, file_name = \"{}\"", attr_fn, fname);
        }
        match attr_fn.namespace {
            ntfs::NS_DOS => (),
            ntfs::NS_POSIX => (),
            ntfs::NS_WIN32 => (),
            ntfs::NS_WINDOS => (),
            _ => return Err(mk_err("Invalid value for file namespace"))
        }

        Ok(FileInfo {
            namespace: attr_fn.namespace,
            name: fname,
            parent_ref: attr_fn.ref_parent.val(),
        })
    }

    pub fn parse_attr(&mut self, attr_buf: ImageDataSlice, attr_header: &ntfs::AttrHeader, parsed_mft: &mut ParsedMftRecord) -> ParsingResult<()> {
        let mk_ctx = || attr_buf.err_ctx(format!("Attribute type {:#X}", attr_header.attr_type.val()));
        let mk_err = |m| ParsingError::new(m).with_context(mk_ctx());

        let name =  || if attr_header.name_length == 0 { Ok(None) } else {
            attr_buf.sub(attr_header.offset_name.val() as usize, (attr_header.name_length as usize)*2)
                .map_err(|_| mk_err("Attribute name out of bounds"))
                .and_then(|d| Ok(Some(from_utf16(&*d))))
        };

        let attr_variant ;
        if attr_header.non_resident == 0 {
            attr_variant = Residency::Resident(attr_buf.parse::<ntfs::AttrResident>().map_err(|_| mk_err("Length too short for resident attribute"))?);
        } else {
            attr_variant = Residency::NonResident(attr_buf.parse::<ntfs::AttrNonResident>().map_err(|_| mk_err("Length too short for non-resident attribute"))?);
        }
        let get_resident_data = |r: &ntfs::AttrResident| attr_buf.tail(r.off_attrib_data.val() as usize)
            .map_err(|_| mk_err("Resident data out of range"));

        let get_data_runs = |r: &ntfs::AttrNonResident| attr_buf.tail(r.data_runs_offset.val() as usize)
            .map_err(|_| mk_err("Data runs out of range"));

        if self.opts.print_structures {
            println!("{:X?}, name = {:?}", attr_variant, name()?);
        }

        // individual attribute types
        let attr_type = attr_header.attr_type.val();
        if attr_type == ntfs::ATTRT_FILENAME {
            if let Some(attr_resident) = attr_variant.resident() {
                let resident_data = get_resident_data(attr_resident)?;
                parsed_mft.names.push(self.parse_fn_attr(resident_data).map_err(|e| e.with_context(mk_ctx()))?);
            } else {
                return Err(mk_err("FileName Attribute is not resident"));
            }
        } else if attr_type == ntfs::ATTRT_ATTRIBUTE_LIST {
            return Err(mk_err("Warning: attribute lists not yet supported"))
        } else if attr_type == ntfs::ATTRT_DATA {
            let name = name()?;
            if name.is_none() {
                // we are interested only in the main data stream
                match attr_variant {
                    Residency::Resident(attr_resident) => {
                        parsed_mft.data = Some(Residency::Resident(get_resident_data(attr_resident)?.to_vec()));
                    },
                    Residency::NonResident(attr_non_resident) => {
                        if attr_non_resident.compression_unit_size.val() != 0 {
                            return Err(mk_err("Warning: compressed files not yet supported"))
                        }
                        let data_runs = get_data_runs(attr_non_resident)?.into_slice().to_vec();
                        parsed_mft.data = Some(Residency::NonResident(ParsedNonResident {
                            length: attr_non_resident.initialized_size,
                            runs: data_runs,
                        }));
                    },
                }
            }
        } else if attr_type == ntfs::ATTRT_INDEX_ROOT {
            if self.opts.parse_indices {
                if let Some(attr_resident) = attr_variant.resident() {
                    let resident_data = get_resident_data(attr_resident)?;
                    let index_root = resident_data.parse::<ntfs::AttrIndexRoot>()
                        .map_err(|_| mk_err("Attribute too small to hold index root header"))?;
                    let offset = ntfs::ATTR_INDEX_NODE_HEADER_OFFSET + index_root.index_node_header.offset_first_entry.val() as usize;
                    let elements_data = resident_data.tail(offset)
                        .map_err(|_| mk_err("Attribute elements out of attribute data"))?;
                    self.parse_index_elements(elements_data, true)
                        .map_err(|e| e.with_context(mk_ctx()))?;
                } else {
                    return Err(mk_err("FileName Attribute is not resident"));
                }
            }
        }
        Ok(())
    }

    pub fn parse_mftr(&mut self, buf_mut: &mut ImageDataMutSlice) -> ParsingResult<()> {
        let mut parsed_mft;
        let usn_info;
        {
            // first stage of the parsing (header)
            let buf = buf_mut.borrow().as_const();
            let mftr = buf.parse::<ntfs::MftRecord>().unwrap();
            if !(mftr.magic.val() == ntfs::MFT_REC_MAGIC 
                    && (mftr.flags.val() & ntfs::MFT_REC_FLAG_USE) != 0) {
                return Err(ParsingError::new("MFT Entry Invalid header").with_context(buf.err_ctx("MFT Entry Header")));
            }
            if self.opts.print_structures {
                println!("{:X?}", mftr);
            }

            parsed_mft  = ParsedMftRecord {
                is_dir: (mftr.flags.val() & ntfs::MFT_REC_FLAG_DIR) != 0,
                names: Vec::new(),
                mft_data_offset: buf.offset(),
                data: None,
            };
            usn_info = UsnInfo {
                offset: mftr.update_sequence_offset.val(),
                size: mftr.update_sequence_words.val(),
            }
        }

        // USN fixups
        self.fixup_usn(buf_mut, usn_info)
            .map_err(|e| e.with_context(buf_mut.borrow().as_const().err_ctx("MFT Entry")))?;

        // Second stage of the parsing (attributes)
        {
            let buf = buf_mut.borrow().as_const();
            let mftr = buf.parse::<ntfs::MftRecord>().unwrap();
            let mft_ctx = || buf.err_ctx("MFT Entry");
            let mk_err = |e| ParsingError::new(e).with_context(mft_ctx());

            let mut current_offset = mftr.attributes_offset.val() as usize;
            loop {
                // Header
                let attr_header = buf.parse_at::<ntfs::AttrHeader>(current_offset)
                    .map_err(|_| mk_err("Attribute header offset out of bounds"))?;
                if attr_header.attr_type.val() == ntfs::MFT_REC_END {
                break;
                }
                let size = attr_header.attr_size.val() as usize;
                if size == 0 || size % 8 != 0 {
                    return Err(ParsingError::new(format!("Attribute size {} is invalid", size)).with_context(buf.tail(current_offset).unwrap().err_ctx("Attribute")));
                }

                let attr_slice = buf.sub(current_offset, size).map_err(|_| mk_err("Attribute out of bounds"))?;
                self.parse_attr(attr_slice, attr_header, &mut parsed_mft).map_err(|e| e.with_context(mft_ctx()))?;

                current_offset += size;
            }
            filter_names(&mut parsed_mft.names);
            if parsed_mft.names.len() == 0 {
                return Err(mk_err("No file names found"));
            }

            let id = MtfId(mftr.record_num.val());
            if id.0 != 0 {
                let rec = self.get_mftr(id);
                rec.borrow_mut().parsed = Some(parsed_mft);
            } else {
                return Err(mk_err("MFT Record does not have explicit ID -- is this pre XP FS? This is currently not supported"))
            }
            Ok(())
        }
    }

    pub fn parse_index_elements(&mut self, buf: ImageDataSlice, strict: bool) -> ParsingResult<()> {
        let mk_ctx = ||  buf.err_ctx("Index Record");
        let mk_err = |e| ParsingError::new(e).with_context(mk_ctx());

        // We may not know what the type of the index is, so we just try to parse the attribute as file-name attributes
        // and hope for the best. 
        let mut attrs: Vec<(MtfId, FileInfo)> = Vec::new();
        let mut failed_attrs = 0usize;
        
        let mut current_offset = 0;
        loop {
            let index_element = buf.parse_at::<ntfs::IndexEntry>(current_offset)
                .map_err(|_| mk_err("Index element out of bounds"))?;

            if (index_element.entry_length.val() as usize) < size_of::<ntfs::IndexEntry>() {
                return Err(mk_err("Index element length is smaller than header length"))
            }
            let data = buf.sub(current_offset, index_element.entry_length.val() as usize)
                .map_err(|_| mk_err("Index data out of bounds"))?;
            if (index_element.flags & ntfs::IDX_ENTRY_LAST) == 0 {
                let attr_data = data.sub(size_of::<ntfs::IndexEntry>(), index_element.stream_length.val() as usize)
                    .map_err(|_| mk_err("Index attribute data out of bounds"))?;
                if self.opts.print_structures {
                    println!("{:X?}", index_element);
                }

                match self.parse_fn_attr(attr_data) {
                    Ok(fi) => {
                        let parent_id = MtfId((index_element.file_reference.val() & 0x0000FFFFFFFFFFFF) as u32);
                        attrs.push((parent_id, fi));
                    },
                    Err(e) => {
                        if strict {
                            return Err(e);
                        } else {
                            failed_attrs += 1;
                        }
                    }
                }
            } else {
                break;
            }
            current_offset += index_element.entry_length.val() as usize;
        }
        if failed_attrs == 0 {
            // maybe choose a different heuristic?
            for (child, fi) in attrs {
                let mftr = self.get_mftr(child);
                let mut mftr = mftr.borrow_mut();
                mftr.parsed_indices.push(fi);
            }
        } else {
            if self.opts.verbose {
                println!("There were {} index elements that did not look like file name attributes", failed_attrs);
            }
        }
        Ok(())
    }

    pub fn parse_index(&mut self, buf_mut: &mut ImageDataMutSlice) -> ParsingResult<()> {
        if !self.opts.parse_indices {
            return Ok(())
        }
        // TODO: Also parse index root entries.
        let node_header;
        let usn_info;
        {
            // first stage of the parsing (header)
            let header = buf_mut.borrow().as_const();
            let index = header.parse::<ntfs::IndexRecord>().unwrap();
            if self.opts.print_structures {
                println!("{:X?}", index);
            }

            usn_info = UsnInfo {
                offset: index.update_sequence_offset.val(),
                size: index.update_sequence_words.val(),
            };
            node_header = index.index_node_header;
        }

        // USN fixups
        self.fixup_usn(buf_mut, usn_info)
            .map_err(|e| e.with_context(buf_mut.borrow().as_const().err_ctx("MFT Entry")))?;

        // Second stage of the parsing (indexed attributes)        
        let buf = buf_mut.borrow().as_const()
            .tail(node_header.offset_first_entry.val() as usize + ntfs::INDEX_RECORD_NODE_HEADER_OFFSET)
            .unwrap();
        
        self.parse_index_elements(buf, false)?;
       
        Ok(())
    }

    /// https://flatcap.org/linux-ntfs/ntfs/concepts/fixup.html
    pub fn fixup_usn(&self, mut_slice: &mut ImageDataMutSlice, usn_info: UsnInfo) -> ParsingResult<()> {
        if usn_info.size == 0 {
            return Ok(())
        }
        let mut sector_iter = mut_slice.borrow().chunks(self.sector_size as usize)
            .map(|s| s.split(self.sector_size as usize - 2).unwrap()).enumerate();
        // get the individual sectors --  the first one is a special one since it also contains the USN Array
        let (_, (sector, first_usn)) = sector_iter.next().unwrap();
        let usn_array = sector.as_const().sub(usn_info.offset as usize, (usn_info.size*2) as usize)
            .map_err(|_| ParsingError::new("Update Sequence array is outside of the first sector"))?;

        // some helpers
        let get_usn_elem = |i| {
            Ok(u16::from_le_bytes(usn_array.sub(i*2, 2).map_err(|_| 
                ParsingError::new(format!("Update Sequence fixup number {} is out of bounds", i))
            )?.into_slice().try_into().unwrap()))
        };
        let seqn = get_usn_elem(0)?;
        let do_fixup = |i: usize, mut usn: ImageDataMutSlice| {
            let fixup_val = get_usn_elem(i + 1)?;
            let val = u16::from_le_bytes(usn.borrow().as_const().into_slice().try_into().unwrap());
            if val != seqn {
                return Err(ParsingError::new("Update Sequence number mismatch, fixup failed")
                    .with_context(usn.borrow().as_const().err_ctx("USN Fixup location"))
                )
            };
            usn.copy_from_slice(&fixup_val.to_le_bytes());
            Ok(())
        };

        do_fixup(0, first_usn)?;

        for (i, (_, usn)) in sector_iter {
            do_fixup(i, usn)?
        }

        Ok(())
    }

    /// Construct the directory hierarchy.
    ///
    /// This fills in the `seen_children` and `seen_parents` members that is are for traversal later.
    pub fn link_children(&mut self) {

        for idx in 0..self.mft_records.len() {
            let r_rc = self.mft_records[idx].clone();
            let mut r_ref = r_rc.borrow_mut();
            let r = &mut *r_ref;
            let names;
            filter_names(&mut r.parsed_indices);

            // Prefer the names from the MFTR, not only random reference
            if let Some(parsed) = &r.parsed {
                names = &parsed.names;
            } else {
                names = &r.parsed_indices
            }

            for fi in names.iter() {
                let parent_ref = (fi.parent_ref & 0x0000FFFFFFFFFFFF) as u32;
                // println!("{} -> {:#X}", &*r, pref);

                if parent_ref == r.mft_id.0 {
                    if r.mft_id.0 != ntfs::MFT_ID_ROOT {
                        println!("Warning: loop")
                    }
                } else {
                    let parent_rc = self.get_mftr(MtfId(parent_ref as u32));
                    let mut parent = parent_rc.borrow_mut();
                    parent.seen_children.push(r.mtf_idx);
                    r.seen_parents.push((fi.name.to_owned(), parent.mtf_idx));
                }
            }
        }
        // todo: we should find a spanning tree now to get rid of loops and allow us to find roots
        // todo: we should also dedup file names
    }

    /// Assign names to all root items
    pub fn assign_names(&mut self) {
        for r in self.mft_records.iter() {
            let mut r = r.borrow_mut();
            if r.mft_id.0 == ntfs::MFT_ID_ROOT {
                r.root_name = Some("root".to_owned());
            } else if r.seen_parents.is_empty() {
                r.root_name = Some(format!("unknown-{:X}-{}", r.mft_id.0, r.mtf_idx.0));
            }
        }
    }

    /// Get all possible paths this file is known as
    pub fn get_paths(&self, current: &CombinedMftRecord) -> Vec<PathBuf> {
        if let Some(root_name) = &current.root_name {
            return vec![PathBuf::from(root_name)];
        } else {
            let mut out = Vec::new();
            if current.seen_parents.is_empty() {
                panic!("Get paths inconsitency {}", current);
            }
            for (my_name, parent_idx) in &current.seen_parents {
                let parent = self.mft_records[parent_idx.0].clone();
                for mut parent_path in self.get_paths(&*parent.borrow_mut()) {
                    parent_path.push(my_name);
                    out.push(parent_path);
                }
            }
            return out;
        }
    }

    pub fn dump_file(&self, file: &mut File, reporter: &impl Reporter, non_resident: &ParsedNonResident) -> Result<()> {
        let length = non_resident.length;
        if let Some(runs) = data_runs::decode_data_runs(non_resident.runs.as_slice()) {
            let mut total = 0u64;
            let mut total_logical = 0u64;
            let mut corrupted = 0u64;
            for run in runs {
                let max_chunk = (length - total_logical).min(run.lcn_length * self.cluster_size) as usize;
                if run.lcn_offset == 0 {
                    file.seek(SeekFrom::Current(run.lcn_length as i64 * self.cluster_size as i64))?;
                } else {
                    let data = self.image.read(
                        self.partition_offset + self.cluster_size * run.lcn_offset, 
                        (self.cluster_size * run.lcn_length) as usize)?;
                    let slice = data.whole().into_slice();
                    corrupted += data.whole().bad_bytes();
                    total += max_chunk as u64;
                    file.write_all(&slice[..max_chunk])?;
                }
                total_logical += max_chunk as u64;
            }
            if corrupted > 0 {
                let percent = (corrupted  as f64)/(total as f64)*100.;
                reporter.report(&format!("{:.4}% is known to be corrupted", percent))?;
            }
        } else {
            writeln!(file, "{}: The run data is corrupted", PROGRAM_NAME)?;
            reporter.report("Run data is corrupted")?;
        }
        Ok(())
    }

    pub fn dump(&self) -> Result<()> {
        let report = File::create(self.opts.working_dir.join("corrupted-report.txt"))?;
        let report = RefCell::new(BufWriter::new(report));

        let base_path = self.opts.working_dir.clone().join("files");
        for r in self.mft_records.iter() {
            let r_ref = r.borrow();
            let r = &* r_ref;
            let all_paths = self.get_paths(r);
            assert!(!all_paths.is_empty());
            // println!("Paths {:?} for {:?}", all_paths, r);

            let report_header_written = Cell::new(false);
            let problem_reporter = |msg: &str| {
                let mut report  = report.borrow_mut();
                if !report_header_written.get() {
                    report_header_written.set(true);
                    for p in &all_paths {
                        writeln!(report, "{}:", p.to_string_lossy())?;
                    }
                }
                writeln!(report, "\t{}", msg)
            };

            if let Some(parsed) = &r.parsed {
                let suffix;
                let save;
                if parsed.is_dir || !r.seen_children.is_empty() {
                    for p in all_paths.iter() {
                        println!("Creating directory {}", p.to_string_lossy());
                        mkdirs(&base_path.join(p))?;
                    }

                    if !parsed.is_dir && parsed.data.is_some() {
                        // We might need to store data somewhere else if there is a directory with data...
                        // Yes, this is a corruption but lets store the data somewhere.
                        suffix = Some(PathBuf::from(format!("{}-saved-data", PROGRAM_NAME)));
                        save = true;
                    } else {
                        save = false;
                        suffix = None;
                    }
                } else {
                    for p in all_paths.iter() {
                        mkdirs(&base_path.join(p.parent().unwrap()))?;
                    }
                    suffix = None;
                    save = true;
                }

                if save {
                    let mut file = create_hardlink_set(&base_path, &all_paths, &suffix)?.unwrap();
                    match &parsed.data {
                        None => {
                            writeln!(file, "{}: no data was found in the FS", PROGRAM_NAME)?;
                            problem_reporter("No data was found in the FS")?;
                        },
                        Some(Residency::Resident(data)) => {
                            file.write_all(&data)?;
                        },
                        Some(Residency::NonResident(data_runs)) => {
                            self.dump_file(&mut file, &problem_reporter, data_runs)?;
                        },
                    }
                }
            } else {
                // no parsed data, create a stub file (only if we don't have children, in that case we are directory)
                if self.opts.stub_files {
                    if r.seen_children.is_empty() {
                        for p in all_paths.iter() {
                            mkdirs(&base_path.join(p.parent().unwrap()))?;
                        }
                        let mut file = create_hardlink_set(&base_path, &all_paths, &None)?.unwrap();
                        writeln!(file, "{}: not enought information about the file", PROGRAM_NAME)?;
                        problem_reporter("not engouh information about the file")?;
                    }
                }
            }
        }
        Ok(())
    }
}
