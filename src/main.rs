use structopt::StructOpt;
use std::{borrow::Cow, cell::Cell, cell::RefCell, fmt::Display, fs::File, mem::size_of, path::{Path, PathBuf}, rc::Rc};
use image::{Image, ImageData, ImageDataSlice};
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

    #[structopt(short="-m", long="--map", parse(from_os_str))]
    ddrescue_map: Option<PathBuf>,

    #[structopt(short="-c", long="--cluster")]
    cluster_size: Option<u8>,

    #[structopt(long, help="Size of the MFT entry in bytes, default is either autodetected from boot record, or 1024 is used")]
    mft_entry: Option<u64>,

    #[structopt(short, help="Be more verbose")]
    verbose: bool,

    #[structopt(short, help="Dump al processed data structures")]
    print_structures: bool,

    #[structopt(long, help="Re-use saved signatures")]
    reuse_sigs: bool,
}

fn parse_rel_size(rel_size: i8, cluster_size: u8) -> u64 {
    if rel_size < 0 {
        1 << (-rel_size)
    } else {
        (cluster_size as u64)* ntfs::SECTOR * (rel_size as u64)
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

fn main() {
    let opts: Opts = Opts::from_args();
    
    let img = image::Image::new(
        &opts.disk_image, opts.ddrescue_map.as_deref()).unwrap();

    let boot_sect_offset = ntfs::SECTOR * opts.partition_offset;
    let boot_sect_data = img.read(boot_sect_offset, 512).unwrap();
    let boot_sect = boot_sect_data.whole().parse::<ntfs::BootSector>().unwrap();

    let valid_boot_sect;
    if !boot_sect.is_valid() {
        valid_boot_sect = None;
        println!("Warning: boot sector does not appear to be valid, are partition offset specified correctly?");
    } else {
        valid_boot_sect = Some(boot_sect);
    }

    let cluster_size = opts.cluster_size
        .or_else(|| valid_boot_sect.map(|b| b.sec_per_clus))
        .unwrap_or_else(|| panic!("Cluster size could not be auto-detected, specify it manually"));

    if opts.verbose {
        println!("Using sectors per cluster value: {}", cluster_size);
    }

    let mftr_size = opts.mft_entry
        .or_else(|| valid_boot_sect.map(|b| parse_rel_size(b.mftr_size, cluster_size)))
        .unwrap_or(1024);

    if boot_sect.sector_count.val()*ntfs::SECTOR + boot_sect_offset > img.size() {
        println!("Warning: boot sector indicates that the partition is larger than the disk image, is the image complete?");
    }

    if opts.print_structures {
        println!("{:#X?}", boot_sect);
    }

    ignore_err(std::fs::create_dir(&opts.working_dir), std::io::ErrorKind::AlreadyExists).unwrap();
    
    let mut context = DumpContext {
        opts, cluster_size, mftr_size,
        image: img,
        partition_offset: boot_sect_offset,
        mft_records: Vec::new(),
        mftr_by_id: HashMap::new(),
    };

    if context.opts.reuse_sigs {
        context.load_mftrs();
    } else {
        context.find_mftrs();
    }
    context.link_children();
    context.assign_names();
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
    pub mft_id: MtfId,
    pub mtf_idx: MtfIdx,
    pub parsed: Option<ParsedMftRecord>,
    pub seen_children: Vec<MtfIdx>,
    pub seen_parents: Vec<(String, MtfIdx)>,
    /// If root, name will eventually be assigned
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
pub struct ParsedMftRecord {
    pub mft_data_offset: u64,
    pub names: Vec<FileInfo>,
    pub is_dir: bool,
    /// Either the data itself or the RunData
    pub data: Option<Residency<Vec<u8>, Vec<u8>>>,
}

#[derive(Clone, Debug)]
pub struct FileInfo {
    pub namespace: u8,
    pub name: String,
    pub parent_ref: u64,
}

/// A disk image with some information
pub struct DumpContext {
    image: Image,
    opts: Opts,
    /// Number of sectors per cluster
    cluster_size: u8,
    /// Number of bytes per MFT Record
    mftr_size: u64,
    partition_offset: u64,

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

fn create_hardlink_set(paths: &Vec<PathBuf>, suffix: &Option<PathBuf>) -> std::io::Result<Option<File>> {
    let mut iter = paths.iter().map(|p| {
        if let Some(suffix) = suffix {
            Cow::Owned(p.clone().join(suffix))
        } else {
            Cow::Borrowed(p)
        }
    });
    if let Some(first) = iter.next() {
        println!("Writing file {}", first.to_string_lossy());
        let file = std::fs::File::create(&*first)?;
        for p in iter {
            println!("Hardlink at {}", p.to_string_lossy());
            std::fs::hard_link(&*first, &*p)?;
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
                root_name: None,
            }));
            self.mft_records.push(rec.clone());
            self.mftr_by_id.insert(id, idx);
            return rec;
        }
    }

    pub fn find_mftrs(&mut self) {
        let sig_file = std::fs::File::create(self.opts.working_dir.join("sig_list.txt")).unwrap();
        let mut sig_file = std::io::BufWriter::new(sig_file);
        let mftr_count  = self.image.size() / self.mftr_size;
        for p in 0..mftr_count {
            let off = p * self.mftr_size;
            if off % (32*1024*1024) == 0 {
                println!("Progress: offset {:X}", off)
            }
            let mftr_data = self.image.read(off, self.mftr_size as usize);
            if let Ok(mftr_data) = mftr_data {
                let mftr = mftr_data.whole().parse::<ntfs::MftRecord>().unwrap();
                if mftr.magic.val() == ntfs::MFT_REC_MAGIC 
                    && (mftr.flags.val() & ntfs::MFT_REC_FLAG_USE) != 0 
                {
                    if self.opts.verbose {
                        println!("Potential MFT entry {} found at offset {:X}", mftr.record_num.val(), off);
                    }
                    writeln!(sig_file, "FILE {:X}", off).unwrap();
                    if let Err(e) = self.add_mtfr(mftr_data.whole()) {
                        println!("{}", e.with_context(mftr_data.whole().err_ctx("MFT Entry")));
                    }
                }
            } else {
                // just ignore the error
            }
        }
    }


    pub fn load_mftrs(&mut self) {
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
                if let Ok(mftr_data) = mftr_data {
                    if let Err(e) = self.add_mtfr(mftr_data.whole()) {
                        println!("{}", e);
                    }
                } else {
                    println!("Saved MFT entry at {} can not be loaded", offset);
                }
            } else {
                panic();
            }
        }
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
                let attr_fn = resident_data.parse::<ntfs::AttrFileName>().map_err(|_| mk_err("FileName attribute is too short"))?;
                let fname = resident_data.sub(size_of::<ntfs::AttrFileName>(),  (attr_fn.file_name_length as usize)*2)
                    .map_err(|_| mk_err("FileName out of attribute data bounds"))?;
                let fname = from_utf16(&*fname);
                if self.opts.print_structures {
                    println!("{:X?}, file_name = \"{}\"", attr_fn, fname);
                }
                parsed_mft.names.push(FileInfo {
                    namespace: attr_fn.namespace,
                    name: fname,
                    parent_ref: attr_fn.ref_parent.val(),
                });
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
                        parsed_mft.data = Some(Residency::NonResident(get_data_runs(attr_non_resident)?.into_slice().to_vec()))
                    },
                }
            }
        }
        Ok(())
    }

    pub fn add_mtfr(&mut self, buf: ImageDataSlice) -> ParsingResult<()> {
        // TODO: make USN fixups
        let mft_ctx = || buf.err_ctx("MFT Entry");
        let mk_err = |e| ParsingError::new(e).with_context(mft_ctx());

        let mftr = buf.parse::<ntfs::MftRecord>().unwrap();
        if !(mftr.magic.val() == ntfs::MFT_REC_MAGIC 
                && (mftr.flags.val() & ntfs::MFT_REC_FLAG_USE) != 0) {
            return Err(mk_err("MFT Entry Malformed"))
        }
        if self.opts.print_structures {
            println!("{:X?}", mftr);
        }
        let mut current_offset = mftr.attributes_offset.val() as usize;
        let mut parsed_mft  = ParsedMftRecord {
            is_dir: (mftr.flags.val() & ntfs::MFT_REC_FLAG_DIR) != 0,
            names: Vec::new(),
            mft_data_offset: buf.offset(),
            data: None,
        };
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
            return Err(mk_err("MFT record does not contain its own index"))
        }
        Ok(())
    }

    pub fn link_children(&mut self) {
        for idx in 0..self.mft_records.len() {
            let r_rc = self.mft_records[idx].clone();
            let mut r_ref = r_rc.borrow_mut();
            let r = &mut *r_ref;
            if let Some(parsed) = &r.parsed {
                for fi in parsed.names.iter() {
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
        }
        // todo: we should find a spanning tree now to get rid of loops and allow us to find roots
        // todo: we should also dedup file names
    }

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

    pub fn dump_file(&self, file: &mut File, reporter: &impl Reporter, data_runs: &[u8]) -> Result<()> {
        if let Some(runs) = data_runs::decode_data_runs(data_runs) {
            let mut total = 0;
            let mut corrupted = 0;
            for run in runs {
                for cluster in run.lcn_offset .. (run.lcn_offset + run.lcn_length) {
                    if run.lcn_offset == 0 {
                        file.seek(SeekFrom::Current(run.lcn_length as i64))?;
                    } else {
                        for sector in 0..self.cluster_size {
                            let sector = (cluster * (self.cluster_size as u64)) + (sector as u64);
                            let data = self.image.read(self.partition_offset + sector * ntfs::SECTOR, ntfs::SECTOR as usize);
                            if let Ok(data) = data {
                                let slice = data.whole().into_slice();
                                file.write_all(slice)?;
                            } else {
                                corrupted += 1;
                            }
                            total += 1;
                        }
                    }
                }
            }
            if corrupted > 0 {
                let percent = (corrupted  as f64)/(total as f64)*100.;
                reporter.report(&format!("{}% is known to be corrupted", percent))?;
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
            let all_paths_full =all_paths.iter().map(|p| base_path.clone().join(p)).collect_vec();
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
                    for p in all_paths_full.iter() {
                        println!("Creating directory {}", p.to_string_lossy());
                        mkdirs(&p)?;
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
                    for p in all_paths_full.iter() {
                        mkdirs(p.parent().unwrap())?;
                    }
                    suffix = None;
                    save = true;
                }

                if save {
                    let mut file = create_hardlink_set(&all_paths_full, &suffix)?.unwrap();
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
                // no parsed data, create a directory if we have children, or otherwise just stub, although this should not happen
                if r.seen_children.is_empty() {
                    let mut file = create_hardlink_set(&all_paths_full, &None)?.unwrap();
                    writeln!(file, "{}: not enought information about the file", PROGRAM_NAME)?;
                    problem_reporter("not engouh information about the file")?;
                } else {
                    for p in all_paths_full.iter() {
                        println!("Creating directory {}", p.to_string_lossy());
                        mkdirs(&p)?;
                    }
                }
            }
        }
        Ok(())
    }
}
