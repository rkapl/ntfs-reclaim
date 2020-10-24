# Reclaim files from corrupted NTFS image

This software allows you to get files from a corrupted NTFS file-system that
cannot be mounted normally, but still has some data stored somewhere (e.g. when
your flash drive fails). It assumes you have already imaged the faulty disk
using software like [ddrescue](https://www.gnu.org/software/ddrescue/) or just
simple Unix `dd`.

Once you have the image, try to get file out like this:

    ntfs-reclaim --partition-offset 8064 -m ddrescue.map disk.img output-directory

The `ddrescue.map` file is optional, but helps when you want to know which
files are corrupted.

Partition offset is a 512b sector number at which the NTFS partition starts. You
can use e.g.  the following command to get the list of partitions and their
start sectors:

    fdisk - l ddrescue.img
    ...
    Device     Boot Start      End  Sectors  Size Id Type
    bk1.img1   *     8064 60632063 60624000 28.9G  7 HPFS/NTFS/exFAT

Use the number in the `Start` column as the partition offset. If you are using a disk/flash without partitions, or you have imaged a single partition, specify
`0`.

Some useful options:
 - `-h`: To get help
 - `--parse-indices`: Parse NTFS Indices to recover extra directory names.
    Might produce some dummy/old/extra directories.
 - `--reuse-sigs`: Speedup the scan if re-running the reclaim process with different arguments.

### Output

The files will be recovered into `output-directory/files`. There will be a
`root` folder for the file-system root directory (`/`) and `unknown-xxxx`
directories when `ntfs-rescue` cannot figure where to place the files/or
directories.

There will also be a report (`corrupted-report.txt`) in the output directory
about files that can not be recovered or their content is corrupted. But be
aware that the file-system might be so corrupted that some files will not be in
this report. You have to provide a ddrescue map file (`-m` option) to get
reports about corrupted sectors in a file. And also keep in mind that even if
ddrescue claims that the sector was readable, the data might still be corrupted.

To sum it up: the report shows files that are known to be corrupted. But the
fact that the file is there is no guarantee that it is OK.

## Getting ntfs-reclaim

Either compile from source using Rust's `cargo` or download a a version for
Linux / Windows from the GitHub release page.

## Missing Stuff

- Attributes
- Alternate streams
- File Dates
- Attribute Lists (internal feature used for files with large meta-data)

## Similar Software
 - Various commercial offerings
 - [Scrounge NTFS](https://github.com/lcorbasson/scrounge-ntfs):
      - Most similar, works well.
      - `ntfs-reclaim` might be able to recover more file-names 
         and be a bit more resilient.
 - [Salvage NTFS](https://sourceforge.net/projects/salvagentfs/): 
    outdated, hard to get working today.
 - `photorec` from [TestDisk](https://www.cgsecurity.org/wiki/TestDisk):
    - Uses different approach, can be combined with ntfs-reclaim

AFAIK, `ntfs-reclaim` is the only free software that can use ddrescue image
maps. It uses the map file to generate a report of corrupted files.

## Analysis Algorithm (Technical Details)

1. Parse the boot record, if not possible (corruption), use the values provided
   on command-line.
2. Perform a full scan of the image looking for File Records and Index
   signatures.
3. Figure out the directory structure from the parsed File Records and Indices.
   Prefer the File Records as a more reliable source for file-names.
4. Dump all files using the given directory structure.

### MFT IDs

The File Records use their index in the MFT (Master File Table) to refer to each
other.  We reconstruct the MFT ID based on the position of the record relative
to `--mft-first-cluster` (if it is available).

On NTFS 3.1+ , the MFT ID is also written in the record. If both sources are
available, the record is didscared if they do not match.
