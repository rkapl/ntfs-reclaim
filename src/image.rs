use std::{cell::RefCell, fs::File};
use std::io::{Seek, Read, SeekFrom, Result, BufRead, BufReader};
use std::path::{Path};
use itertools::Itertools;
use crate::ntfs::{FromByteSlice};
use crate::error::ParsingErrorContext;

/// Somewhere to pull data from
pub struct Image {
    file: RefCell<File>,
    size: u64,
    /// Sorted list of non-overlapping areas of bad bytes (usually aligned to sector boundaries).
    /// The format is (start byte, end byte inclusive).
    bad_areas: Vec<(u64, u64)>,
}

#[derive(Debug)]
pub struct OutOfRangeError();

/// A slice of data pulled from the image
///
/// Currrently it is always a fresh instance, but might point into some cache in the future.
pub struct ImageData {
    buf: Vec<u8>,
    bad_areas: Vec<(u64, u64)>,
    offset: u64,
}

#[derive(Copy, Clone)]
/// Reference to slice of the `[ImageData]`
pub struct ImageDataSlice<'a> {
    /// absolute offset
    offset: u64,
    slice: &'a [u8],
    bad_areas: &'a Vec<(u64, u64)>,
}

/// Exclusive reference to slice of the `[ImageData]`
pub struct ImageDataMutSlice<'a> {
    /// absolute offset
    offset: u64,
    slice: &'a mut [u8],
    bad_areas: &'a Vec<(u64, u64)>,
}

// tranform a binary search result to get the nearest strictly smaller element
fn binsearch_before(v: std::result::Result<usize, usize>) -> isize {
    match v {
        Ok(v) => (v as isize) - 1,
        Err(v) => (v as isize) - 1,
    }
}

// tranform a binary search result to get the nearest larger smaller element
fn binsearch_after(v: std::result::Result<usize, usize>) -> isize {
    match v {
        Ok(v) => (v as isize) + 1,
        Err(v) => (v as isize),
    }
}

/// Finds if any areas that overlap with the given area.
/// If found, return (first intersecting, last intersecting).
fn overlapping_areas<T: Ord + Copy>(area: (T, T), list: &[(T, T)]) -> Option<(usize, usize)> {
    let (start, end) =  area;
    // index of the last area that precedes the query
    let first = binsearch_before(list.binary_search_by_key(&start, |(_a, b)| *b));
    // index of the first area that follow the query
    let last = binsearch_after(list.binary_search_by_key(&end, |(a, _b)| *a));

    // is there at least one are in the middle?
    if last - first > 1 {
        Some(((first + 1) as usize, (last - 1) as usize))
    } else {
        None
    }
}

impl Image {
    pub fn new(image: &Path, ddrescue_map: Option<&Path>) -> Result<Self> {
        let file =  File::open(image)?;
        let size = file.metadata().unwrap().len();
        let mut bad_areas: Vec<(u64, u64)> = Vec::new();

        if let Some (map) = ddrescue_map {
            let map_reader = BufReader::new(File::open(map)?);
            let mut it = map_reader.lines().filter(|l| l.as_ref().map_or(true, |l| {
                !(l.starts_with('#') || l.trim().is_empty())
            }));
            it.next().expect("Status line at the beginning of the map")?;
            for l in it {
                let l = l?;
                let (start, size, area_type) = l.split_ascii_whitespace().collect_tuple().expect("Three values on a map line");
                let start = u64::from_str_radix(start.trim_start_matches("0x"), 16).expect("Start should be hex integer");
                let size = u64::from_str_radix(size.trim_start_matches("0x"), 16).expect("Start should be hex integer");
                if area_type == "*" || area_type == "/" || area_type == "-" {
                    bad_areas.push((start, start + size - 1));
                }
            }
            bad_areas.sort_by_key(|(a, _)| *a);
        }

        Ok(Self {
            file: RefCell::new(file), size, bad_areas,
        })
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn read(&self, offset: u64, size: usize) -> Result<ImageData> {
        let last = offset + (size as u64) - 1;
        assert!(last < self.size);
        let mut bad_areas = Vec::new();
        if let Some((first_bad, last_bad)) = overlapping_areas((offset, last), &self.bad_areas) {
            bad_areas.extend_from_slice(&self.bad_areas[first_bad..(last_bad + 1)])
        }
        
        self.file.borrow_mut().seek(SeekFrom::Start(offset))?;
        let mut buf = Vec::new();
        buf.resize(size, 0);
        self.file.borrow_mut().read_exact(&mut buf)?;
        Ok(ImageData { 
            offset, buf, bad_areas,
        })
    }
}

impl ImageData {
    pub fn whole(&self) -> ImageDataSlice {
        ImageDataSlice {
            slice: self.buf.as_slice(),
            offset: self.offset,
            bad_areas: &self.bad_areas,
        }
    }
    pub fn whole_mut(&mut self) -> ImageDataMutSlice {
        ImageDataMutSlice {
            slice: self.buf.as_mut_slice(),
            offset: self.offset,
            bad_areas: &self.bad_areas,
        }
    }
}

/// Reference to part of ImageData, with accompanying meta-data (e.g. offset)
impl<'a> ImageDataSlice<'a> {
    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn is_bad(&self) -> bool {
        overlapping_areas((self.offset, self.offset + self.slice.len() as u64 - 1), self.bad_areas).is_some()
    }

    pub fn bad_bytes(&self) -> u64 {
        let mut acc = 0u64;
        if self.slice.len() == 0 {
            return 0;
        }
        let start = self.offset;
        let end = self.offset + (self.slice.len() as u64) - 1;
        for (a_start, a_end) in self.bad_areas {
            let o_start = start.max(*a_start);
            let o_end = end.min(*a_end);
            if o_end >= o_start {
                acc += o_end - o_start + 1;
            }
        }
        acc
    }

    pub fn sub(self, offset: usize, len: usize) -> std::result::Result<ImageDataSlice<'a>, OutOfRangeError> {
        if offset + len > self.slice.len() {
            Err(OutOfRangeError())
        } else {
            Ok(ImageDataSlice {
                offset: self.offset + offset as u64,
                slice: &self.slice[offset..(offset+len)],
                bad_areas: self.bad_areas,
            })
                
        }
    }

    pub fn tail(self, offset: usize) -> std::result::Result<ImageDataSlice<'a>, OutOfRangeError> {
        if offset > self.slice.len() {
            Err(OutOfRangeError())
        } else {
            Ok(ImageDataSlice {
                offset: self.offset + offset as u64,
                slice: &self.slice[offset..],
                bad_areas: self.bad_areas,
            })
                
        }
    }

    pub fn into_slice(self) -> &'a [u8] {
        self.slice
    }

    pub fn parse<T: FromByteSlice>(self) -> std::result::Result<&'a T, OutOfRangeError> {
        let len = std::mem::size_of::<T>();
        Ok(T::from_bytes(self.sub(0, len)?.into_slice()))
    }

    pub fn parse_at<T: FromByteSlice>(self, offset: usize) -> std::result::Result<&'a T, OutOfRangeError> {
        let len = std::mem::size_of::<T>();
        Ok(T::from_bytes(self.sub(offset, len)?.slice))
    }

    pub fn err_ctx<M: Into<String>>(&self, desc: M) -> ParsingErrorContext {
        ParsingErrorContext {
            area_offset: self.offset,
            size: self.slice.len(),
            desc: desc.into(),
        }
    }
}

/// Mutable reference to part of ImageData, with accompanying meta-data (e.g. offset)
impl<'a> std::ops::Deref for ImageDataSlice<'a> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.slice
    }
}

impl<'a> ImageDataMutSlice<'a> {
    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn borrow(&mut self) -> ImageDataMutSlice {
        ImageDataMutSlice {
            slice: self.slice,
            bad_areas: self.bad_areas,
            offset: self.offset,
        }
    }

    pub fn as_const(self) -> ImageDataSlice<'a> {
        ImageDataSlice {
            bad_areas: self.bad_areas,
            offset: self.offset,
            slice: self.slice,
        }
    }

    pub fn sub(self, offset: usize, len: usize) -> std::result::Result<ImageDataMutSlice<'a>, OutOfRangeError> {
        if offset + len > self.slice.len() {
            Err(OutOfRangeError())
        } else {
            Ok(ImageDataMutSlice {
                offset: self.offset + offset as u64,
                slice: &mut self.slice[offset..(offset+len)],
                bad_areas: self.bad_areas,
            })
                
        }
    }

    pub fn tail(self, offset: usize) -> std::result::Result<ImageDataMutSlice<'a>, OutOfRangeError> {
        if offset > self.slice.len() {
            Err(OutOfRangeError())
        } else {
            Ok(ImageDataMutSlice {
                offset: self.offset + offset as u64,
                slice: &mut self.slice[offset..],
                bad_areas: self.bad_areas,
            })
                
        }
    }

    pub fn chunks(self, size: usize) -> impl Iterator<Item=ImageDataMutSlice<'a>> + 'a {
        let ImageDataMutSlice {bad_areas, slice, offset} = self;
        slice.chunks_mut(size).enumerate().map(move |(i, chunk)| {
            ImageDataMutSlice {
                bad_areas: bad_areas,
                offset: offset + (i * size) as u64,
                slice: chunk,
            }
        })
    }

    pub fn split(self, mid: usize) -> std::result::Result<(Self, Self), OutOfRangeError> {
        if mid > self.slice.len() {
            return Err(OutOfRangeError());
        }
        let (head, tail) = self.slice.split_at_mut(mid);
        Ok((
            ImageDataMutSlice {
                slice: head,
                bad_areas: self.bad_areas,
                offset: self.offset,
            },
            ImageDataMutSlice {
                slice: tail,
                bad_areas: self.bad_areas,
                offset: self.offset,
            }
        ))
    }

    pub fn as_slice(&mut self) -> &mut [u8] {
        self.slice
    }

    pub fn into_slice(self) -> &'a mut [u8] {
        self.slice
    }
}

impl<'a> std::ops::Deref for ImageDataMutSlice<'a> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.slice
    }
}

impl<'a> std::ops::DerefMut for ImageDataMutSlice<'a> {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.slice
    }
}

#[cfg(test)]
mod tests {
    use super::{overlapping_areas};

    #[test]
    fn test_overlapping_areas() {
        let areas: &[(u64, u64)] = &[
            (2,2),
            (5,9),
        ];
        assert_eq!(overlapping_areas((0, 1), &areas), None);
        assert_eq!(overlapping_areas((0, 2), &areas), Some((0, 0)));
        assert_eq!(overlapping_areas((0, 3), &areas), Some((0, 0)));
        assert_eq!(overlapping_areas((3, 4), &areas), None);
        assert_eq!(overlapping_areas((2, 6), &areas), Some((0, 1)));
        assert_eq!(overlapping_areas((2, 10), &areas), Some((0, 1)));
    }
}