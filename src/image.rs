use std::{cell::RefCell, fs::File};
use std::io::{Seek, Read, SeekFrom, Result};
use std::path::Path;
use std::ops::Range;
use crate::ntfs::FromByteSlice;
use crate::error::ParsingErrorContext;

/// Somewhere to pull data from
pub struct Image {
    file: RefCell<File>,
    size: u64,
}

#[derive(Debug)]
pub struct OutOfRangeError();

/// A slice of data pulled from the image
///
/// Currrently it is always a fresh instance, but might point into some cache in the future.
pub struct ImageData {
    buf: Vec<u8>,
    offset: u64,
}

#[derive(Copy, Clone)]
/// Reference to slice of the `[ImageData]`
pub struct ImageDataSlice<'a> {
    /// absolute offset
    offset: u64,
    slice: &'a [u8],
}

impl Image {
    pub fn new(image: &Path, _ddrescue_map: Option<&Path>) -> Result<Self> {
        let file =  File::open(image)?;
        let size = file.metadata().unwrap().len();
        Ok(Self {
            file: RefCell::new(file), size,
        })
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn read(&self, offset: u64, size: usize) -> Result<ImageData> {
        self.file.borrow_mut().seek(SeekFrom::Start(offset))?;
        let mut buf = Vec::new();
        buf.resize(size, 0);
        self.file.borrow_mut().read_exact(&mut buf)?;
        Ok(ImageData { 
            offset, buf,
        })
    }
}

impl ImageData {
    pub fn range(&self) -> Range<u64> {
        self.offset .. (self.offset + self.buf.len() as u64)
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn whole(&self) -> ImageDataSlice {
        ImageDataSlice {
            slice: self.buf.as_slice(),
            offset: self.offset,
        }
    }
}

impl<'a> ImageDataSlice<'a> {
    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn sub(self, offset: usize, len: usize) -> std::result::Result<ImageDataSlice<'a>, OutOfRangeError> {
        if offset + len > self.slice.len() {
            Err(OutOfRangeError())
        } else {
            Ok(ImageDataSlice {
                offset: self.offset + offset as u64,
                slice: &self.slice[offset..(offset+len)],
            })
                
        }
    }

    pub fn tail(&self, offset: usize) -> std::result::Result<ImageDataSlice<'a>, OutOfRangeError> {
        if offset > self.slice.len() {
            Err(OutOfRangeError())
        } else {
            Ok(ImageDataSlice {
                offset: self.offset + offset as u64,
                slice: &self.slice[offset..],
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

impl<'a> std::ops::Deref for ImageDataSlice<'a> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.slice
    }
}