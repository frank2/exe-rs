//! [exe-rs](https://github.com/frank2/exe-rs) is a library for handling PE files, whether it be building them or analyzing them!
//!
//! Getting started is easy:
//! ```rust
//! use exe::PE;
//! use exe::types::{ImportDirectory, CCharString};
//!
//! let pefile = PE::from_file("test/compiled.exe").unwrap();
//! let import_directory = ImportDirectory::parse(&pefile).unwrap();
//!
//! for import in import_directory.descriptors {
//!    println!("Module: {}", import.get_name(&pefile).unwrap().as_str());
//!    println!("Imports: {:?}", import.get_imports(&pefile).unwrap());
//! }
//! ```
//!
//! Standard PE headers and other types can be found in the [types](types/) module. The
//! [buffer](buffer/) module contains low-level functionality for handling a PE buffer.
//! Further usage examples can be found in the [test file](https://github.com/frank2/exe-rs/blob/main/src/tests.rs).

extern crate chrono;

pub mod buffer;
pub mod headers;
pub mod types;

#[cfg(test)]
mod tests;

use std::convert::AsRef;
use std::io::{Error as IoError};
use std::mem;
use std::path::Path;
use std::slice;

use crate::buffer::Buffer;
use crate::headers::*;
use crate::types::*;

/// Errors produced by the library.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Error {
    /// The PE buffer was too small to complete the operation.
    BufferTooSmall,
    /// The PE file has an invalid DOS signature.
    InvalidDOSSignature,
    /// The header is not aligned correctly.
    BadAlignment,
    /// The PE file has an invalid PE signature.
    InvalidPESignature,
    /// The PE file has an invalid NT signature.
    InvalidNTSignature,
    /// The offset provided or generated resulted in an invalid offset value.
    InvalidOffset,
    /// The RVA provided or generated resulted in an invalid RVA value.
    InvalidRVA,
    /// The VA provided or generated resulted in an invalid VA value.
    InvalidVA,
    /// The PE section was not found given the search criteria (e.g., an RVA value)
    SectionNotFound,
    /// The pointer provided or generated did not fit in the range of the buffer.
    BadPointer,
    /// The data directory requested is currently unsupported.
    UnsupportedDirectory,
    /// The relocation entry is invalid.
    InvalidRelocation,
    /// The provided directory is not available.
    BadDirectory,
    /// The data directory is corrupt and cannot be parsed.
    CorruptDataDirectory,
}

/// An enum to tag the PE file with what its memory map looks like.
///
/// When a PE is loaded, it's ultimately parsed and rewritten before being placed into memory. This
/// means the image in memory is different from the disk. This is why, for example,
/// RVAs and Offsets differ in type-- the RVA represents the offset to the image in
/// *memory*, whereas the Offset represents the offset to the image on *disk*. This enum
/// is necessary to maintain a simple translation layer for basic address operations.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum PEType {
    Disk,
    Memory,
}

/// An enum to translate between RVA and Offset addresses.
///
/// This typically never gets exposed beyond the [`translate`](PE::translate) function. See [`PEType`](PEType)
/// for an explanation of why this is here.
pub enum PETranslation {
    Disk(Offset),
    Memory(RVA),
}
impl Address for PETranslation {
    fn as_offset(&self, pe: &PE) -> Result<Offset, Error> {
        match self {
            Self::Disk(o) => Ok(*o),
            Self::Memory(r) => r.as_offset(pe),
        }
    }
    fn as_rva(&self, pe: &PE) -> Result<RVA, Error> {
        match self {
            Self::Disk(o) => o.as_rva(pe),
            Self::Memory(r) => Ok(*r),
        }
    }
    fn as_va(&self, pe: &PE) -> Result<VA, Error> {
        match self {
            Self::Disk(o) => o.as_va(pe),
            Self::Memory(r) => r.as_va(pe),
        }
    }
}

/// Represents a PE file.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct PE {
    /// The type of buffer the PE file is expecting. See [PEType](PEType) for an explanation.
    pub pe_type: PEType,
    /// The buffer that holds the data. Various operations such as getting
    /// references to objects in the data can be found in the buffer object.
    pub buffer: Buffer,
    /// The optional filename of the PE file.
    pub filename: Option<String>,
}
impl PE {
    /// Generates a new, blank PE file. Typically only useful for constructing
    /// new PE files.
    pub fn new(size: Option<usize>, pe_type: PEType) -> Self {
        Self {
            pe_type: pe_type,
            buffer: Buffer::new(size),
            filename: None,
        }
    }
    /// Generates a new PE object from a slice of data, marking it as a memory-resident image.
    pub fn from_data(data: &[u8], pe_type: PEType) -> Self {
        Self {
            pe_type: pe_type,
            buffer: Buffer::from_data(data),
            filename: None,
        }
    }
    /// Generates a new PE object from a file on disk.
    pub fn from_file<P: AsRef<Path>>(filename: P) -> Result<Self, IoError> {
        match Buffer::from_file(&filename) {
            Ok(buffer) => Ok(
                Self {
                    pe_type: PEType::Disk,
                    buffer: buffer,
                    filename: Some(String::from(filename.as_ref().to_str().unwrap()))
                }
            ),
            Err(e) => Err(e),
        }
    }
    /// Generates a new PE object from a file on disk, marking it as a memory dump (i.e., sets ```pe_type``` to [`PEType::Memory`](PEType::Memory)).
    pub fn from_memory_dump<P: AsRef<Path>>(filename: P) -> Result<Self, IoError> {
        match Buffer::from_file(&filename) {
            Ok(buffer) => Ok(
                Self {
                    pe_type: PEType::Memory,
                    buffer: buffer,
                    filename: Some(String::from(filename.as_ref().to_str().unwrap()))
                }
            ),
            Err(e) => Err(e),
        }
    }
    /// Generates a new PE file from a pointer to memory.
    ///
    /// This pointer is assumed to be pointed at a memory-mapped image (i.e., is [`PEType::Memory`](PEType::Memory)). Because of the nature
    /// of verifying the given pointer is a PE image, this function also parses the image and verifies it's a PE image. And despite using
    /// a pointer, this function copies the image from memory, and does not maintain its pointed status.
    pub unsafe fn from_ptr(ptr: *const u8) -> Result<PE, Error> {
        let dos_header = &*(ptr as *const ImageDOSHeader);

        if dos_header.e_magic != DOS_SIGNATURE {
            return Err(Error::InvalidDOSSignature);
        }

        let nt_header = &*(ptr.add(dos_header.e_lfanew.0 as usize) as *const ImageNTHeaders32);

        if nt_header.signature != NT_SIGNATURE {
            return Err(Error::InvalidPESignature);
        }

        let mut image_size = 0usize;

        if nt_header.optional_header.magic == HDR32_MAGIC {
            image_size = nt_header.optional_header.size_of_image as usize;
        }
        else if nt_header.optional_header.magic == HDR64_MAGIC {
            let nt_header_64 = &*(ptr.add(dos_header.e_lfanew.0 as usize) as *const ImageNTHeaders64);
            image_size = nt_header_64.optional_header.size_of_image as usize;
        }
        else {
            return Err(Error::InvalidNTSignature);
        }

        let data = slice::from_raw_parts(ptr, image_size);

        Ok(PE {
            pe_type: PEType::Memory,
            buffer: Buffer::from_data(data),
            filename: None,
        })
    }

    /// Translate an address into a buffer offset relevant to the image type.
    ///
    /// This differs from [`rva_to_offset`](PE::rva_to_offset) because it does not directly rely on the section table.
    /// Rather, if the image is a memory image, it treats [`RVA`](RVA)s as offsets, because that's what they are in memory.
    /// Otherwise, it converts the [`RVA`](RVA) into an offset via the section table. The reverse goes for if
    /// the PE image is a disk image and an [Offset](Offset) is provided.
    pub fn translate(&self, addr: PETranslation) -> Result<Offset, Error> {
        match self.pe_type {
            PEType::Disk => match addr {
                PETranslation::Disk(o) => Ok(o),
                PETranslation::Memory(r) => r.as_offset(self),
            }
            PEType::Memory => match addr {
                PETranslation::Disk(o) => match o.as_rva(self) {
                    Ok(rva) => Ok(Offset(rva.0)),
                    Err(e) => Err(e),
                },
                PETranslation::Memory(r) => Ok(Offset(r.0)),
            }
        }
    }

    /// Get the DOS header without verifying its contents.
    pub fn get_dos_header(&self) -> Result<&ImageDOSHeader, Error> {
        self.buffer.get_ref::<ImageDOSHeader>(Offset(0))
    }
    /// Get a mutable DOS header without verifying its contents.
    pub fn get_mut_dos_header(&mut self) -> Result<&mut ImageDOSHeader, Error> {
        self.buffer.get_mut_ref::<ImageDOSHeader>(Offset(0))
    }
    /// Get the DOS header and verify it's a valid DOS header.
    pub fn get_valid_dos_header(&self) -> Result<&ImageDOSHeader, Error> {
        let dos_header = match self.get_dos_header() {
            Ok(h) => h,
            Err(e) => return Err(e),
        };

        if dos_header.e_magic != DOS_SIGNATURE {
            return Err(Error::InvalidDOSSignature);
        }

        Ok(dos_header)
    }
    /// Get a mutable DOS header and verify it's a valid DOS header.
    pub fn get_valid_mut_dos_header(&mut self) -> Result<&mut ImageDOSHeader, Error> {
        let dos_header = match self.get_mut_dos_header() {
            Ok(h) => h,
            Err(e) => return Err(e),
        };

        if dos_header.e_magic != DOS_SIGNATURE {
            return Err(Error::InvalidDOSSignature);
        }

        Ok(dos_header)
    }
    /// Get the offset to the PE headers.
    pub fn e_lfanew(&self) -> Result<Offset, Error> {
        match self.get_valid_dos_header() {
            Ok(h) => Ok(h.e_lfanew),
            Err(e) => Err(e)
        }
    }

    /// Get 32-bit NT headers without verifying its contents.
    pub fn get_nt_headers_32(&self) -> Result<&ImageNTHeaders32, Error> {
        let e_lfanew = match self.e_lfanew() {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        self.buffer.get_ref::<ImageNTHeaders32>(e_lfanew)
    }
    /// Get mutable 32-bit NT headers without verifying its contents.
    pub fn get_mut_nt_headers_32(&mut self) -> Result<&mut ImageNTHeaders32, Error> {
        let e_lfanew = match self.e_lfanew() {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        self.buffer.get_mut_ref::<ImageNTHeaders32>(e_lfanew)
    }
    /// Get 32-bit NT headers and verify that they're 32-bit NT headers.
    pub fn get_valid_nt_headers_32(&self) -> Result<&ImageNTHeaders32, Error> {
        let e_lfanew = match self.e_lfanew() {
            Ok(l) => l,
            Err(e) => return Err(e),
        };

        if e_lfanew.0 % 4 != 0 {
            return Err(Error::BadAlignment);
        }
        
        let nt_headers = match self.get_nt_headers_32() {
            Ok(h) => h,
            Err(e) => return Err(e),
        };

        if nt_headers.signature != NT_SIGNATURE {
            return Err(Error::InvalidPESignature);
        }

        if nt_headers.optional_header.magic != HDR32_MAGIC {
            return Err(Error::InvalidNTSignature);
        }

        Ok(nt_headers)
    }
    /// Get mutable 32-bit NT headers and verify that they're 32-bit NT headers.
    pub fn get_valid_mut_nt_headers_32(&mut self) -> Result<&mut ImageNTHeaders32, Error> {
        let e_lfanew = match self.e_lfanew() {
            Ok(l) => l,
            Err(e) => return Err(e),
        };

        if e_lfanew.0 % 4 != 0 {
            return Err(Error::BadAlignment);
        }

        let nt_headers = match self.get_mut_nt_headers_32() {
            Ok(h) => h,
            Err(e) => return Err(e),
        };

        if nt_headers.signature != NT_SIGNATURE {
            return Err(Error::InvalidPESignature);
        }

        if nt_headers.optional_header.magic != HDR32_MAGIC {
            return Err(Error::InvalidNTSignature);
        }

        Ok(nt_headers)
    }
    /// Get 64-bit NT headers without verifying its contents.
    pub fn get_nt_headers_64(&self) -> Result<&ImageNTHeaders64, Error> {
        let e_lfanew = match self.e_lfanew() {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        self.buffer.get_ref::<ImageNTHeaders64>(e_lfanew)
    }
    /// Get mutable 64-bit NT headers without verifying its contents.
    pub fn get_mut_nt_headers_64(&mut self) -> Result<&mut ImageNTHeaders64, Error> {
        let e_lfanew = match self.e_lfanew() {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        self.buffer.get_mut_ref::<ImageNTHeaders64>(e_lfanew)
    }
    /// Get 64-bit NT headers and verify that they're 64-bit NT headers.
    pub fn get_valid_nt_headers_64(&self) -> Result<&ImageNTHeaders64, Error> {
        let e_lfanew = match self.e_lfanew() {
            Ok(l) => l,
            Err(e) => return Err(e),
        };

        if e_lfanew.0 % 4 != 0 {
            return Err(Error::BadAlignment);
        }

        let nt_headers = match self.get_nt_headers_64() {
            Ok(h) => h,
            Err(e) => return Err(e),
        };

        if nt_headers.signature != NT_SIGNATURE {
            return Err(Error::InvalidPESignature);
        }

        if nt_headers.optional_header.magic != HDR64_MAGIC {
            return Err(Error::InvalidNTSignature);
        }
        
        Ok(nt_headers)
    }
    /// Get mutable 64-bit NT headers and verify that they're 64-bit NT headers.
    pub fn get_valid_mut_nt_headers_64(&mut self) -> Result<&mut ImageNTHeaders64, Error> {
        let e_lfanew = match self.e_lfanew() {
            Ok(l) => l,
            Err(e) => return Err(e),
        };

        if e_lfanew.0 % 4 != 0 {
            return Err(Error::BadAlignment);
        }

        let nt_headers = match self.get_mut_nt_headers_64() {
            Ok(h) => h,
            Err(e) => return Err(e),
        };

        if nt_headers.signature != NT_SIGNATURE {
            return Err(Error::InvalidPESignature);
        }

        if nt_headers.optional_header.magic != HDR64_MAGIC {
            return Err(Error::InvalidNTSignature);
        }

        Ok(nt_headers)
    }
    /// Get the NT signature from the optional header of the NT headers.
    pub fn get_nt_magic(&self) -> Result<u16, Error> {
        // the difference in size doesn't affect the magic header, so we
        // simply blindly cast it to a 32-bit header to get the value
        
        match self.get_nt_headers_32() {
            Ok(h) => Ok(h.optional_header.magic),
            Err(e) => Err(e),
        }
    }
    /// Get the architecture of this PE file.
    pub fn get_arch(&self) -> Result<Arch, Error> {
        match self.get_nt_magic() {
            Ok(m) => match m {
                HDR32_MAGIC => Ok(Arch::X86),
                HDR64_MAGIC => Ok(Arch::X64),
                _ => return Err(Error::InvalidNTSignature),
            },
            Err(e) => Err(e),
        }
    }
    /// Get the NT headers of this PE file, inferring from the content of the file which architecture it is and
    /// validating the headers.
    ///
    /// ```rust
    /// use exe::PE;
    /// use exe::headers::HDR64_MAGIC;
    /// use exe::types::NTHeaders;
    ///
    /// let pefile = PE::from_file("test/normal64.exe").unwrap();
    /// let headers = pefile.get_valid_nt_headers().unwrap();
    ///
    /// let magic = match headers {
    ///    NTHeaders::NTHeaders32(hdr32) => hdr32.optional_header.magic,
    ///    NTHeaders::NTHeaders64(hdr64) => hdr64.optional_header.magic,
    /// };
    ///
    /// assert_eq!(magic, HDR64_MAGIC);
    /// ```
    pub fn get_valid_nt_headers(&self) -> Result<NTHeaders, Error> {
        let magic = match self.get_nt_magic() {
            Ok(m) => m,
            Err(e) => return Err(e),
        };

        if magic == HDR32_MAGIC {
            match self.get_valid_nt_headers_32() {
                Ok(h) => Ok(NTHeaders::NTHeaders32(h)),
                Err(e) => Err(e)
            }
        }
        else if magic == HDR64_MAGIC {
            match self.get_valid_nt_headers_64() {
                Ok(h) => Ok(NTHeaders::NTHeaders64(h)),
                Err(e) => Err(e),
            }
        }
        else {
            Err(Error::InvalidNTSignature)
        }
    }
    /// Get mutable NT headers of this PE file, inferring from the content of the file which architecture it is and
    /// validating the headers.
    pub fn get_valid_mut_nt_headers(&mut self) -> Result<NTHeadersMut, Error> {
        let magic = match self.get_nt_magic() {
            Ok(m) => m,
            Err(e) => return Err(e),
        };

        if magic == HDR32_MAGIC {
            match self.get_valid_mut_nt_headers_32() {
                Ok(h) => Ok(NTHeadersMut::NTHeaders32(h)),
                Err(e) => Err(e)
            }
        }
        else if magic == HDR64_MAGIC {
            match self.get_valid_mut_nt_headers_64() {
                Ok(h) => Ok(NTHeadersMut::NTHeaders64(h)),
                Err(e) => Err(e),
            }
        }
        else {
            Err(Error::InvalidNTSignature)
        }
    }

    /// Get the entrypoint of this PE file.
    pub fn get_entrypoint(&self) -> Result<RVA, Error> {
        let nt_headers = match self.get_valid_nt_headers() {
            Ok(h) => h,
            Err(e) => return Err(e),
        };

        match nt_headers {
            NTHeaders::NTHeaders32(h32) => Ok(h32.optional_header.address_of_entry_point),
            NTHeaders::NTHeaders64(h64) => Ok(h64.optional_header.address_of_entry_point),
        }
    }

    /// Get the offset to the data directory within the PE file.
    pub fn get_data_directory_offset(&self) -> Result<Offset, Error> {
        let e_lfanew = match self.e_lfanew() {
            Ok(o) => o,
            Err(e) => return Err(e),
        };
        
        let nt_header = match self.get_valid_nt_headers() {
            Ok(h) => h,
            Err(e) => return Err(e),
        };

        let header_size = match nt_header {
            NTHeaders::NTHeaders32(_) => mem::size_of::<ImageNTHeaders32>(),
            NTHeaders::NTHeaders64(_) => mem::size_of::<ImageNTHeaders64>(),
        };

        let offset = Offset(e_lfanew.0 + (header_size as u32));

        if !self.validate_offset(offset) {
            return Err(Error::BufferTooSmall);
        }

        Ok(offset)
    }
    /// Get the size of the data directory. Rounds down ```number_of_rva_and_sizes``` to 16, which is what
    /// the Windows loader does.
    pub fn get_data_directory_size(&self) -> Result<usize, Error> {
        let nt_header = match self.get_valid_nt_headers() {
            Ok(h) => h,
            Err(e) => return Err(e),
        };

        let sizes = match nt_header {
            NTHeaders::NTHeaders32(h32) => h32.optional_header.number_of_rva_and_sizes,
            NTHeaders::NTHeaders64(h64) => h64.optional_header.number_of_rva_and_sizes,
        };

        // data directory gets rounded down if greater than 16
        if sizes > 16 {
            Ok(16 as usize)
        }
        else {
            Ok(sizes as usize)
        }
    }
    /// Get the data directory table.
    ///
    /// Normally one would expect this to be a part of [ImageOptionalHeader](ImageOptionalHeader32), but
    /// [ImageOptionalHeader::number_of_rva_and_sizes](ImageOptionalHeader32::number_of_rva_and_sizes) controls
    /// the size of the array. Therefore, we can't stick it in the optional header, because that would
    /// produce a variable-sized structure, which Rust doesn't support.
    pub fn get_data_directory_table(&self) -> Result<&[ImageDataDirectory], Error> {
        let offset = match self.get_data_directory_offset() {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        let size = match self.get_data_directory_size() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        self.buffer.get_slice_ref::<ImageDataDirectory>(offset, size)
    }
    /// Get a mutable data directory table.
    pub fn get_mut_data_directory_table(&mut self) -> Result<&mut [ImageDataDirectory], Error> {
        let offset = match self.get_data_directory_offset() {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        let size = match self.get_data_directory_size() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        self.buffer.get_mut_slice_ref::<ImageDataDirectory>(offset, size)
    }

    /// Get the offset to the section table within the PE file.
    pub fn get_section_table_offset(&self) -> Result<Offset, Error> {
        let e_lfanew = match self.e_lfanew() {
            Ok(o) => o,
            Err(e) => return Err(e),
        };
        
        let nt_header = match self.get_valid_nt_headers() {
            Ok(h) => h,
            Err(e) => return Err(e),
        };

        let size_of_optional = match nt_header {
            NTHeaders::NTHeaders32(h) => h.file_header.size_of_optional_header,
            NTHeaders::NTHeaders64(h) => h.file_header.size_of_optional_header,
        };

        let Offset(mut offset) = e_lfanew;

        offset += mem::size_of::<u32>() as u32;
        offset += mem::size_of::<ImageFileHeader>() as u32;
        offset += size_of_optional as u32;

        if !self.validate_offset(Offset(offset)) {
            return Err(Error::BufferTooSmall);
        }

        Ok(Offset(offset))
    }
    /// Get the section table of the PE file.
    pub fn get_section_table(&self) -> Result<&[ImageSectionHeader], Error> {
        let offset = match self.get_section_table_offset() {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        let nt_headers = match self.get_valid_nt_headers() {
            Ok(h) => h,
            Err(e) => return Err(e),
        };

        let sections = match nt_headers {
            NTHeaders::NTHeaders32(h) => h.file_header.number_of_sections,
            NTHeaders::NTHeaders64(h) => h.file_header.number_of_sections,
        };

        self.buffer.get_slice_ref::<ImageSectionHeader>(offset, sections as usize)
    }
    /// Get a mutable section table from the PE file.
    pub fn get_mut_section_table(&mut self) -> Result<&mut [ImageSectionHeader], Error> {
        let offset = match self.get_section_table_offset() {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        let nt_headers = match self.get_valid_nt_headers() {
            Ok(h) => h,
            Err(e) => return Err(e),
        };

        let sections = match nt_headers {
            NTHeaders::NTHeaders32(h) => h.file_header.number_of_sections,
            NTHeaders::NTHeaders64(h) => h.file_header.number_of_sections,
        };

        self.buffer.get_mut_slice_ref::<ImageSectionHeader>(offset, sections as usize)
    }

    /// Get a reference to a section in the PE file by a given offset. Yields a
    /// [Error::SectionNotFound](Error::SectionNotFound) error if the offset wasn't found to be in a section.
    pub fn get_section_by_offset(&self, offset: Offset) -> Result<&ImageSectionHeader, Error> {
        let section_table = match self.get_section_table() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        for section in section_table {
            if section.has_offset(offset) {
                return Ok(section);
            }
        }

        Err(Error::SectionNotFound)
    }

    /// Get a mutable reference to a section in the PE file by a given offset. Yields a
    /// [Error::SectionNotFound](Error::SectionNotFound) error if the offset wasn't found to be in a section.
    pub fn get_mut_section_by_offset(&mut self, offset: Offset) -> Result<&mut ImageSectionHeader, Error> {
        let section_table = match self.get_mut_section_table() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        for section in section_table {
            if section.has_offset(offset) {
                return Ok(section);
            }
        }

        Err(Error::SectionNotFound)
    }

    /// Get a reference to a section in the PE file by a given RVA. Yields a
    /// [Error::SectionNotFound](Error::SectionNotFound) error if the RVA wasn't found to be in a section.
    pub fn get_section_by_rva(&self, rva: RVA) -> Result<&ImageSectionHeader, Error> {
        let section_table = match self.get_section_table() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        for section in section_table {
            if section.has_rva(rva) {
                return Ok(section);
            }
        }

        Err(Error::SectionNotFound)
    }

    /// Get a mutable reference to a section in the PE file by a given RVA. Yields a
    /// [Error::SectionNotFound](Error::SectionNotFound) error if the RVA wasn't found to be in a section.
    pub fn get_mut_section_by_rva(&mut self, rva: RVA) -> Result<&mut ImageSectionHeader, Error> {
        let section_table = match self.get_mut_section_table() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        for section in section_table {
            if section.has_rva(rva) {
                return Ok(section);
            }
        }

        Err(Error::SectionNotFound)
    }

    /// Get a reference to a section in the PE file by its name. Yields a
    /// [Error::SectionNotFound](Error::SectionNotFound) error if the name wasn't found in the section table.
    pub fn get_section_by_name(&self, name: String) -> Result<&ImageSectionHeader, Error> {
        let sections = match self.get_section_table() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let s = name.as_str();

        for section in sections {
            if section.name.as_str() == s {
                return Ok(section);
            }
        }

        Err(Error::SectionNotFound)
    }

    /// Get a mutable reference to a section in the PE file by its name. Yields a
    /// [Error::SectionNotFound](Error::SectionNotFound) error if the name wasn't found in the section table.
    pub fn get_mut_section_by_name(&mut self, name: String) -> Result<&mut ImageSectionHeader, Error> {
        let sections = match self.get_mut_section_table() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let s = name.as_str();
        
        for section in sections {
            if section.name.as_str() == s {
                return Ok(section);
            }
        }

        Err(Error::SectionNotFound)
    }

    /// Verify that the given offset is a valid offset.
    ///
    /// An offset is validated if it is less than the length of the buffer.
    pub fn validate_offset(&self, offset: Offset) -> bool {
        (offset.0 as usize) < self.buffer.len()
    }
    /// Verify that the given RVA is a valid RVA.
    ///
    /// An RVA is validated if it is less than the size of the image.
    pub fn validate_rva(&self, rva: RVA) -> bool {
        let headers = match self.get_valid_nt_headers() {
            Ok(h) => h,
            Err(_) => return false,
        };
        let image_size = match headers {
            NTHeaders::NTHeaders32(h32) => h32.optional_header.size_of_image as usize,
            NTHeaders::NTHeaders64(h64) => h64.optional_header.size_of_image as usize,
        };

        (rva.0 as usize) < image_size
    }
    /// Verify that the given VA is a valid VA for this image.
    ///
    /// A VA is validated if it lands between the image base and the end of the image, determined by its size.
    /// In other words: ```image_base <= VA < (image_base+image_size)```
    pub fn validate_va(&self, va: VA) -> bool {
        let headers = match self.get_valid_nt_headers() {
            Ok(h) => h,
            Err(_) => return false,
        };
        let (image_size, image_base) = match headers {
            NTHeaders::NTHeaders32(h32) => (h32.optional_header.size_of_image as usize,
                                            h32.optional_header.image_base as usize),
            NTHeaders::NTHeaders64(h64) => (h64.optional_header.size_of_image as usize,
                                            h64.optional_header.image_base as usize)
        };

        let start = image_base;
        let end = start + image_size;

        match va {
            VA::VA32(v32) => start <= (v32.0 as usize) && (v32.0 as usize) < end,
            VA::VA64(v64) => start <= (v64.0 as usize) && (v64.0 as usize) < end,
        }
    }

    /// Check if a given [`Offset`](Offset) is aligned to the [`file_alignment`](ImageOptionalHeader32::file_alignment) attribute of the
    /// [optional header](ImageOptionalHeader32).
    pub fn is_aligned_to_file(&self, offset: Offset) -> bool {
        let alignment = match self.get_valid_nt_headers() {
            Ok(h) => match h {
                NTHeaders::NTHeaders32(h32) => h32.optional_header.file_alignment,
                NTHeaders::NTHeaders64(h64) => h64.optional_header.file_alignment,
            },
            Err(e) => return false,
        };

        offset.0 % alignment == 0
    }
    /// Check if a given [`RVA`](RVA) is aligned to the [`section_alignment`](ImageOptionalHeader32::section_alignment) attribute of the
    /// [optional header](ImageOptionalHeader32).
    pub fn is_aligned_to_section(&self, rva: RVA) -> bool {
        let alignment = match self.get_valid_nt_headers() {
            Ok(h) => match h {
                NTHeaders::NTHeaders32(h32) => h32.optional_header.file_alignment,
                NTHeaders::NTHeaders64(h64) => h64.optional_header.file_alignment,
            },
            Err(e) => return false,
        };

        rva.0 % alignment == 0
    }
    /// Aligns a given [`Offset`](Offset) to the [`file_alignment`](ImageOptionalHeader32::file_alignment) attribute of the
    /// [optional header](ImageOptionalHeader32).
    pub fn align_to_file(&self, offset: Offset) -> Result<Offset, Error> {
        let alignment = match self.get_valid_nt_headers() {
            Ok(h) => match h {
                NTHeaders::NTHeaders32(h32) => h32.optional_header.file_alignment,
                NTHeaders::NTHeaders64(h64) => h64.optional_header.file_alignment,
            },
            Err(e) => return Err(e),
        };

        let current = offset.0 % alignment;

        if current == 0 {
            if !self.validate_offset(offset) {
                return Err(Error::InvalidOffset);
            }
            
            return Ok(offset);
        }

        let new_offset = Offset(offset.0 + (alignment - current));

        if !self.validate_offset(new_offset) {
            return Err(Error::InvalidOffset);
        }

        Ok(new_offset)
    }
    /// Aligns a given [`RVA`](RVA) to the [`section_alignment`](ImageOptionalHeader32::section_alignment) attribute of the
    /// [optional header](ImageOptionalHeader32).
    pub fn align_to_section(&self, rva: RVA) -> Result<RVA, Error> {
        let alignment = match self.get_valid_nt_headers() {
            Ok(h) => match h {
                NTHeaders::NTHeaders32(h32) => h32.optional_header.section_alignment,
                NTHeaders::NTHeaders64(h64) => h64.optional_header.section_alignment,
            },
            Err(e) => return Err(e),
        };

        println!("alignment is {}", alignment);

        let current = rva.0 % alignment;

        if current == 0 {
            if !self.validate_rva(rva) {
                return Err(Error::InvalidRVA);
            }
            
            return Ok(rva);
        }

        println!("current is {}", current);

        let new_rva = RVA(rva.0 + (alignment - current));

        println!("new RVA is {:?}", new_rva);

        if !self.validate_rva(new_rva) {
            return Err(Error::InvalidRVA);
        }

        Ok(new_rva)
    }

    /// Convert an offset to an RVA address. Produces [Error::InvalidRVA](Error::InvalidRVA) if the produced
    /// RVA is invalid or if the section it was transposed from no longer contains it.
    pub fn offset_to_rva(&self, offset: Offset) -> Result<RVA, Error> {
        let section = match self.get_section_by_offset(offset) {
            Ok(s) => s,
            Err(e) => {
                if e != Error::SectionNotFound {
                    return Err(e);
                }

                if !self.validate_rva(RVA(offset.0)) {
                    return Err(Error::InvalidRVA);
                }

                return Ok(RVA(offset.0));
            }
        };

        let mut rva = offset.0;
        rva -= section.pointer_to_raw_data.0;
        rva += section.virtual_address.0;

        let final_rva = RVA(rva);

        if !self.validate_rva(final_rva) || !section.has_rva(final_rva) {
            return Err(Error::InvalidRVA);
        }

        Ok(RVA(rva))
    }
    /// Convert an offset to a VA address.
    pub fn offset_to_va(&self, offset: Offset) -> Result<VA, Error> {
        let rva = match self.offset_to_rva(offset) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        self.rva_to_va(rva)
    }

    /// Convert an RVA to an offset address. Produces a [Error::InvalidOffset](Error::InvalidOffset) error if
    /// the produced offset is invalid or if the section it was transposed from no longer contains it.
    pub fn rva_to_offset(&self, rva: RVA) -> Result<Offset, Error> {
        let section = match self.get_section_by_rva(rva) {
            Ok(s) => s,
            Err(e) => {
                if e != Error::SectionNotFound {
                    return Err(e);
                }

                if !self.validate_offset(Offset(rva.0)) {
                    return Err(Error::InvalidOffset);
                }

                return Ok(Offset(rva.0));
            }
        };

        let mut offset = rva.0;
        offset -= section.virtual_address.0;
        offset += section.pointer_to_raw_data.0;

        let final_offset = Offset(offset);

        if !self.validate_offset(final_offset) || !section.has_offset(final_offset) {
            return Err(Error::InvalidOffset);
        }

        Ok(Offset(offset))
    }
    /// Convert an RVA to a VA address. Produces a [Error::InvalidVA](Error::InvalidVA) error if the produced
    /// VA is invalid.
    pub fn rva_to_va(&self, rva: RVA) -> Result<VA, Error> {
        let headers = match self.get_valid_nt_headers() {
            Ok(h) => h,
            Err(e) => return Err(e),
        };

        let va = match headers {
            NTHeaders::NTHeaders32(h32) => VA::VA32(VA32(rva.0 + h32.optional_header.image_base)),
            NTHeaders::NTHeaders64(h64) => VA::VA64(VA64((rva.0 as u64) + h64.optional_header.image_base)),
        };

        if !self.validate_va(va) {
            return Err(Error::InvalidVA);
        }

        Ok(va)
    }

    /// Convert a VA to an RVA. Produces a [Error::InvalidRVA](Error::InvalidRVA) error if the produced RVA
    /// is invalid.
    pub fn va_to_rva(&self, va: VA) -> Result<RVA, Error> {
        let headers = match self.get_valid_nt_headers() {
            Ok(h) => h,
            Err(e) => return Err(e),
        };
        let image_base = match headers {
            NTHeaders::NTHeaders32(h32) => h32.optional_header.image_base as usize,
            NTHeaders::NTHeaders64(h64) => h64.optional_header.image_base as usize,
        };
        let rva = match va {
            VA::VA32(v32) => RVA(( (v32.0 as usize) - image_base ) as u32),
            VA::VA64(v64) => RVA(( (v64.0 as usize) - image_base ) as u32),
        };

        if !self.validate_rva(rva) {
            return Err(Error::InvalidRVA);
        }

        Ok(rva)
    }
    /// Converts a VA to an offset.
    pub fn va_to_offset(&self, va: VA) -> Result<Offset, Error> {
        let rva = match self.va_to_rva(va) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        self.rva_to_offset(rva)
    }

    /// Get the data directory reference represented by the [ImageDirectoryEntry](headers::ImageDirectoryEntry) enum.
    /// Returns [Error::BadDirectory](Error::BadDirectory) if the given directory is inaccessible due to the directory
    /// size.
    pub fn get_data_directory(&self, dir: ImageDirectoryEntry) -> Result<&ImageDataDirectory, Error> {
        let directory_table = match self.get_data_directory_table() {
            Ok(d) => d,
            Err(e) => return Err(e),
        };
        let index = dir as usize;

        if index >= directory_table.len() {
            return Err(Error::BadDirectory);
        }

        Ok(&directory_table[index])
    }
    /// Get the mutable data directory reference represented by the [ImageDirectoryEntry](headers::ImageDirectoryEntry) enum.
    pub fn get_mut_data_directory(&mut self, dir: ImageDirectoryEntry) -> Result<&mut ImageDataDirectory, Error> {
        let directory_table = match self.get_mut_data_directory_table() {
            Ok(d) => d,
            Err(e) => return Err(e),
        };
        let index = dir as usize;

        if index >= directory_table.len() {
            return Err(Error::BadDirectory);
        }

        Ok(&mut directory_table[index])
    }
    /// Check whether or not this PE file has a given data directory.
    ///
    /// A PE file "has" a data directory if the following conditions are met:
    /// * the directory is present in the data directory array
    /// * the RVA is nonzero
    /// * the RVA is valid
    pub fn has_data_directory(&self, dir: ImageDirectoryEntry) -> bool {
        let dir_obj = match self.get_data_directory(dir) {
            Ok(d) => d,
            Err(_) => return false,
        };

        if dir_obj.virtual_address.0 == 0 { return false; }

        self.validate_rva(dir_obj.virtual_address)
    }

    /// Get an [`RVA`](RVA) object relative to the resource directory.
    ///
    /// This is useful for gathering addresses when parsing the resource directory. Returns [`Error::BufferTooSmall`](Error::BufferTooSmall)
    /// if the offset doesn't fit in the resource directory.
    pub fn get_resource_address(&self, offset: ResourceOffset) -> Result<RVA, Error> {
        let dir = match self.get_data_directory(ImageDirectoryEntry::Resource) {
            Ok(d) => d,
            Err(e) => return Err(e),
        };

        if offset.0 > dir.size {
            return Err(Error::BufferTooSmall);
        }

        if dir.virtual_address.0 == 0 || !self.validate_rva(dir.virtual_address) {
            return Err(Error::InvalidRVA);
        }

        Ok(RVA(dir.virtual_address.0 + offset.0))
    }
}
