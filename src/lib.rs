//! [exe-rs](https://github.com/frank2/exe-rs) is a library for handling PE files, whether it be building them or analyzing them!
//!
//! Getting started is easy:
//! ```rust
//! let pefile = PE::from_file("test/compiled.exe").unwrap();
//! let import_directory = pefile.resolve_data_directory(ImageDirectoryEntry::Import).unwrap();
//!
//! if let DataDirectory::Import(import_table) = import_directory {
//!    for import in import_table {
//!       println!("Module: {}", import.get_name(pefile).unwrap().as_str());
//!       println!("Imports: {:?}", import.get_imports(pefile).unwrap());
//!    }
//! }
//! ```
//!
//! Standard PE headers and other types can be found in the [types](types/) module. The
//! [buffer](buffer/) module contains low-level functionality for handling a PE buffer.
//! Further usage examples can be found in the [test file](https://github.com/frank2/exe-rs/blob/main/src/tests.rs).

extern crate chrono;

pub mod buffer;
pub mod types;

#[cfg(test)]
mod tests;

use std::convert::AsRef;
use std::io::{Error as IoError};
use std::mem::size_of;
use std::path::Path;

use crate::buffer::Buffer;
use crate::types::*;

/// Errors produced by the library.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Error {
    /// The PE buffer was too small to complete the operation.
    BufferTooSmall,
    /// The PE file has an invalid DOS signature.
    InvalidDOSSignature,
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
}

/// Represents a PE file.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct PE {
    /// The buffer that holds the data. Various operations such as getting
    /// references to objects in the data can be found in the buffer object.
    pub buffer: Buffer,
    /* pub virtual: Option<Buffer> */
    /// The optional filename of the PE file.
    pub filename: Option<String>,
}
impl PE {
    /// Generates a new, blank PE file. Typically only useful for constructing
    /// new PE files.
    pub fn new(size: Option<usize>) -> Self {
        Self {
            buffer: Buffer::new(size),
            filename: None,
        }
    }
    /// Generates a new PE file from a slice of data.
    pub fn from_data(data: &[u8]) -> Self {
        Self {
            buffer: Buffer::from_data(data),
            filename: None,
        }
    }
    /// Generates a new PE file from a file on disk.
    pub fn from_file<P: AsRef<Path>>(filename: P) -> Result<Self, IoError> {
        match Buffer::from_file(&filename) {
            Ok(buffer) => Ok(Self { buffer: buffer, filename: Some(String::from(filename.as_ref().to_str().unwrap())) }),
            Err(e) => Err(e),
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
    /// let pefile = PE::from_file("test/normal64.exe").unwrap();
    /// let headers = pefile.get_valid_nt_headers().unwrap();
    ///
    /// match headers {
    ///    NTHeaders::NTHeaders32(_) => println!("this won't print..."),
    ///    NTHeaders::NTHeaders64(_) => println!("...but this will!"),
    /// }
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

        offset += size_of::<u32>() as u32;
        offset += size_of::<ImageFileHeader>() as u32;
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
    /// ```Error::SectionNotFound``` error if the offset wasn't found to be in a section.
    pub fn get_section_by_offset(&self, offset: Offset) -> Result<&ImageSectionHeader, Error> {
        let section_table = match self.get_section_table() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        for section in section_table {
            let base = section.pointer_to_raw_data.0;
            let end = base+section.size_of_raw_data;

            if base <= offset.0 && offset.0 < end {
                return Ok(section);
            }
        }

        Err(Error::SectionNotFound)
    }

    /// Get a mutable reference to a section in the PE file by a given offset. Yields a
    /// ```Error::SectionNotFound``` error if the offset wasn't found to be in a section.
    pub fn get_mut_section_by_offset(&mut self, offset: Offset) -> Result<&mut ImageSectionHeader, Error> {
        let section_table = match self.get_mut_section_table() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        for section in section_table {
            let base = section.pointer_to_raw_data.0;
            let end = base+section.size_of_raw_data;

            if base <= offset.0 && offset.0 < end {
                return Ok(section);
            }
        }

        Err(Error::SectionNotFound)
    }

    /// Get a reference to a section in the PE file by a given RVA. Yields a
    /// ```Error::SectionNotFound``` error if the RVA wasn't found to be in a section.
    pub fn get_section_by_rva(&self, rva: RVA) -> Result<&ImageSectionHeader, Error> {
        let section_table = match self.get_section_table() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        for section in section_table {
            let base = section.virtual_address.0;
            let end = base+section.virtual_size;

            if base <= rva.0 && rva.0 < end {
                return Ok(section);
            }
        }

        Err(Error::SectionNotFound)
    }

    /// Get a mutable reference to a section in the PE file by a given RVA. Yields a
    /// ```Error::SectionNotFound``` error if the RVA wasn't found to be in a section.
    pub fn get_mut_section_by_rva(&mut self, rva: RVA) -> Result<&mut ImageSectionHeader, Error> {
        let section_table = match self.get_mut_section_table() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        for section in section_table {
            let base = section.virtual_address.0;
            let end = base+section.virtual_size;

            if base <= rva.0 && rva.0 < end {
                return Ok(section);
            }
        }

        Err(Error::SectionNotFound)
    }

    /// Get a reference to a section in the PE file by its name. Yields a
    /// ```Error::SectionNotFound``` error if the name wasn't found in the section table.
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
    /// ```Error::SectionNotFound``` error if the name wasn't found in the section table.
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

    /// Verify that the given offset is a valid offset. An offset is validated if it is less than
    /// the length of the buffer.
    pub fn validate_offset(&self, offset: Offset) -> bool {
        (offset.0 as usize) < self.buffer.len()
    }
    /// Verify that the given RVA is a valid RVA. An RVA is validated if it is less than the size
    /// of the image.
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
    /// Verify that the given VA is a valid VA for this image. A VA is validated if it
    /// lands between the image base and the end of the image, determined by its size.
    /// In other words: image_base <= VA < (image_base+image_size)
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

    /// Convert an offset to an RVA address. Produces ```Error::InvalidRVA``` if the produced
    /// RVA is invalid.
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

        if !self.validate_rva(final_rva) {
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

    /// Convert an RVA to an offset address. Produces a ```Error::InvalidOffset``` error if
    /// the produced offset is invalid.
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

        if !self.validate_offset(final_offset) {
            return Err(Error::InvalidOffset);
        }

        Ok(Offset(offset))
    }
    /// Convert an RVA to a VA address. Produces a ```Error::InvalidVA``` error if the produced
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

    /// Convert a VA to an RVA. Produces a ```Error::InvalidRVA``` error if the produced RVA
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

    /// Get the data directory reference represented by the ```ImageDirectoryEntry``` enum.
    pub fn get_data_directory(&self, dir: ImageDirectoryEntry) -> Result<&ImageDataDirectory, Error> {
        match self.get_valid_nt_headers() {
            Err(e) => return Err(e),
            Ok(h) => match h {
                NTHeaders::NTHeaders32(h32) => Ok(&h32.optional_header.data_directory[dir as usize]),
                NTHeaders::NTHeaders64(h64) => Ok(&h64.optional_header.data_directory[dir as usize]),
            }
        }
    }
    /// Get the mutable data directory reference represented by the ```ImageDirectoryEntry``` enum.
    pub fn get_mut_data_directory(&mut self, dir: ImageDirectoryEntry) -> Result<&mut ImageDataDirectory, Error> {
        match self.get_valid_mut_nt_headers() {
            Err(e) => return Err(e),
            Ok(h) => match h {
                NTHeadersMut::NTHeaders32(h32) => Ok(&mut h32.optional_header.data_directory[dir as usize]),
                NTHeadersMut::NTHeaders64(h64) => Ok(&mut h64.optional_header.data_directory[dir as usize]),
            }
        }
    }
    
    /// Resolve the data directory represented by the ```ImageDirectoryEntry``` enum. This produces a data
    /// directory variant enum object associated with the data directory type.
    pub fn resolve_data_directory(&self, dir: ImageDirectoryEntry) -> Result<DataDirectory, Error> {
        match self.get_valid_nt_headers() {
            Err(e) => return Err(e),
            Ok(h) => match h {
                NTHeaders::NTHeaders32(h32) => h32.optional_header.data_directory[dir as usize].resolve(self, dir),
                NTHeaders::NTHeaders64(h64) => h64.optional_header.data_directory[dir as usize].resolve(self, dir),
            }
        }
    }
}
