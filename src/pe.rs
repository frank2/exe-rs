//! This module contains the primary traits and types by which PE structures are derived.

use byteorder::{LittleEndian, ReadBytesExt};

use pkbuffer::{PtrBuffer, VecBuffer, Error as PKError};
pub use pkbuffer::{Buffer, Castable};

use std::clone::Clone;
use std::cmp;
use std::convert::AsRef;
use std::io::Cursor;
use std::mem;
use std::ops::{Index, IndexMut};
use std::path::Path;
use std::slice;

use crate::{align, Error, HashData};
use crate::headers::*;
use crate::imphash::*;
use crate::types::*;

/// An enum to tag the PE file with what its memory map looks like.
///
/// When a PE is loaded by Windows, it's ultimately parsed and rewritten before being placed into
/// memory. This means the image in memory is different from the disk. This is why, for example,
/// [`RVA`](RVA)s and [`Offset`](Offset)s differ in type-- the `RVA` represents the offset to the image in
/// *memory*, whereas the `Offset` represents the offset to the image on *disk*. This enum
/// is necessary to maintain a simple translation layer for basic address operations.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum PEType {
    Disk,
    Memory,
}

/// An enum to translate between [`RVA`](RVA) and [`Offset`](Offset) addresses.
///
/// This typically never gets exposed beyond the [`translate`](PE::translate) function. See [`PEType`](PEType)
/// for an explanation of why this is here.
pub enum PETranslation {
    Disk(Offset),
    Memory(RVA),
}
impl Address for PETranslation {
    fn as_offset<P: PE>(&self, pe: &P) -> Result<Offset, Error> {
        match self {
            Self::Disk(o) => Ok(*o),
            Self::Memory(r) => r.as_offset(pe),
        }
    }
    fn as_rva<P: PE>(&self, pe: &P) -> Result<RVA, Error> {
        match self {
            Self::Disk(o) => o.as_rva(pe),
            Self::Memory(r) => Ok(*r),
        }
    }
    fn as_va<P: PE>(&self, pe: &P) -> Result<VA, Error> {
        match self {
            Self::Disk(o) => o.as_va(pe),
            Self::Memory(r) => r.as_va(pe),
        }
    }
    fn as_ptr<P: PE>(&self, pe: &P) -> Result<*const u8, Error> {
        let offset = self.as_offset(pe)?;
        offset.as_ptr(pe)
    }
}
impl From<Offset> for PETranslation {
    fn from(offset: Offset) -> Self {
        Self::Disk(offset)
    }
}
impl From<RVA> for PETranslation {
    fn from(rva: RVA) -> Self {
        Self::Memory(rva)
    }
}

/// Represents a type which handles PE data.
pub trait PE: Buffer + Sized {
    /// Return the type of `PE` this object represents.
    fn get_type(&self) -> PEType;

    /// Only for Windows. Return if the `PE` has been allocated by `VirtualAlloc`.
    #[cfg(feature="win32")]
    fn is_allocated(&self) -> bool;

    /// Get the size of a zero-terminated C-string in the data.
    fn get_cstring_size(&self, offset: usize, thunk: bool, max_size: Option<usize>) -> Result<usize, Error> {
        let end = match max_size {
            None => self.len(),
            Some(s) => offset + s,
        };

        if end > self.len() {
            return Err(Error::OutOfBounds(self.len(), end));
        }

        let mut cursor = Cursor::new(self.as_slice());
        let mut index = offset;

        for i in index..end {
            cursor.set_position(i as u64);

            let val = cursor.read_u8();

            match val {
                Err(e) => return Err(Error::from(e)),
                Ok(v) => match v {
                    0 => { index = i; break; },
                    _ => ()
                }
            }
        }

        index += 1; // include null byte
        let mut size = index - offset;

        if thunk {
            size += size % 2;
        }

        Ok(size)
    }
    /// Gets the size of a zero-terminated UTF16 string in the data.
    fn get_widestring_size(&self, offset: usize, max_size: Option<usize>) -> Result<usize, Error> {
        let end = match max_size {
            None => self.len(),
            Some(s) => offset + (s * 2),
        };

        if end > self.len() {
            return Err(Error::OutOfBounds(self.len(), end));
        }

        let mut cursor = Cursor::new(self.as_slice());
        let mut index = offset;

        for i in (index..end).step_by(2) {
            cursor.set_position(i as u64);

            let val = cursor.read_u16::<LittleEndian>();

            match val {
                Err(e) => return Err(Error::from(e)),
                Ok(v) => match v {
                    0 => { index = i; break; },
                    _ => ()
                }
            }
        }

        Ok( ( (index+2) - offset) / 2 )
    }
    /// Get a zero-terminated C-string from the data. The thunk option is there to handle imports by name, whose null
    /// terminated value size is dependent on how long the string is (i.e., if it's an odd length, an extra zero is
    /// appended).
    ///
    /// # Example
    ///
    /// ```rust
    /// use exe::{PE, VecPE};
    /// use exe::types::{Offset, CCharString};
    ///
    /// let pefile = VecPE::from_disk_file("test/dll.dll").unwrap();
    /// let dll_name = pefile.get_cstring(Offset(0x328).into(), false, None).unwrap();
    ///
    /// assert_eq!(dll_name.as_str().unwrap(), "dll.dll");
    /// ```
    fn get_cstring(&self, offset: usize, thunk: bool, max_size: Option<usize>) -> Result<&[CChar], Error> {
        let found_size = self.get_cstring_size(offset, thunk, max_size)?;
        let result = self.get_slice_ref::<CChar>(offset, found_size)?;
        Ok(result)
    }
    /// Get a mutable zero-terminated C-string from the data.
    fn get_mut_cstring(&mut self, offset: usize, thunk: bool, max_size: Option<usize>) -> Result<&mut [CChar], Error> {
        let found_size = self.get_cstring_size(offset, thunk, max_size)?;
        let result = self.get_mut_slice_ref::<CChar>(offset, found_size)?;
        Ok(result)
    }
    /// Get a zero-terminated UTF16 string from the data.
    fn get_widestring(&self, offset: usize, max_size: Option<usize>) -> Result<&[WChar], Error> {
        let found_size = self.get_widestring_size(offset, max_size)?;
        let result = self.get_slice_ref::<WChar>(offset, found_size)?;
        Ok(result)
    }
    /// Get a mutable zero-terminated UTF16 string from the data.
    fn get_mut_widestring(&mut self, offset: usize, max_size: Option<usize>) -> Result<&mut [WChar], Error> {
        let found_size = self.get_widestring_size(offset, max_size)?;
        let result = self.get_mut_slice_ref::<WChar>(offset, found_size)?;
        Ok(result)
    }
    
    /// Translate an address into an offset usable by the [`Buffer`](pkbuffer::Buffer) trait based on the `PE` object's
    /// type (i.e., the result of [`PE::get_type`](PE::get_type)).
    ///
    /// This differs from [`rva_to_offset`](PE::rva_to_offset) because it does not directly rely on the section table.
    /// Rather, if the image is a memory image, it treats [`RVA`](RVA)s as buffer offsets, because that's what they
    /// are in memory. Otherwise, it converts the [`RVA`](RVA) into an offset via the section table. The reverse goes
    /// for if the PE image is a disk image and an [`Offset`](Offset) is provided.
    ///
    /// Typically, if you're going to directly access data with the [`Buffer`](pkbuffer::Buffer), you'll
    /// want to call this function instead of calling [`rva_to_offset`](PE::rva_to_offset) and similar functions
    /// because this function should guarantee the buffer offset is correct.
    ///
    /// # Example
    ///
    /// ```rust
    /// use exe::{PE, VecPE};
    /// use exe::types::Offset;
    ///
    /// let pefile = VecPE::from_memory_file("test/compiled_dumped.bin").unwrap();
    /// let offset = Offset(0x400);
    ///
    /// assert_eq!(pefile.translate(offset.into()).unwrap(), 0x1000);
    /// ```
    fn translate(&self, addr: PETranslation) -> Result<usize, Error> {
        match self.get_type() {
            PEType::Disk => match addr {
                PETranslation::Disk(o) => Ok(o.into()),
                PETranslation::Memory(r) => {
                    let result = r.as_offset(self)?;
                    Ok(result.into())
                },
            }
            PEType::Memory => match addr {
                PETranslation::Disk(o) => {
                    let result = o.as_rva(self)?;
                    Ok(result.into())
                },
                PETranslation::Memory(r) => Ok(r.into()),
            }
        }
    }

    /// Get the DOS header without verifying its contents.
    fn get_dos_header(&self) -> Result<&ImageDOSHeader, Error> {
        let result = self.get_ref::<ImageDOSHeader>(0)?; Ok(result)
    }
    /// Get a mutable DOS header without verifying its contents.
    fn get_mut_dos_header(&mut self) -> Result<&mut ImageDOSHeader, Error> {
        let result = self.get_mut_ref::<ImageDOSHeader>(0)?; Ok(result)
    }
    /// Get the DOS header and verify it's a valid DOS header.
    fn get_valid_dos_header(&self) -> Result<&ImageDOSHeader, Error> {
        let dos_header = self.get_dos_header()?;

        if dos_header.e_magic != DOS_SIGNATURE {
            return Err(Error::InvalidDOSSignature(dos_header.e_magic));
        }

        Ok(dos_header)
    }
    /// Get a mutable DOS header and verify it's a valid DOS header.
    fn get_valid_mut_dos_header(&mut self) -> Result<&mut ImageDOSHeader, Error> {
        let dos_header = self.get_mut_dos_header()?;

        if dos_header.e_magic != DOS_SIGNATURE {
            return Err(Error::InvalidDOSSignature(dos_header.e_magic));
        }

        Ok(dos_header)
    }
    /// Get the offset to the PE headers.
    fn e_lfanew(&self) -> Result<Offset, Error> {
        let header = self.get_valid_dos_header()?;
        Ok(header.e_lfanew)
    }
    /// Get the executable DOS stub in the data.
    ///
    /// This collects a [`u8`](u8) slice from the end of the DOS header to [`e_lfanew`](ImageDOSHeader::e_lfanew). If
    /// [`e_lfanew`](ImageDOSHeader::e_lfanew) overlaps the DOS header, an empty slice is returned.
    fn get_dos_stub(&self) -> Result<&[u8], Error> {
        let e_lfanew = self.e_lfanew()?;
        let dos_header_end = Offset(mem::size_of::<ImageDOSHeader>() as u32);

        if e_lfanew.0 < dos_header_end.0 {
            let result = self.read(dos_header_end.into(), 0usize)?;
            return Ok(result);
        }
        
        let result = self.read(dos_header_end.into(), (e_lfanew.0 - dos_header_end.0) as usize)?;
        Ok(result)
    }

    /// Get 32-bit NT headers without verifying its contents.
    fn get_nt_headers_32(&self) -> Result<&ImageNTHeaders32, Error> {
        let e_lfanew = self.e_lfanew()?;
        let result = self.get_ref::<ImageNTHeaders32>(e_lfanew.into())?;
        Ok(result)
    }
    /// Get mutable 32-bit NT headers without verifying its contents.
    fn get_mut_nt_headers_32(&mut self) -> Result<&mut ImageNTHeaders32, Error> {
        let e_lfanew = self.e_lfanew()?;
        let result = self.get_mut_ref::<ImageNTHeaders32>(e_lfanew.into())?;
        Ok(result)
    }
    /// Get 32-bit NT headers and verify that they're 32-bit NT headers.
    fn get_valid_nt_headers_32(&self) -> Result<&ImageNTHeaders32, Error> {
        let e_lfanew = self.e_lfanew()?;

        if e_lfanew.0 % 4 != 0 {
            return Err(Error::BadAlignment);
        }
        
        let nt_headers = self.get_nt_headers_32()?;

        if nt_headers.signature != NT_SIGNATURE {
            return Err(Error::InvalidPESignature(nt_headers.signature));
        }

        if nt_headers.optional_header.magic != HDR32_MAGIC {
            return Err(Error::InvalidNTSignature(nt_headers.optional_header.magic));
        }

        Ok(nt_headers)
    }
    /// Get mutable 32-bit NT headers and verify that they're 32-bit NT headers.
    fn get_valid_mut_nt_headers_32(&mut self) -> Result<&mut ImageNTHeaders32, Error> {
        let e_lfanew = self.e_lfanew()?;

        if e_lfanew.0 % 4 != 0 {
            return Err(Error::BadAlignment);
        }

        let nt_headers = self.get_mut_nt_headers_32()?;

        if nt_headers.signature != NT_SIGNATURE {
            return Err(Error::InvalidPESignature(nt_headers.signature));
        }

        if nt_headers.optional_header.magic != HDR32_MAGIC {
            return Err(Error::InvalidNTSignature(nt_headers.optional_header.magic));
        }

        Ok(nt_headers)
    }
    /// Get 64-bit NT headers without verifying its contents.
    fn get_nt_headers_64(&self) -> Result<&ImageNTHeaders64, Error> {
        let e_lfanew = self.e_lfanew()?;
        let result = self.get_ref::<ImageNTHeaders64>(e_lfanew.into())?;
        Ok(result)
    }
    /// Get mutable 64-bit NT headers without verifying its contents.
    fn get_mut_nt_headers_64(&mut self) -> Result<&mut ImageNTHeaders64, Error> {
        let e_lfanew = self.e_lfanew()?;
        let result = self.get_mut_ref::<ImageNTHeaders64>(e_lfanew.into())?;
        Ok(result)
    }
    /// Get 64-bit NT headers and verify that they're 64-bit NT headers.
    fn get_valid_nt_headers_64(&self) -> Result<&ImageNTHeaders64, Error> {
        let e_lfanew = self.e_lfanew()?;
        
        if e_lfanew.0 % 4 != 0 {
            return Err(Error::BadAlignment);
        }

        let nt_headers = self.get_nt_headers_64()?;

        if nt_headers.signature != NT_SIGNATURE {
            return Err(Error::InvalidPESignature(nt_headers.signature));
        }

        if nt_headers.optional_header.magic != HDR64_MAGIC {
            return Err(Error::InvalidNTSignature(nt_headers.optional_header.magic));
        }
        
        Ok(nt_headers)
    }
    /// Get mutable 64-bit NT headers and verify that they're 64-bit NT headers.
    fn get_valid_mut_nt_headers_64(&mut self) -> Result<&mut ImageNTHeaders64, Error> {
        let e_lfanew = self.e_lfanew()?;

        if e_lfanew.0 % 4 != 0 {
            return Err(Error::BadAlignment);
        }

        let nt_headers = self.get_mut_nt_headers_64()?;

        if nt_headers.signature != NT_SIGNATURE {
            return Err(Error::InvalidPESignature(nt_headers.signature));
        }

        if nt_headers.optional_header.magic != HDR64_MAGIC {
            return Err(Error::InvalidNTSignature(nt_headers.optional_header.magic));
        }

        Ok(nt_headers)
    }
    /// Get the NT signature from the optional header of the NT headers.
    fn get_nt_magic(&self) -> Result<u16, Error> {
        // the difference in size doesn't affect the magic header, so we
        // simply blindly cast it to a 32-bit header to get the value
        
        let header = self.get_nt_headers_32()?;
        Ok(header.optional_header.magic)
    }
    /// Get the architecture of this PE file.
    fn get_arch(&self) -> Result<Arch, Error> {
        let magic = self.get_nt_magic()?;

        match magic {
            HDR32_MAGIC => Ok(Arch::X86),
            HDR64_MAGIC => Ok(Arch::X64),
            _ => return Err(Error::InvalidNTSignature(magic)),
        }
    }
    /// Get the NT headers of this PE file, inferring from the content of the file which architecture it is and
    /// validating the headers.
    ///
    /// # Example
    ///
    /// ```rust
    /// use exe::{PE, VecPE};
    /// use exe::headers::HDR64_MAGIC;
    /// use exe::types::NTHeaders;
    ///
    /// let image = VecPE::from_disk_file("test/normal64.exe").unwrap();
    /// let headers = image.get_valid_nt_headers().unwrap();
    ///
    /// let magic = match headers {
    ///    NTHeaders::NTHeaders32(hdr32) => hdr32.optional_header.magic,
    ///    NTHeaders::NTHeaders64(hdr64) => hdr64.optional_header.magic,
    /// };
    ///
    /// assert_eq!(magic, HDR64_MAGIC);
    /// ```
    fn get_valid_nt_headers(&self) -> Result<NTHeaders, Error> {
        let magic = self.get_nt_magic()?;
        
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
            Err(Error::InvalidNTSignature(magic))
        }
    }
    /// Get mutable NT headers of this PE file, inferring from the content of the file which architecture it is and
    /// validating the headers.
    fn get_valid_mut_nt_headers(&mut self) -> Result<NTHeadersMut, Error> {
        let magic = self.get_nt_magic()?;
        
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
            Err(Error::InvalidNTSignature(magic))
        }
    }

    /// Validate the checksum in the image with the calculated checksum.
    fn validate_checksum(&self) -> Result<bool, Error> {
        let checksum = match self.get_valid_nt_headers() {
            Ok(h) => match h {
                NTHeaders::NTHeaders32(h32) => h32.optional_header.checksum,
                NTHeaders::NTHeaders64(h64) => h64.optional_header.checksum,
            },
            Err(e) => return Err(e),
        };

        match self.calculate_checksum() {
            Ok(c) => Ok(c == checksum),
            Err(e) => Err(e),
        }
    }

    /// Calculate the checksum of the PE image.
    fn calculate_checksum(&self) -> Result<u32, Error> {
        let checksum_ref = match self.get_valid_nt_headers() {
            Ok(h) => match h {
                NTHeaders::NTHeaders32(h32) => &h32.optional_header.checksum,
                NTHeaders::NTHeaders64(h64) => &h64.optional_header.checksum,
            },
            Err(e) => return Err(e),
        };

        let checksum_offset = self.ref_to_offset(checksum_ref)?;
        let eof = self.len();
        let mut checksum = 0u64;

        for offset in (0..eof).step_by(4) {
            if offset == checksum_offset { continue; }

            let data: Vec<u8> = match self.read(offset, 4) {
                Ok(d) => d.iter().cloned().collect(),
                Err(e) => {
                    if let PKError::OutOfBounds(_,_) = e { () }
                    else { return Err(Error::from(e)); }

                    let real_size = eof - offset;
                    let real_output = self.read(offset, real_size)?;                        
                    let mut padded_output = Vec::<u8>::new();
                    padded_output.extend_from_slice(real_output);
                    padded_output.append(&mut vec![0u8; 4 - padded_output.len()]);

                    padded_output
                },
            };

            let int_val = data.as_slice().read_u32::<LittleEndian>().unwrap();
            
            checksum = (checksum & 0xFFFFFFFF) + (int_val as u64) + (checksum >> 32);

            if checksum > (u32::MAX as u64) {
                checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32);
            }
        }

        checksum = (checksum & 0xFFFF) + (checksum >> 16);
        checksum = checksum + (checksum >> 16);
        checksum = checksum & 0xFFFF;
        checksum += eof as u64;

        Ok(checksum as u32)
    }

    /// Get the entrypoint of this PE file.
    fn get_entrypoint(&self) -> Result<RVA, Error> {
        let nt_headers = self.get_valid_nt_headers()?;

        match nt_headers {
            NTHeaders::NTHeaders32(h32) => Ok(h32.optional_header.address_of_entry_point),
            NTHeaders::NTHeaders64(h64) => Ok(h64.optional_header.address_of_entry_point),
        }
    }
    /// Get the image base of this PE file.
    ///
    /// On Windows, if the buffer has been allocated with `VirtualAlloc` (like a [`VallocBuffer`](crate::valloc::VallocBuffer)), return that base address instead.
    /// Otherwise, return [`ImageBase`](ImageOptionalHeader32::image_base) from the NT headers.
    fn get_image_base(&self) -> Result<u64, Error> {
        #[cfg(feature="win32")] {
            if self.is_allocated() {
                return Ok(self.as_ptr() as u64);
            }
        }

        match self.get_valid_nt_headers() {
            Ok(h) => match h {
                NTHeaders::NTHeaders32(h32) => Ok(h32.optional_header.image_base as u64),
                NTHeaders::NTHeaders64(h64) => Ok(h64.optional_header.image_base),
            },
            Err(e) => return Err(e),
        }
    }

    /// Get the offset to the data directory within the PE file.
    fn get_data_directory_offset(&self) -> Result<Offset, Error> {
        let e_lfanew = self.e_lfanew()?;        
        let nt_header = self.get_valid_nt_headers()?;
        let header_size = match nt_header {
            NTHeaders::NTHeaders32(_) => mem::size_of::<ImageNTHeaders32>(),
            NTHeaders::NTHeaders64(_) => mem::size_of::<ImageNTHeaders64>(),
        };

        let offset = Offset(e_lfanew.0 + (header_size as u32));

        if !self.validate_offset(offset) {
            return Err(Error::InvalidOffset(offset));
        }

        Ok(offset)
    }
    /// Get the size of the data directory. Rounds down [`number_of_rva_and_sizes`](ImageOptionalHeader32::number_of_rva_and_sizes) to 16, which is what
    /// the Windows loader does.
    fn get_data_directory_size(&self) -> Result<usize, Error> {
        let nt_header = self.get_valid_nt_headers()?;
        let sizes = match nt_header {
            NTHeaders::NTHeaders32(h32) => h32.optional_header.number_of_rva_and_sizes,
            NTHeaders::NTHeaders64(h64) => h64.optional_header.number_of_rva_and_sizes,
        };

        // data directory gets rounded down if greater than 16
        if sizes > 16 {
            Ok(16)
        }
        else {
            Ok(sizes as usize)
        }
    }
    /// Get the data directory table.
    ///
    /// Normally one would expect this to be a part of [`ImageOptionalHeader`](ImageOptionalHeader32), but
    /// [`ImageOptionalHeader::number_of_rva_and_sizes`](ImageOptionalHeader32::number_of_rva_and_sizes) controls
    /// the size of the array. Therefore, we can't stick it in the optional header, because that would
    /// produce a variable-sized structure, which Rust doesn't support.
    fn get_data_directory_table(&self) -> Result<&[ImageDataDirectory], Error> {
        let offset = self.get_data_directory_offset()?;
        let size = self.get_data_directory_size()?;
        let result = self.get_slice_ref::<ImageDataDirectory>(offset.into(), size)?;
        Ok(result)
    }
    /// Get a mutable data directory table.
    fn get_mut_data_directory_table(&mut self) -> Result<&mut [ImageDataDirectory], Error> {
        let offset = self.get_data_directory_offset()?;
        let size = self.get_data_directory_size()?;
        let result = self.get_mut_slice_ref::<ImageDataDirectory>(offset.into(), size)?;
        Ok(result)
    }

    /// Get the data directory reference represented by the [`ImageDirectoryEntry`](crate::headers::ImageDirectoryEntry) enum.
    /// Returns [`Error::BadDirectory`](Error::BadDirectory) if the given directory is inaccessible due to the directory
    /// size.
    fn get_data_directory(&self, dir: ImageDirectoryEntry) -> Result<&ImageDataDirectory, Error> {
        let directory_table = self.get_data_directory_table()?;
        let index = dir as usize;

        if index >= directory_table.len() {
            return Err(Error::BadDirectory(dir));
        }

        Ok(&directory_table[index])
    }
    /// Get the mutable data directory reference represented by the [`ImageDirectoryEntry`](crate::headers::ImageDirectoryEntry) enum.
    fn get_mut_data_directory(&mut self, dir: ImageDirectoryEntry) -> Result<&mut ImageDataDirectory, Error> {
        let directory_table = self.get_mut_data_directory_table()?;
        let index = dir as usize;

        if index >= directory_table.len() {
            return Err(Error::BadDirectory(dir));
        }

        Ok(&mut directory_table[index])
    }
    /// Check whether or not this PE file has a given data directory.
    ///
    /// A PE file "has" a data directory if the following conditions are met:
    /// * the directory is present in the data directory array
    /// * the RVA is nonzero
    /// * the RVA is valid
    fn has_data_directory(&self, dir: ImageDirectoryEntry) -> bool {
        let dir_obj = match self.get_data_directory(dir) {
            Ok(d) => d,
            Err(_) => return false,
        };
        
        if dir_obj.virtual_address.0 == 0 { return false; }

        self.validate_rva(dir_obj.virtual_address)
    }
    /// Parse an object at the given data directory identified by [`ImageDirectoryEntry`](ImageDirectoryEntry).
    fn cast_directory<T: Castable>(&self, dir: ImageDirectoryEntry) -> Result<&T, Error> {
        let directory = self.get_data_directory(dir)?;
        directory.cast::<T,Self>(self)
    }
    /// Parse a mutable object at the given data directory identified by [`ImageDirectoryEntry`](ImageDirectoryEntry).
    fn cast_directory_mut<T: Castable>(&mut self, dir: ImageDirectoryEntry) -> Result<&mut T, Error> {
        // I don't know how to do this properly, so do some casting magic to get around
        // the borrow checker
        let bypass = unsafe { &mut *(self as *mut Self) };
        let directory = self.get_data_directory(dir)?;
        directory.cast_mut::<T,Self>(bypass)
    }

    /// Get the offset to the section table within the PE file.
    fn get_section_table_offset(&self) -> Result<Offset, Error> {
        let e_lfanew = self.e_lfanew()?;        
        let nt_header = self.get_valid_nt_headers()?;
        let size_of_optional = match nt_header {
            NTHeaders::NTHeaders32(h) => h.file_header.size_of_optional_header,
            NTHeaders::NTHeaders64(h) => h.file_header.size_of_optional_header,
        };

        let Offset(mut offset) = e_lfanew;

        offset += mem::size_of::<u32>() as u32;
        offset += mem::size_of::<ImageFileHeader>() as u32;
        offset += size_of_optional as u32;

        if !self.validate_offset(Offset(offset)) {
            return Err(Error::InvalidOffset(Offset(offset)));
        }

        Ok(Offset(offset))
    }
    /// Get the section table of the PE file.
    fn get_section_table(&self) -> Result<&[ImageSectionHeader], Error> {
        let offset = self.get_section_table_offset()?;
        let nt_headers = self.get_valid_nt_headers()?;
        let sections = match nt_headers {
            NTHeaders::NTHeaders32(h) => h.file_header.number_of_sections,
            NTHeaders::NTHeaders64(h) => h.file_header.number_of_sections,
        };

        let result = self.get_slice_ref::<ImageSectionHeader>(offset.into(), sections as usize)?;
        Ok(result)
    }
    /// Get a mutable section table from the PE file.
    fn get_mut_section_table(&mut self) -> Result<&mut [ImageSectionHeader], Error> {
        let offset = self.get_section_table_offset()?;
        let nt_headers = self.get_valid_nt_headers()?;
        let sections = match nt_headers {
            NTHeaders::NTHeaders32(h) => h.file_header.number_of_sections,
            NTHeaders::NTHeaders64(h) => h.file_header.number_of_sections,
        };

        let result = self.get_mut_slice_ref::<ImageSectionHeader>(offset.into(), sections as usize)?;
        Ok(result)
    }

    /// Get a reference to a section in the PE file by a given offset. Yields a
    /// [`Error::SectionNotFound`](Error::SectionNotFound) error if the offset wasn't found to be in a section.
    fn get_section_by_offset(&self, offset: Offset) -> Result<&ImageSectionHeader, Error> {
        let section_table = self.get_section_table()?;
        
        for section in section_table {
            if section.has_offset(offset) {
                return Ok(section);
            }
        }

        Err(Error::SectionNotFound)
    }

    /// Get a mutable reference to a section in the PE file by a given offset. Yields a
    /// [`Error::SectionNotFound`](Error::SectionNotFound) error if the offset wasn't found to be in a section.
    fn get_mut_section_by_offset(&mut self, offset: Offset) -> Result<&mut ImageSectionHeader, Error> {
        let section_table = self.get_mut_section_table()?;

        for section in section_table {
            if section.has_offset(offset) {
                return Ok(section);
            }
        }

        Err(Error::SectionNotFound)
    }

    /// Get a reference to a section in the PE file by a given RVA. Yields a
    /// [`Error::SectionNotFound`](Error::SectionNotFound) error if the RVA wasn't found to be in a section.
    fn get_section_by_rva(&self, rva: RVA) -> Result<&ImageSectionHeader, Error> {
        let section_table = self.get_section_table()?;
        
        for section in section_table {
            if section.has_rva(rva) {
                return Ok(section);
            }
        }

        Err(Error::SectionNotFound)
    }

    /// Get a mutable reference to a section in the PE file by a given RVA. Yields a
    /// [`Error::SectionNotFound`](Error::SectionNotFound) error if the RVA wasn't found to be in a section.
    fn get_mut_section_by_rva(&mut self, rva: RVA) -> Result<&mut ImageSectionHeader, Error> {
        let section_table = self.get_mut_section_table()?;

        for section in section_table {
            if section.has_rva(rva) {
                return Ok(section);
            }
        }

        Err(Error::SectionNotFound)
    }

    /// Get a reference to a section in the PE file by its name. Yields a
    /// [`Error::SectionNotFound`](Error::SectionNotFound) error if the name wasn't found in the section table.
    fn get_section_by_name<S: AsRef<str>>(&self, name: S) -> Result<&ImageSectionHeader, Error> {
        let sections = self.get_section_table()?;
        let s = name.as_ref();

        for section in sections {
            let name = section.name.as_str()?;
            
            if name == s {
                return Ok(section);
            }
        }

        Err(Error::SectionNotFound)
    }

    /// Get a mutable reference to a section in the PE file by its name. Yields a
    /// [`Error::SectionNotFound`](Error::SectionNotFound) error if the name wasn't found in the section table.
    fn get_mut_section_by_name(&mut self, name: String) -> Result<&mut ImageSectionHeader, Error> {
        let sections = self.get_mut_section_table()?;
        let s = name.as_str();
        
        for section in sections {
            let name = section.name.as_str()?;
            
            if name == s {
                return Ok(section);
            }
        }

        Err(Error::SectionNotFound)
    }
    /// Add a given section header to the section table. Returns a mutable reference to the section header as it exists
    /// in the section table.
    fn add_section(&mut self, section: &ImageSectionHeader) -> Result<&mut ImageSectionHeader, Error> {
        match self.get_valid_mut_nt_headers() {
            Ok(ref mut h) => match h {
                NTHeadersMut::NTHeaders32(ref mut h32) => h32.file_header.number_of_sections += 1,
                NTHeadersMut::NTHeaders64(ref mut h64) => h64.file_header.number_of_sections += 1,
            },
            Err(e) => return Err(e),
        }

        let section_table = self.get_mut_section_table()?;

        section_table[section_table.len()-1].clone_from(section);

        Ok(&mut section_table[section_table.len()-1])
    }
    /// Append a given section header to the end of the PE sections. This function differs from [`add_section`](PE::add_section) by setting the
    /// new section's [`pointer_to_raw_data`](ImageSectionHeader::pointer_to_raw_data) and [`virtual_address`](ImageSectionHeader::virtual_address)
    /// to the end of the previous section's boundaries.
    ///
    /// Returns a mutable reference to the new section as it exists in the section table.
    fn append_section(&mut self, section: &ImageSectionHeader) -> Result<&mut ImageSectionHeader, Error> {
        let section_table_ro = self.get_section_table()?;
        let last_section_file_size;
        let last_section_virtual_size;
        let last_offset;
        let last_rva;

        if section_table_ro.len() == 0 {
            last_section_file_size = match self.calculate_header_size() {
                Ok(s) => s as u32,
                Err(e) => return Err(e),
            };
            last_section_virtual_size = last_section_file_size;
            last_offset = Offset(0);
            last_rva = RVA(0);
        }
        else {
            let last_section = section_table_ro[section_table_ro.len()-1].clone();
            last_section_file_size = last_section.size_of_raw_data;
            last_section_virtual_size = last_section.virtual_size;
            last_offset = last_section.pointer_to_raw_data.clone();
            last_rva = last_section.virtual_address.clone();
        }

        let next_offset = self.align_to_file(Offset(last_offset.0 + last_section_file_size))?;
        let next_rva = self.align_to_section(RVA(last_rva.0 + last_section_virtual_size))?;
        let added_section = self.add_section(section)?;

        added_section.pointer_to_raw_data = next_offset;
        added_section.virtual_address = next_rva;

        Ok(added_section)
    }

    /// Verify that the given offset is a valid offset.
    ///
    /// An offset is validated if it is less than the length of the buffer.
    fn validate_offset(&self, offset: Offset) -> bool {
        (offset.0 as usize) < self.len()
    }
    /// Verify that the given RVA is a valid RVA.
    ///
    /// An RVA is validated if it is less than the size of the image.
    fn validate_rva(&self, rva: RVA) -> bool {
        let headers = match self.get_valid_nt_headers() {
            Ok(h) => h,
            Err(_) => return false,
        };
        let image_size = match headers {
            NTHeaders::NTHeaders32(h32) => h32.optional_header.size_of_image,
            NTHeaders::NTHeaders64(h64) => h64.optional_header.size_of_image,
        };

        rva.0 < image_size
    }
    /// Verify that the given VA is a valid VA for this image.
    ///
    /// A VA is validated if it lands between the image base and the end of the image, determined by its size.
    /// In other words: `image_base <= VA < (image_base+image_size)`
    fn validate_va(&self, va: VA) -> bool {
        let headers = match self.get_valid_nt_headers() {
            Ok(h) => h,
            Err(_) => return false,
        };
        let image_base = match self.get_image_base() {
            Ok(i) => i,
            Err(_) => return false,
        };
        let image_size = match headers {
            NTHeaders::NTHeaders32(h32) => h32.optional_header.size_of_image as u64,
            NTHeaders::NTHeaders64(h64) => h64.optional_header.size_of_image as u64,
        };
        
        let start = image_base;
        let end = start + image_size;

        match va {
            VA::VA32(v32) => start <= (v32.0 as u64) && (v32.0 as u64) < end,
            VA::VA64(v64) => start <= v64.0 && v64.0 < end,
        }
    }

    /// Check if a given [`Offset`](Offset) is aligned to the [`file_alignment`](ImageOptionalHeader32::file_alignment) attribute of the
    /// [optional header](ImageOptionalHeader32).
    fn is_aligned_to_file(&self, offset: Offset) -> bool {
        let alignment = match self.get_valid_nt_headers() {
            Ok(h) => match h {
                NTHeaders::NTHeaders32(h32) => h32.optional_header.file_alignment,
                NTHeaders::NTHeaders64(h64) => h64.optional_header.file_alignment,
            },
            Err(_) => return false,
        };

        offset.0 % alignment == 0
    }
    /// Check if a given [`RVA`](RVA) is aligned to the [`section_alignment`](ImageOptionalHeader32::section_alignment) attribute of the
    /// [optional header](ImageOptionalHeader32).
    fn is_aligned_to_section(&self, rva: RVA) -> bool {
        let alignment = match self.get_valid_nt_headers() {
            Ok(h) => match h {
                NTHeaders::NTHeaders32(h32) => h32.optional_header.section_alignment,
                NTHeaders::NTHeaders64(h64) => h64.optional_header.section_alignment,
            },
            Err(_) => return false,
        };

        rva.0 % alignment == 0
    }
    /// Aligns a given [`Offset`](Offset) to the [`file_alignment`](ImageOptionalHeader32::file_alignment) attribute of the
    /// [optional header](ImageOptionalHeader32).
    fn align_to_file(&self, offset: Offset) -> Result<Offset, Error> {
        let alignment = match self.get_valid_nt_headers() {
            Ok(h) => match h {
                NTHeaders::NTHeaders32(h32) => h32.optional_header.file_alignment,
                NTHeaders::NTHeaders64(h64) => h64.optional_header.file_alignment,
            },
            Err(e) => return Err(e),
        };

        Ok(Offset(align(offset.0, alignment)))
    }
    /// Aligns a given [`RVA`](RVA) to the [`section_alignment`](ImageOptionalHeader32::section_alignment) attribute of the
    /// [optional header](ImageOptionalHeader32).
    fn align_to_section(&self, rva: RVA) -> Result<RVA, Error> {
        let alignment = match self.get_valid_nt_headers() {
            Ok(h) => match h {
                NTHeaders::NTHeaders32(h32) => h32.optional_header.section_alignment,
                NTHeaders::NTHeaders64(h64) => h64.optional_header.section_alignment,
            },
            Err(e) => return Err(e),
        };

        Ok(RVA(align(rva.0, alignment)))
    }

    /// Convert an offset to an RVA address. Produces [`Error::InvalidRVA`](Error::InvalidRVA) if the produced
    /// RVA is invalid or if the section it was transposed from no longer contains it.
    fn offset_to_rva(&self, offset: Offset) -> Result<RVA, Error> {
        if !self.validate_offset(offset) {
            return Err(Error::InvalidOffset(offset));
        }
        
        let section = match self.get_section_by_offset(offset) {
            Ok(s) => s,
            Err(e) => {
                if let Error::SectionNotFound = e { () } else { return Err(Error::from(e)); }
                
                if !self.validate_rva(RVA(offset.0)) {
                    return Err(Error::InvalidRVA(RVA(offset.0)));
                }

                return Ok(RVA(offset.0));
            }
        };

        let mut rva = offset.0;
        rva -= section.pointer_to_raw_data.0;
        rva += section.virtual_address.0;

        let final_rva = RVA(rva);

        if !self.validate_rva(final_rva) || !section.has_rva(final_rva) {
            return Err(Error::InvalidRVA(final_rva));
        }

        Ok(RVA(rva))
    }
    /// Convert an offset to a VA address.
    fn offset_to_va(&self, offset: Offset) -> Result<VA, Error> {
        if !self.validate_offset(offset) {
            return Err(Error::InvalidOffset(offset));
        }

        let rva = match self.offset_to_rva(offset) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        self.rva_to_va(rva)
    }

    /// Convert an RVA to an offset address. Produces a [`Error::InvalidOffset`](Error::InvalidOffset) error if
    /// the produced offset is invalid or if the section it was transposed from no longer contains it.
    fn rva_to_offset(&self, rva: RVA) -> Result<Offset, Error> {
        if !self.validate_rva(rva) {
            return Err(Error::InvalidRVA(rva));
        }

        let section = match self.get_section_by_rva(rva) {
            Ok(s) => s,
            Err(e) => {
                if let Error::SectionNotFound = e { () } else { return Err(Error::from(e)); }

                if !self.validate_offset(Offset(rva.0)) {
                    return Err(Error::InvalidOffset(Offset(rva.0)));
                }

                return Ok(Offset(rva.0));
            }
        };

        let mut offset = rva.0;
        offset -= section.virtual_address.0;
        offset += section.pointer_to_raw_data.0;

        let final_offset = Offset(offset);

        if !self.validate_offset(final_offset) || !section.has_offset(final_offset) {
            return Err(Error::InvalidOffset(final_offset));
        }

        Ok(Offset(offset))
    }
    /// Convert an RVA to a VA address. Produces a [`Error::InvalidVA`](Error::InvalidVA) error if the produced
    /// VA is invalid.
    fn rva_to_va(&self, rva: RVA) -> Result<VA, Error> {
        if !self.validate_rva(rva) {
            return Err(Error::InvalidRVA(rva));
        }

        let image_base = match self.get_image_base() {
            Ok(i) => i,
            Err(e) => return Err(e),
        };

        let arch = match self.get_arch() {
            Ok(a) => a,
            Err(e) => return Err(e),
        };

        let va = match arch {
            Arch::X86 => VA::VA32(VA32(rva.0 + (image_base as u32))),
            Arch::X64 => VA::VA64(VA64((rva.0 as u64) + image_base)),
        };

        if !self.validate_va(va) {
            return Err(Error::InvalidVA(va));
        }

        Ok(va)
    }

    /// Convert a VA to an RVA. Produces a [`Error::InvalidRVA`](Error::InvalidRVA) error if the produced RVA
    /// is invalid.
    fn va_to_rva(&self, va: VA) -> Result<RVA, Error> {
        if !self.validate_va(va) {
            return Err(Error::InvalidVA(va));
        }

        let image_base = self.get_image_base()?;
        
        let rva = match va {
            VA::VA32(v32) => RVA(( (v32.0 as u64) - image_base ) as u32),
            VA::VA64(v64) => RVA(( v64.0 - image_base ) as u32),
        };

        if !self.validate_rva(rva) {
            return Err(Error::InvalidRVA(rva));
        }

        Ok(rva)
    }
    /// Converts a VA to an offset.
    fn va_to_offset(&self, va: VA) -> Result<Offset, Error> {
        if !self.validate_va(va) {
            return Err(Error::InvalidVA(va));
        }

        let rva = self.va_to_rva(va)?;
        self.rva_to_offset(rva)
    }

    /// Get an [`RVA`](RVA) object relative to the resource directory.
    ///
    /// This is useful for gathering addresses when parsing the resource directory. Returns [`Error::OutOfBounds`](Error::OutOfBounds)
    /// if the offset doesn't fit in the resource directory.
    fn get_resource_address(&self, offset: ResourceOffset) -> Result<RVA, Error> {
        let dir = self.get_data_directory(ImageDirectoryEntry::Resource)?;

        if offset.0 > dir.size {
            return Err(Error::OutOfBounds(dir.size as usize, offset.0 as usize));
        }

        if dir.virtual_address.0 == 0 || !self.validate_rva(dir.virtual_address) {
            return Err(Error::InvalidRVA(dir.virtual_address));
        }

        Ok(RVA(dir.virtual_address.0 + offset.0))
    }

    /// Calculates the size of the image headers.
    fn calculate_header_size(&self) -> Result<usize, Error> {
        let mut header_size = 0usize;
        let e_lfanew = self.e_lfanew()?;

        header_size = cmp::max(e_lfanew.into(), header_size);

        let data_dir_offset = self.get_data_directory_offset()?;
        
        header_size = cmp::max(data_dir_offset.into(), header_size);

        let data_dir_size = self.get_data_directory_size()?;

        header_size += data_dir_size * mem::size_of::<ImageDataDirectory>();

        let section_offset = self.get_section_table_offset()?;

        header_size = cmp::max(section_offset.into(), header_size);

        let section_table = self.get_section_table()?;

        header_size += section_table.len() * mem::size_of::<ImageSectionHeader>();

        Ok(header_size)
    }

    /// Calculate the size of the image as it appears on disk. Note that if there is appended data at the end of the file,
    /// it will not be factored in.
    fn calculate_disk_size(&self) -> Result<usize, Error> {
        let mut disk_size = self.calculate_header_size()?;
        let section_table = self.get_section_table()?;
        
        for section in section_table {
            let section_end = (section.pointer_to_raw_data.0 as usize) + (section.size_of_raw_data as usize);

            disk_size = cmp::max(section_end, disk_size);
        }

        Ok(disk_size)
    }

    /// Calculate the size of the image as it appears in memory.
    fn calculate_memory_size(&self) -> Result<usize, Error> {
        let mut memory_size = self.calculate_header_size()?;
        let section_table = self.get_section_table()?;
        
        for section in section_table {
            let section_end = (section.virtual_address.0 as usize) + (section.virtual_size as usize);

            memory_size = cmp::max(section_end, memory_size);
        }

        let alignment = match self.get_valid_nt_headers() {
            Ok(h) => match h {
                NTHeaders::NTHeaders32(h32) => h32.optional_header.section_alignment as usize,
                NTHeaders::NTHeaders64(h64) => h64.optional_header.section_alignment as usize,
            }
            Err(e) => return Err(e),
        };

        if memory_size % alignment != 0 {
            memory_size += alignment - (memory_size % alignment);
        }

        Ok(memory_size)
    }

    /// Calculate the imphash of the PE file.
    fn calculate_imphash(&self) -> Result<Vec<u8>, Error> {
        let import_directory = ImportDirectory::parse(self)?;
        let mut imphash_results = Vec::<String>::new();

        for import in import_directory.descriptors {
            let dll_name = match import.get_name(self) {
                Ok(n) => match n.as_str() {
                    Ok(s) => s.to_string().to_ascii_lowercase(),
                    Err(e) => return Err(e),
                },
                Err(e) => return Err(e),
            };

            let mut imphash_dll_name = dll_name.clone();
            let extensions = &["ocx", "sys", "dll"];

            let name_chunks: Vec<String> = dll_name.as_str()
                .rsplitn(2, '.')
                .map(|x| x.to_string())
                .collect();

            if name_chunks.len() > 1 && extensions.contains(&name_chunks[0].as_str()) {
                imphash_dll_name = name_chunks[1].clone();
            }

            let import_entries = import.get_imports(self)?;
            for import_data in import_entries {
                let import_name = match import_data {
                    ImportData::Ordinal(x) => imphash_resolve(dll_name.as_str(), x).to_ascii_lowercase(),
                    ImportData::ImportByName(s) => s.to_string().to_ascii_lowercase(),
                };

                let mut imphash_name = String::new();
                imphash_name.push_str(imphash_dll_name.as_str());
                imphash_name.push('.');
                imphash_name.push_str(import_name.as_str());

                imphash_results.push(imphash_name.clone());
            }
        }

        Ok(imphash_results.join(",").as_str().as_bytes().md5())
    }

    /// Creates a new vector representing either what the image looks like on disk (i.e., a [`PEType::Disk`](PEType::Disk) image)
    /// or what the image looks like in memory (i.e., a [`PEType::Memory`](PEType::Memory) image).
    ///
    /// Note that for [`Memory`](PEType::Memory) images, it does not use [`caluclate_memory_size`](PE::calculate_memory_size).
    /// It rather relies on the [`size_of_image`](ImageOptionalHeader32::size_of_image) field, as that's what the loader does.
    fn recreate_image(&self, pe_type: PEType) -> Result<Vec<u8>, Error> {
        let buffer_size = match pe_type {
            PEType::Disk => match self.calculate_disk_size() {
                Ok(s) => s,
                Err(e) => return Err(e),
            },
            PEType::Memory => match self.get_valid_nt_headers() {
                Ok(h) => {
                    let (mut image_size, alignment) = match h {
                        NTHeaders::NTHeaders32(h32) => (h32.optional_header.size_of_image as usize, h32.optional_header.section_alignment as usize),
                        NTHeaders::NTHeaders64(h64) => (h64.optional_header.size_of_image as usize, h64.optional_header.section_alignment as usize),
                    };

                    if image_size % alignment != 0 {
                        image_size += alignment - (image_size % alignment);
                    }

                    image_size
                },
                Err(e) => return Err(e),
            }
        };

        let mut buffer = VecBuffer::with_initial_size(buffer_size);
        let header_size = self.calculate_header_size()?;
        let header_data = self.read(0, header_size)?;
        buffer.write(0, header_data)?;

        let section_table = self.get_section_table()?;
        
        for section in section_table {
            let section_data = section.read(self)?;

            let section_size = match pe_type {
                PEType::Disk => section.size_of_raw_data as usize,
                PEType::Memory => section.virtual_size as usize,
            };
            
            let data_size = section_data.len();
            let written_size;

            if section_size > data_size {
                written_size = data_size
            }
            else {
                written_size = section_size
            }

            let buffer_offset = match pe_type {
                PEType::Disk => section.pointer_to_raw_data,
                PEType::Memory => Offset(section.virtual_address.0),
            };

            buffer.write(buffer_offset.into(), &section_data[..written_size])?;
        }

        Ok(buffer.to_vec())
    }
    /// Recalculate the `PE`'s memory size with [`calculate_memory_size`](PE::calculate_memory_size) and set this value as the
    /// header's [`size_of_image`](ImageOptionalHeader32::size_of_image) value.
    fn fix_image_size(&mut self) -> Result<(), Error> {
        let image_size = self.calculate_memory_size()?;
        
        match self.get_valid_mut_nt_headers() {
            Ok(ref mut h) => match h {
                NTHeadersMut::NTHeaders32(ref mut h32) => h32.optional_header.size_of_image = image_size as u32,
                NTHeadersMut::NTHeaders64(ref mut h64) => h64.optional_header.size_of_image = image_size as u32,
            },
            Err(e) => return Err(e),
        }

        Ok(())
    }
}

/// Represents [`PE`](PE) data that's sitting behind a pointer/size pair.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct PtrPE {
    pe_type: PEType,
    buffer: PtrBuffer,
}
impl PtrPE {
    /// Generates a new `PtrPE` object from a pointer/size pair.
    pub fn new(pe_type: PEType, pointer: *const u8, size: usize) -> Self {
        Self {
            pe_type: pe_type,
            buffer: PtrBuffer::new(pointer, size),
        }
    }
    /// Generates a new `PtrPE` object from the pointer/size pair, marking it as a [`Disk`](PEType::Disk) image.
    pub fn new_disk(pointer: *const u8, size: usize) -> Self {
        Self::new(PEType::Disk, pointer, size)
    }
    /// Generates a new `PtrPE` object from the data slice, marking it as a [`Memory`](PEType::Memory) image.
    pub fn new_memory(pointer: *const u8, size: usize) -> Self {
        Self::new(PEType::Memory, pointer, size)
    }
    /// Generates a new [`Memory`](PEType::Memory) `PtrPE` object from a pointer to memory.
    ///
    /// Because of the nature of verifying the given pointer is a PE image, this function also parses the image and verifies it.
    pub unsafe fn from_memory(ptr: *const u8) -> Result<Self, Error> {
        let dos_header = &*(ptr as *const ImageDOSHeader);

        if dos_header.e_magic != DOS_SIGNATURE {
            return Err(Error::InvalidDOSSignature(dos_header.e_magic));
        }

        let nt_header = &*(ptr.add(dos_header.e_lfanew.0 as usize) as *const ImageNTHeaders32);

        if nt_header.signature != NT_SIGNATURE {
            return Err(Error::InvalidPESignature(nt_header.signature));
        }

        let image_size;

        if nt_header.optional_header.magic == HDR32_MAGIC {
            image_size = nt_header.optional_header.size_of_image as usize;
        }
        else if nt_header.optional_header.magic == HDR64_MAGIC {
            let nt_header_64 = &*(ptr.add(dos_header.e_lfanew.0 as usize) as *const ImageNTHeaders64);
            image_size = nt_header_64.optional_header.size_of_image as usize;
        }
        else {
            return Err(Error::InvalidNTSignature(nt_header.optional_header.magic));
        }

        Ok(Self::new_memory(ptr, image_size))
    }

    /// Turn the `PtrPE` object into an owned [`VecPE`](VecPE) object.
    pub fn to_vecpe(&self) -> VecPE {
        VecPE::from_data(self.pe_type, self.as_slice())
    }

    /// Get the underlying [`PtrBuffer`](PtrBuffer) object.
    pub fn get_buffer(&self) -> &PtrBuffer {
        &self.buffer
    }

    /// Get a mutable reference to the underlying [`PtrBuffer`](PtrBuffer) object.
    pub fn get_mut_buffer(&mut self) -> &mut PtrBuffer {
        &mut self.buffer
    }
}
impl PE for PtrPE {
    /// Get the [`PEType`](PEType) this PE represents.
    fn get_type(&self) -> PEType { self.pe_type }
    /// Only for Windows. Check if this [`PE`](PE) object is allocated. `PtrPE` is never
    /// allocated, so this function always returns false.
    #[cfg(feature="win32")]
    fn is_allocated(&self) -> bool { false }
}
impl Buffer for PtrPE {
    fn len(&self) -> usize { self.buffer.len() }
    fn as_ptr(&self) -> *const u8 { self.buffer.as_ptr() }
    fn as_mut_ptr(&mut self) -> *mut u8 { self.buffer.as_mut_ptr() }
    fn as_slice(&self) -> &[u8] { self.buffer.as_slice() }
    fn as_mut_slice(&mut self) -> &mut [u8] { self.buffer.as_mut_slice() }
}
impl<Idx: slice::SliceIndex<[u8]>> Index<Idx> for PtrPE {
    type Output = Idx::Output;

    fn index(&self, index: Idx) -> &Self::Output {
        self.as_slice().index(index)
    }
}
impl<Idx: slice::SliceIndex<[u8]>> IndexMut<Idx> for PtrPE {
    fn index_mut(&mut self, index: Idx) -> &mut Self::Output {
        self.as_mut_slice().index_mut(index)
    }
}

/// Represents a [`PE`](PE) object with owned data.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct VecPE {
    pe_type: PEType,
    buffer: VecBuffer,
}
impl VecPE {
    /// Creates a new `VecPE` object with a mutable [`PE`](PE) object, initializing a backing buffer with the given size.
    pub fn new(pe_type: PEType, size: usize) -> Self {
        let buffer = VecBuffer::with_initial_size(size);

        Self { pe_type, buffer }
    }
    /// Creates a new `VecPE` as type [`Disk`](PEType::Disk), initializing a vector of the given size.
    pub fn new_disk(size: usize) -> Self {
        Self::new(PEType::Disk, size)
    }
    /// Creates a new `VecPE` as type [`Memory`](PEType::Memory), initializing a vector of the given size.
    pub fn new_memory(size: usize) -> Self {
        Self::new(PEType::Memory, size)
    }
    /// Creates a new `VecPE` object with the given file's data.
    pub fn from_file<P: AsRef<Path>>(pe_type: PEType, filename: P) -> Result<Self, Error> {
        let buffer = VecBuffer::from_file(filename)?;

        Ok(Self { pe_type, buffer })
    }
    /// Creates a new `VecPE` object with the given file's data, marking it as a [`Disk`](PEType::Disk) image.
    pub fn from_disk_file<P: AsRef<Path>>(filename: P) -> Result<Self, Error> {
        Self::from_file(PEType::Disk, filename)
    }
    /// Creates a new `VecPE` object with the given file's data, marking it as a [`Memory`](PEType::Memory) image.
    pub fn from_memory_file<P: AsRef<Path>>(filename: P) -> Result<Self, Error> {
        Self::from_file(PEType::Memory, filename)
    }
    /// Creates a new `VecPE` object with the given data.
    pub fn from_data<B: AsRef<[u8]>>(pe_type: PEType, data: B) -> Self {
        let buffer = VecBuffer::from_data(data);

        Self { pe_type, buffer }
    }
    /// Creates a new `VecPE` object from the given slice object, marking it as a [`Disk`](PEType::Disk) image.
    pub fn from_disk_data<B: AsRef<[u8]>>(data: B) -> Self {
        Self::from_data(PEType::Disk, data)
    }
    /// Creates a new `VecPE` object from the given slice object, marking it as a [`Memory`](PEType::Memory) image.
    pub fn from_memory_data<B: AsRef<[u8]>>(data: B) -> Self {
        Self::from_data(PEType::Memory, data)
    }
    /// Creates a new `VecPE` object from a buffer of assembly. Useful for converting shellcode into a binary.
    ///
    /// Returns [`InvalidOffset`](Error::InvalidOffset) if the offset given doesn't point at code.
    pub fn from_assembly<B: AsRef<[u8]>>(arch: Arch, asm_ref: B, entrypoint: Offset) -> Result<Self, Error> {
        let asm_data = asm_ref.as_ref();
        let mut result = Self::new_disk(0x400);

        result.write_ref(0, &ImageDOSHeader::default())?;
        
        let e_lfanew = result.e_lfanew()?;
        
        match arch {
            Arch::X86 => result.write_ref(e_lfanew.into(), &ImageNTHeaders32::default())?,
            Arch::X64 => result.write_ref(e_lfanew.into(), &ImageNTHeaders64::default())?,
        }

        let mut new_section = ImageSectionHeader::default();
        new_section.set_name(Some(".text"));

        let mut appended_section = result.append_section(&new_section)?; 
        
        appended_section.size_of_raw_data = asm_data.len() as u32;
        appended_section.virtual_size = appended_section.size_of_raw_data;
        appended_section.characteristics = SectionCharacteristics::MEM_EXECUTE
            | SectionCharacteristics::MEM_READ
            | SectionCharacteristics::CNT_CODE;

        let new_entrypoint = RVA(entrypoint.0 + appended_section.virtual_address.0);

        result.fix_image_size()?;
        
        if !result.validate_rva(new_entrypoint) {
            return Err(Error::InvalidOffset(entrypoint));
        }

        result.append(asm_data);

        match result.get_valid_mut_nt_headers() {
            Ok(ref mut h) => match h {
                NTHeadersMut::NTHeaders32(ref mut h32) => h32.optional_header.address_of_entry_point = new_entrypoint,
                NTHeadersMut::NTHeaders64(ref mut h64) => h64.optional_header.address_of_entry_point = new_entrypoint,
            },
            Err(e) => return Err(e),
        }

        Ok(result)
    }

    /// Get a [`PtrPE`](PtrPE) object representing the PE data in this buffer.
    pub fn as_ptr_pe(&self) -> PtrPE {
        PtrPE::new(self.pe_type, self.as_ptr(), self.len())
    }

    /// Get the underlying [`VecBuffer`](VecBuffer) object.
    pub fn get_buffer(&self) -> &VecBuffer {
        &self.buffer
    }

    /// Get a mutable reference to the underlying [`VecBuffer`](VecBuffer) object.
    pub fn get_mut_buffer(&mut self) -> &mut VecBuffer {
        &mut self.buffer
    }

    /// Appends the given data to the end of the `VecPE` object. See [`VecBuffer::append`](VecBuffer::append).
    pub fn append<B: AsRef<[u8]>>(&mut self, data: B) {
        self.buffer.append(data);
    }
    /// Appends the given reference to the end of the `VecPE` object. See [`VecBuffer::append_ref`](VecBuffer::append_ref).
    pub fn append_ref<T: Castable>(&mut self, data: &T) -> Result<(), Error> {
        self.buffer.append_ref(data)?; Ok(())
    }
    /// Appends the given slice reference to the end of the `VecPE` object. See [`VecBuffer::append_slice_ref`](VecBuffer::append_slice_ref).
    pub fn append_slice_ref<T: Castable>(&mut self, data: &[T]) -> Result<(), Error> {
        self.buffer.append_slice_ref(data)?; Ok(())
    }
    /// Insert a byte at the given offset. See [`VecBuffer::insert`](VecBuffer::insert).
    pub fn insert(&mut self, offset: usize, element: u8) {
        self.buffer.insert(offset, element);
    }
    /// Remove a byte at the given offset. See [`VecBuffer::remove`](VecBuffer::remove).
    pub fn remove(&mut self, offset: usize) {
        self.buffer.remove(offset);
    }
    /// Push a byte onto the end of the `VecPE` buffer. See [`VecBuffer::push`](VecBuffer::push).
    pub fn push(&mut self, byte: u8) {
        self.buffer.push(byte);
    }
    /// Pop a byte from the end of the `VecPE` buffer. See [`VecBuffer::pop`](VecBuffer::pop).
    pub fn pop(&mut self) -> Option<u8> {
        self.buffer.pop()
    }
    /// Clear the `VecPE` buffer. See [`VecBuffer::clear`](VecBuffer::clear).
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
    /// Resize the buffer and fill with the given closure. See [`VecBuffer::resize_with`](VecBuffer::resize_with).
    pub fn resize_with<F>(&mut self, new_len: usize, f: F)
    where
        F: FnMut() -> u8,
    {
        self.buffer.resize_with(new_len, f);
    }
    /// Resize the given `VecPE` buffer. See [`VecBuffer::resize`](VecBuffer::resize).
    pub fn resize(&mut self, new_len: usize, value: u8) {
        self.buffer.resize(new_len, value);
    }
    /// Truncate the given `VecPE` buffer. See [`VecBuffer::truncate`](VecBuffer::truncate).
    pub fn truncate(&mut self, len: usize) {
        self.buffer.truncate(len);
    }
    
    /// Pad the backing vector with `0` to the [`PE`](PE)'s [`file_alignment`](ImageOptionalHeader32::file_alignment) specification.
    pub fn pad_to_file_alignment(&mut self) -> Result<(), Error> {
        let current_offset = Offset(self.len() as u32);
        let aligned_offset = self.align_to_file(current_offset)?;
        let padding = aligned_offset.0 - current_offset.0;

        if padding != 0 { self.append(&vec![0u8; padding as usize]); }

        Ok(())
    }
    /// Pad the backing vector with `0` to the [`PE`](PE)'s [`section_alignment`](ImageOptionalHeader32::section_alignment) specification.
    pub fn pad_to_section_alignment(&mut self) -> Result<(), Error> {
        let current_rva = RVA(self.len() as u32);
        let aligned_rva = self.align_to_section(current_rva)?;
        let padding = aligned_rva.0 - current_rva.0;

        if padding != 0 { self.append(&vec![0u8; padding as usize]); }

        Ok(())
    }
    /// Pad with `0` to either [`file_alignment`](ImageOptionalHeader32::file_alignment) or
    /// [`section_alignment`](ImageOptionalHeader32::section_alignment), depending on what the [`PEType`](PEType) of the image is.
    pub fn pad_to_alignment(&mut self) -> Result<(), Error> {
        match self.pe_type {
            PEType::Disk => self.pad_to_file_alignment(),
            PEType::Memory => self.pad_to_section_alignment(),
        }
    }
}
impl PE for VecPE {
    fn get_type(&self) -> PEType { self.pe_type }
    #[cfg(feature="win32")]
    fn is_allocated(&self) -> bool { false }
}
impl Buffer for VecPE {
    fn len(&self) -> usize { self.buffer.len() }
    fn as_ptr(&self) -> *const u8 { self.buffer.as_ptr() }
    fn as_mut_ptr(&mut self) -> *mut u8 { self.buffer.as_mut_ptr() }
    fn as_slice(&self) -> &[u8] { self.buffer.as_slice() }
    fn as_mut_slice(&mut self) -> &mut [u8] { self.buffer.as_mut_slice() }
}
impl<Idx: slice::SliceIndex<[u8]>> Index<Idx> for VecPE {
    type Output = Idx::Output;

    fn index(&self, index: Idx) -> &Self::Output {
        self.as_slice().index(index)
    }
}
impl<Idx: slice::SliceIndex<[u8]>> IndexMut<Idx> for VecPE {
    fn index_mut(&mut self, index: Idx) -> &mut Self::Output {
        self.as_mut_slice().index_mut(index)
    }
}
