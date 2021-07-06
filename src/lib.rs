pub mod buffer;
pub mod types;

#[cfg(test)]
mod tests;

use std::io::{Error as IoError};
use std::mem::size_of;
use std::path::Path;

use crate::buffer::PEBuffer;
use crate::types::*;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Error {
    BufferTooSmall,
    InvalidDOSSignature,
    InvalidPESignature,
    InvalidNTSignature,
    InvalidOffset,
    InvalidRVA,
}

pub struct PEFile {
    pub buffer: PEBuffer,
    pub filename: Option<String>,
}
impl PEFile {
    pub fn new() -> Self {
        Self {
            buffer: PEBuffer::new(),
            filename: None,
        }
    }
    pub fn from_data(data: &[u8]) -> Self {
        Self {
            buffer: PEBuffer::from_data(data),
            filename: None,
        }
    }
    pub fn from_file(filename: &str) -> Result<Self, IoError> {
        match PEBuffer::from_file(filename) {
            Ok(buffer) => Ok(Self { buffer: buffer, filename: Some(String::from(filename)) }),
            Err(e) => Err(e),
        }
    }

    pub fn get_dos_header(&self) -> Result<&DOSHeader, Error> {
        let dos_header = self.buffer.get_ref::<DOSHeader>(Offset(0));

        if dos_header.is_err() {
            return Err(Error::BufferTooSmall);
        }

        Ok(dos_header.unwrap())
    }
    pub fn get_mut_dos_header(&mut self) -> Result<&mut DOSHeader, Error> {
        let dos_header = self.buffer.get_mut_ref::<DOSHeader>(Offset(0));

        if dos_header.is_err() {
            return Err(Error::BufferTooSmall);
        }

        Ok(dos_header.unwrap())
    }
    pub fn get_valid_dos_header(&self) -> Result<&DOSHeader, Error> {
        let dos_header = match self.get_dos_header() {
            Ok(h) => h,
            Err(e) => return Err(e),
        };

        if dos_header.e_magic != DOS_SIGNATURE {
            return Err(Error::InvalidDOSSignature);
        }

        Ok(dos_header)
    }
    pub fn get_valid_mut_dos_header(&mut self) -> Result<&DOSHeader, Error> {
        let dos_header = match self.get_mut_dos_header() {
            Ok(h) => h,
            Err(e) => return Err(e),
        };

        if dos_header.e_magic != DOS_SIGNATURE {
            return Err(Error::InvalidDOSSignature);
        }

        Ok(dos_header)
    }
    pub fn e_lfanew(&self) -> Result<Offset, Error> {
        match self.get_valid_dos_header() {
            Ok(h) => Ok(h.e_lfanew),
            Err(e) => Err(e)
        }
    }
    
    pub fn get_nt_headers_32(&self) -> Result<&NTHeaders32, Error> {
        let e_lfanew = match self.e_lfanew() {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        let nt_headers = self.buffer.get_ref::<NTHeaders32>(e_lfanew);

        match nt_headers {
            Ok(h) => Ok(h),
            Err(_) => Err(Error::BufferTooSmall),
        }
    }
    pub fn get_mut_nt_headers_32(&mut self) -> Result<&mut NTHeaders32, Error> {
        let e_lfanew = match self.e_lfanew() {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        let nt_headers = self.buffer.get_mut_ref::<NTHeaders32>(e_lfanew);

        match nt_headers {
            Ok(h) => Ok(h),
            Err(_) => Err(Error::BufferTooSmall),
        }
    }
    pub fn get_valid_nt_headers_32(&self) -> Result<&NTHeaders32, Error> {
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
    pub fn get_valid_mut_nt_headers_32(&mut self) -> Result<&mut NTHeaders32, Error> {
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
    pub fn get_nt_headers_64(&self) -> Result<&NTHeaders64, Error> {
        let e_lfanew = match self.e_lfanew() {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        let nt_headers = self.buffer.get_ref::<NTHeaders64>(e_lfanew);

        match nt_headers {
            Ok(h) => Ok(h),
            Err(_) => Err(Error::BufferTooSmall),
        }
    }
    pub fn get_mut_nt_headers_64(&mut self) -> Result<&mut NTHeaders64, Error> {
        let e_lfanew = match self.e_lfanew() {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        let nt_headers = self.buffer.get_mut_ref::<NTHeaders64>(e_lfanew);

        match nt_headers {
            Ok(h) => Ok(h),
            Err(_) => Err(Error::BufferTooSmall),
        }
    }
    pub fn get_valid_nt_headers_64(&self) -> Result<&NTHeaders64, Error> {
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
    pub fn get_valid_mut_nt_headers_64(&mut self) -> Result<&mut NTHeaders64, Error> {
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
    pub fn get_nt_magic(&self) -> Result<u16, Error> {
        match self.get_nt_headers_32() {
            Ok(h) => Ok(h.optional_header.magic),
            Err(e) => Err(e),
        }
    }
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
        offset += size_of::<FileHeader>() as u32;
        offset += size_of_optional as u32;

        if offset as usize > self.buffer.len() {
            return Err(Error::BufferTooSmall);
        }

        Ok(Offset(offset))
    }
    pub fn get_section_table(&self) -> Result<&[SectionHeader], Error> {
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

        match self.buffer.get_slice_ref::<SectionHeader>(offset, sections as usize) {
            Ok(s) => Ok(s),
            Err(_) => Err(Error::BufferTooSmall),
        }
    }
    pub fn get_mut_section_table(&mut self) -> Result<&mut [SectionHeader], Error> {
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

        match self.buffer.get_mut_slice_ref::<SectionHeader>(offset, sections as usize) {
            Ok(s) => Ok(s),
            Err(_) => Err(Error::BufferTooSmall),
        }
    }
}
