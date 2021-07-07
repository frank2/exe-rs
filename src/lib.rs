pub mod buffer;
pub mod types;

#[cfg(test)]
mod tests;

use std::io::{Error as IoError};
use std::mem::size_of;

use crate::buffer::Buffer;
use crate::types::*;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Error {
    BufferTooSmall,
    InvalidDOSSignature,
    InvalidPESignature,
    InvalidNTSignature,
    InvalidOffset,
    InvalidRVA,
    InvalidVA,
    SectionNotFound,
}

pub enum NTHeaders<'data> {
    NTHeaders32(&'data ImageNTHeaders32),
    NTHeaders64(&'data ImageNTHeaders64),
}

pub enum NTHeadersMut<'data> {
    NTHeaders32(&'data mut ImageNTHeaders32),
    NTHeaders64(&'data mut ImageNTHeaders64),
}

pub struct PE {
    pub buffer: Buffer,
    /* pub virtual: Option<Buffer> */
    pub filename: Option<String>,
}
impl PE {
    pub fn new() -> Self {
        Self {
            buffer: Buffer::new(),
            filename: None,
        }
    }
    pub fn from_data(data: &[u8]) -> Self {
        Self {
            buffer: Buffer::from_data(data),
            filename: None,
        }
    }
    pub fn from_file(filename: &str) -> Result<Self, IoError> {
        match Buffer::from_file(filename) {
            Ok(buffer) => Ok(Self { buffer: buffer, filename: Some(String::from(filename)) }),
            Err(e) => Err(e),
        }
    }

    pub fn get_dos_header(&self) -> Result<&ImageDOSHeader, Error> {
        let dos_header = self.buffer.get_ref::<ImageDOSHeader>(Offset(0));

        if dos_header.is_err() {
            return Err(Error::BufferTooSmall);
        }

        Ok(dos_header.unwrap())
    }
    pub fn get_mut_dos_header(&mut self) -> Result<&mut ImageDOSHeader, Error> {
        let dos_header = self.buffer.get_mut_ref::<ImageDOSHeader>(Offset(0));

        if dos_header.is_err() {
            return Err(Error::BufferTooSmall);
        }

        Ok(dos_header.unwrap())
    }
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
    pub fn get_valid_mut_dos_header(&mut self) -> Result<&ImageDOSHeader, Error> {
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
    
    pub fn get_nt_headers_32(&self) -> Result<&ImageNTHeaders32, Error> {
        let e_lfanew = match self.e_lfanew() {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        let nt_headers = self.buffer.get_ref::<ImageNTHeaders32>(e_lfanew);

        match nt_headers {
            Ok(h) => Ok(h),
            Err(_) => Err(Error::BufferTooSmall),
        }
    }
    pub fn get_mut_nt_headers_32(&mut self) -> Result<&mut ImageNTHeaders32, Error> {
        let e_lfanew = match self.e_lfanew() {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        let nt_headers = self.buffer.get_mut_ref::<ImageNTHeaders32>(e_lfanew);

        match nt_headers {
            Ok(h) => Ok(h),
            Err(_) => Err(Error::BufferTooSmall),
        }
    }
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
    pub fn get_nt_headers_64(&self) -> Result<&ImageNTHeaders64, Error> {
        let e_lfanew = match self.e_lfanew() {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        let nt_headers = self.buffer.get_ref::<ImageNTHeaders64>(e_lfanew);

        match nt_headers {
            Ok(h) => Ok(h),
            Err(_) => Err(Error::BufferTooSmall),
        }
    }
    pub fn get_mut_nt_headers_64(&mut self) -> Result<&mut ImageNTHeaders64, Error> {
        let e_lfanew = match self.e_lfanew() {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        let nt_headers = self.buffer.get_mut_ref::<ImageNTHeaders64>(e_lfanew);

        match nt_headers {
            Ok(h) => Ok(h),
            Err(_) => Err(Error::BufferTooSmall),
        }
    }
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
        offset += size_of::<ImageFileHeader>() as u32;
        offset += size_of_optional as u32;

        if offset as usize > self.buffer.len() {
            return Err(Error::BufferTooSmall);
        }

        Ok(Offset(offset))
    }
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

        match self.buffer.get_slice_ref::<ImageSectionHeader>(offset, sections as usize) {
            Ok(s) => Ok(s),
            Err(_) => Err(Error::BufferTooSmall),
        }
    }
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

        match self.buffer.get_mut_slice_ref::<ImageSectionHeader>(offset, sections as usize) {
            Ok(s) => Ok(s),
            Err(_) => Err(Error::BufferTooSmall),
        }
    }
    
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
    pub fn get_mut_section_by_rva(&mut self, rva: RVA) -> Result<&ImageSectionHeader, Error> {
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
    pub fn get_section_by_name(&self, name: String) -> Result<&ImageSectionHeader, Error> {
        let sections = match self.get_section_table() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let s = name.as_str();

        for section in sections {
            if section.name.as_os_str() == s {
                return Ok(section);
            }
        }

        Err(Error::SectionNotFound)
    }
    pub fn get_mut_section_by_name(&mut self, name: String) -> Result<&mut ImageSectionHeader, Error> {
        let sections = match self.get_mut_section_table() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let s = name.as_str();
        
        for section in sections {
            if section.name.as_os_str() == s {
                return Ok(section);
            }
        }

        Err(Error::SectionNotFound)
    }

    pub fn validate_offset(&self, offset: Offset) -> bool {
        (offset.0 as usize) < self.buffer.len()
    }
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
    pub fn validate_va(&self, va: VA) -> bool {
        let headers = match self.get_valid_nt_headers() {
            Ok(h) => h,
            Err(_) => return false,
        };
        let image_size = match headers {
            NTHeaders::NTHeaders32(h32) => h32.optional_header.size_of_image as usize,
            NTHeaders::NTHeaders64(h64) => h64.optional_header.size_of_image as usize,
        };
        let image_base = match headers {
            NTHeaders::NTHeaders32(h32) => h32.optional_header.image_base as usize,
            NTHeaders::NTHeaders64(h64) => h64.optional_header.image_base as usize,
        };

        let start = image_base;
        let end = start + image_size;

        match va {
            VA::VA32(v32) => start <= (v32.0 as usize) && (v32.0 as usize) < end,
            VA::VA64(v64) => start <= (v64.0 as usize) && (v64.0 as usize) < end,
        }
    }

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
    pub fn offset_to_va(&self, offset: Offset) -> Result<VA, Error> {
        let rva = match self.offset_to_rva(offset) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        self.rva_to_va(rva)
    }
    
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
    pub fn va_to_offset(&self, va: VA) -> Result<Offset, Error> {
        let rva = match self.va_to_rva(va) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        self.rva_to_offset(rva)
    }
}
