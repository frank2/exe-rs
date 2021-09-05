//! This module contains Rust types to help with the parsing of PE files.

use bitflags::bitflags;

use std::collections::HashMap;
use std::mem;
use std::slice;

use widestring::U16Str;

use crate::*;
use crate::headers::*;
use crate::buffer::align;

/// Represents the architecture of the PE image.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Arch {
    X86,
    X64,
}

/// Represents a C-style character unit. Basically a wrapper for [`u8`](u8).
#[repr(C)]
#[derive(Copy, Clone, Default, Eq, PartialEq, Debug)]
pub struct CChar(pub u8);

/* borrowed from pe-rs */
/// Syntactic sugar to get functionality out of C-char referenced slices.
pub trait CCharString {
    /// Get the zero-terminated representation of this string, or [`None`](None) if it is not zero-terminated.
    fn zero_terminated(&self) -> Option<&Self>;
    /// Get the string slice as a [`&str`](str).
    fn as_str(&self) -> &str;
}
impl CCharString for [CChar] {
    fn zero_terminated(&self) -> Option<&Self> {
        self.iter()
            .position(|&CChar(x)| x == 0)
            .map(|p| &self[..p])
    }
    fn as_str(&self) -> &str {
        let cstr = self.zero_terminated().unwrap_or(&self);

        unsafe { mem::transmute::<&[CChar],&str>(cstr) }
    }
}

/// Represents a UTF16 character unit. Basically a wrapper for [`u16`](u16).
#[repr(C)]
#[derive(Copy, Clone, Default, Eq, PartialEq, Debug)]
pub struct WChar(pub u16);

/// Syntactic sugar for dealing with UTF16 referenced slices.
pub trait WCharString {
    /// Get the zero-terminated representation of this string, or [`None`](None) if it is not zero-terminated.
    fn zero_terminated(&self) -> Option<&Self>;
    /// Get the string slice as a [`U16Str`](U16Str).
    fn as_u16_str(&self) -> &U16Str;
}
impl WCharString for [WChar] {
    fn zero_terminated(&self) -> Option<&Self> {
        self.iter()
            .position(|&WChar(x)| x == 0)
            .map(|p| &self[..p])
    }
    fn as_u16_str(&self) -> &U16Str {
        let u16str = self.zero_terminated().unwrap_or(&self);

        unsafe { mem::transmute::<&[WChar],&U16Str>(u16str) }
    }
}

/// Represents an object which could be considered an address in a PE file.
pub trait Address {
    /// Convert the address to an offset value.
    fn as_offset(&self, pe: &PE) -> Result<Offset, Error>;
    /// Convert the address to an RVA value.
    fn as_rva(&self, pe: &PE) -> Result<RVA, Error>;
    /// Convert the address to a VA value.
    fn as_va(&self, pe: &PE) -> Result<VA, Error>;
    /// Convert the address to a pointer.
    fn as_ptr(&self, pe: &PE) -> Result<*const u8, Error>;
}

/// Represents a file offset in the image. This typically represents an address of the file on disk versus the file in memory.
#[repr(C)]
#[derive(Copy, Clone, Default, Eq, PartialEq, Debug)]
pub struct Offset(pub u32);
impl Offset {
    /// Gets a reference to an object in the [`PE`](PE) object's buffer data. See [`Buffer::get_ref`](crate::buffer::Buffer::get_ref).
    pub fn get_ref<'data, T>(&self, pe: &'data PE) -> Result<&'data T, Error> {
        pe.buffer.get_ref::<T>(*self)
    }
    /// Gets a mutable reference to an object in the [`PE`](PE) object's buffer data. See [`Buffer::get_mut_ref`](crate::buffer::Buffer::get_mut_ref).
    pub fn get_mut_ref<'data, T>(&self, pe: &'data mut PE) -> Result<&'data mut T, Error> {
        pe.buffer.get_mut_ref::<T>(*self)
    }
    /// Gets a slice reference in the [`PE`](PE) buffer. See [`Buffer::get_slice_ref`](crate::buffer::Buffer::get_slice_ref).
    pub fn get_slice_ref<'data, T>(&self, pe: &'data PE, count: usize) -> Result<&'data [T], Error> {
        pe.buffer.get_slice_ref::<T>(*self, count)
    }
    /// Gets a mutable slice reference in the [`PE`](PE) buffer. See [`Buffer::get_mut_slice_ref`](crate::buffer::Buffer::get_mut_slice_ref).
    pub fn get_mut_slice_ref<'data, T>(&self, pe: &'data mut PE, count: usize) -> Result<&'data mut [T], Error> {
        pe.buffer.get_mut_slice_ref::<T>(*self, count)
    }
    /// Gets the size of a zero-terminated C-string in the data at the offset.
    pub fn get_cstring_size(&self, pe: &PE, thunk: bool, max_size: Option<usize>) -> Result<usize, Error> {
        pe.buffer.get_cstring_size(*self, thunk, max_size)
    }
    /// Gets the size of a zero-terminated UTF16 string in the data at the offset.
    pub fn get_widestring_size(&self, pe: &PE, max_size: Option<usize>) -> Result<usize, Error> {
        pe.buffer.get_widestring_size(*self, max_size)
    }
    /// Get a zero-terminated C-string from the data. See [`Buffer::get_cstring`](crate::buffer::Buffer::get_cstring).
    pub fn get_cstring<'data>(&self, pe: &'data PE, thunk: bool, max_size: Option<usize>) -> Result<&'data [CChar], Error> {
        pe.buffer.get_cstring(*self, thunk, max_size)
    }
    /// Get a mutable zero-terminated C-string from the data. See [`Buffer::get_mut_cstring`](crate::buffer::Buffer::get_mut_cstring).
    pub fn get_mut_cstring<'data>(&self, pe: &'data mut PE, thunk: bool, max_size: Option<usize>) -> Result<&'data mut [CChar], Error> {
        pe.buffer.get_mut_cstring(*self, thunk, max_size)
    }
    /// Get a zero-terminated C-string from the data. See [`Buffer::get_widestring`](crate::buffer::Buffer::get_widestring).
    pub fn get_widestring<'data>(&self, pe: &'data PE, max_size: Option<usize>) -> Result<&'data [WChar], Error> {
        pe.buffer.get_widestring(*self, max_size)
    }
    /// Get a mutable zero-terminated C-string from the data. See [`Buffer::get_mut_widestring`](crate::buffer::Buffer::get_mut_widestring).
    pub fn get_mut_widestring<'data>(&self, pe: &'data mut PE, max_size: Option<usize>) -> Result<&'data mut [WChar], Error> {
        pe.buffer.get_mut_widestring(*self, max_size)
    }
    /// Read arbitrary data from the offset.
    pub fn read<'data>(&self, pe: &'data PE, size: usize) -> Result<&'data [u8], Error> {
        pe.buffer.read(*self, size)
    }
    /// Read mutable arbitrary data from the offset.
    pub fn read_mut<'data>(&self, pe: &'data mut PE, size: usize) -> Result<&'data mut [u8], Error> {
        pe.buffer.read_mut(*self, size)
    }
    /// Write arbitrary data to the offset.
    pub fn write(&self, pe: &mut PE, data: &[u8]) -> Result<(), Error> {
        pe.buffer.write(*self, data)
    }
    /// Write a reference to an object at the offset.
    pub fn write_ref<T>(&self, pe: &mut PE, data: &T) -> Result<(), Error> {
        pe.buffer.write_ref::<T>(*self, data)
    }
}
impl Address for Offset {
    fn as_offset(&self, _: &PE) -> Result<Offset, Error> {
        Ok(self.clone())
    }
    fn as_rva(&self, pe: &PE) -> Result<RVA, Error> {
        pe.offset_to_rva(*self)
    }
    fn as_va(&self, pe: &PE) -> Result<VA, Error> {
        pe.offset_to_va(*self)
    }
    fn as_ptr(&self, pe: &PE) -> Result<*const u8, Error> {
        let corrected_offset = match pe.translate(PETranslation::Disk(*self)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };
        
        unsafe { Ok(pe.buffer.offset_to_ptr(corrected_offset)) }
    }
}

/// Represents a relative virtual address (i.e., RVA). This address typically points to data in memory versus data on disk.
#[repr(C)]
#[derive(Copy, Clone, Default, Eq, PartialEq, Debug)]
pub struct RVA(pub u32);
impl Address for RVA {
    fn as_offset(&self, pe: &PE) -> Result<Offset, Error> {
        pe.rva_to_offset(*self)
    }
    fn as_rva(&self, _: &PE) -> Result<RVA, Error> {
        Ok(self.clone())
    }
    fn as_va(&self, pe: &PE) -> Result<VA, Error> {
        pe.rva_to_va(*self)
    }
    fn as_ptr(&self, pe: &PE) -> Result<*const u8, Error> {
        let offset = match pe.translate(PETranslation::Memory(*self)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        unsafe { Ok(pe.buffer.offset_to_ptr(offset)) }
    }
}

/// Represents a 32-bit virtual address (i.e., VA). This address typically points directly to active memory.
#[repr(C)]
#[derive(Copy, Clone, Default, Eq, PartialEq, Debug)]
pub struct VA32(pub u32);
impl Address for VA32 {
    fn as_offset(&self, pe: &PE) -> Result<Offset, Error> {
        pe.va_to_offset(VA::VA32(*self))
    }
    fn as_rva(&self, pe: &PE) -> Result<RVA, Error> {
        pe.va_to_rva(VA::VA32(*self))
    }
    fn as_va(&self, _: &PE) -> Result<VA, Error> {
        Ok(VA::VA32(self.clone()))
    }
    fn as_ptr(&self, pe: &PE) -> Result<*const u8, Error> {
        let rva = match self.as_rva(pe) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        rva.as_ptr(pe)
    }
}

/// Represents a 64-bit virtual address (i.e., VA). This address typically points directly to active memory.
#[repr(C)]
#[derive(Copy, Clone, Default, Eq, PartialEq, Debug)]
pub struct VA64(pub u64);
impl Address for VA64 {
    fn as_offset(&self, pe: &PE) -> Result<Offset, Error> {
        pe.va_to_offset(VA::VA64(*self))
    }
    fn as_rva(&self, pe: &PE) -> Result<RVA, Error> {
        pe.va_to_rva(VA::VA64(*self))
    }
    fn as_va(&self, _: &PE) -> Result<VA, Error> {
        Ok(VA::VA64(self.clone()))
    }
    fn as_ptr(&self, pe: &PE) -> Result<*const u8, Error> {
        let rva = match self.as_rva(pe) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        rva.as_ptr(pe)
    }
}

/// Represents either a 32-bit or a 64-bit virtual address.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum VA {
    VA32(VA32),
    VA64(VA64),
}
impl Address for VA {
    fn as_offset(&self, pe: &PE) -> Result<Offset, Error> {
        pe.va_to_offset(*self)
    }
    fn as_rva(&self, pe: &PE) -> Result<RVA, Error> {
        pe.va_to_rva(*self)
    }
    fn as_va(&self, _: &PE) -> Result<VA, Error> {
        Ok(self.clone())
    }
    fn as_ptr(&self, pe: &PE) -> Result<*const u8, Error> {
        let rva = match self.as_rva(pe) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        rva.as_ptr(pe)
    }
}

/// Represents either a 32-bit or 64-bit NT header.
pub enum NTHeaders<'data> {
    NTHeaders32(&'data ImageNTHeaders32),
    NTHeaders64(&'data ImageNTHeaders64),
}

/// Represents a mutable 32-bit or 64-bit NT header.
pub enum NTHeadersMut<'data> {
    NTHeaders32(&'data mut ImageNTHeaders32),
    NTHeaders64(&'data mut ImageNTHeaders64),
}

/// An enum representing thunk data for imports and exports.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ThunkData {
    ForwarderString(RVA),
    Function(RVA),
    ImportByName(RVA),
    Ordinal(u32),
}
/// Functions to help with thunks in import/export data.
pub trait ThunkFunctions {
    /// Check whether this thunk is an ordinal or not.
    fn is_ordinal(&self) -> bool;
    /// Parse this thunk as an export thunk.
    fn parse_export(&self, start: RVA, end: RVA) -> ThunkData;
    /// Parse this thunk as an import thunk.
    fn parse_import(&self) -> ThunkData;
}

/// Represents a 32-bit thunk entry.
#[repr(packed)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Thunk32(pub u32);
impl ThunkFunctions for Thunk32 {
    fn is_ordinal(&self) -> bool {
        (self.0 & 0x80000000) != 0
    }
    fn parse_export(&self, start: RVA, end: RVA) -> ThunkData {
        if self.is_ordinal() {
            ThunkData::Ordinal((self.0 & 0xFFFF) as u32)
        }
        else {
            let value = self.0 as u32;

            if start.0 <= value && value < end.0 {
                ThunkData::ForwarderString(RVA(value))
            }
            else {
                ThunkData::Function(RVA(value))
            }
        }
    }
    fn parse_import(&self) -> ThunkData {
        if self.is_ordinal() {
            ThunkData::Ordinal((self.0 & 0xFFFF) as u32)
        }
        else {
            ThunkData::ImportByName(RVA(self.0 as u32))
        }
    }
}

/// Represents a 64-bit thunk entry.
#[repr(packed)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Thunk64(pub u64);
impl ThunkFunctions for Thunk64 {
    fn is_ordinal(&self) -> bool {
        (self.0 & 0x8000000000000000) != 0
    }
    fn parse_export(&self, start: RVA, end: RVA) -> ThunkData {
        if self.is_ordinal() {
            ThunkData::Ordinal((self.0 & 0xFFFFFFFF) as u32)
        }
        else {
            let value = self.0 as u32;

            if start.0 <= value && value < end.0 {
                ThunkData::ForwarderString(RVA(value))
            }
            else {
                ThunkData::Function(RVA(value))
            }
        }
    }
    fn parse_import(&self) -> ThunkData {
        if self.is_ordinal() {
            ThunkData::Ordinal((self.0 & 0xFFFFFFFF) as u32)
        }
        else {
            ThunkData::ImportByName(RVA(self.0 as u32))
        }
    }
}

/// Abstractly represents a thunk object.
pub enum Thunk<'data> {
    Thunk32(&'data Thunk32),
    Thunk64(&'data Thunk64),
}

/// Abstractly represents a mutable thunk object.
pub enum ThunkMut<'data> {
    Thunk32(&'data mut Thunk32),
    Thunk64(&'data mut Thunk64),
}

pub type ExportDirectory = ImageExportDirectory;

/// An enum representing resolved import data from thunk data.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum ImportData<'data> {
    Ordinal(u32),
    ImportByName(&'data str),
}

/// Represents the import directory in the PE file.
pub struct ImportDirectory<'data> {
    pub descriptors: &'data [ImageImportDescriptor]
}
impl<'data> ImportDirectory<'data> {
    /// Parse the size of the import table in the PE file.
    pub fn parse_size(pe: &'data PE) -> Result<usize, Error> {
        let dir = match pe.get_data_directory(ImageDirectoryEntry::Import) {
            Ok(d) => d,
            Err(e) => return Err(e),
        };

        if dir.virtual_address.0 == 0 || !pe.validate_rva(dir.virtual_address) {
            return Err(Error::InvalidRVA);
        }

        let mut address = match pe.translate(PETranslation::Memory(dir.virtual_address)) {
            Ok(a) => a,
            Err(e) => return Err(e),
        };

        let mut imports = 0usize;

        loop {
            if !pe.validate_offset(address) {
                return Err(Error::InvalidOffset);
            }

            match pe.buffer.get_ref::<ImageImportDescriptor>(address) {
                Ok(x) => { if x.original_first_thunk.0 == 0 && x.first_thunk.0 == 0 { break; } },
                Err(e) => return Err(e),
            }

            imports += 1;
            address.0 += mem::size_of::<ImageImportDescriptor>() as u32;
        }

        Ok(imports)
    }
    /// Parse the import table in the PE file.
    pub fn parse(pe: &'data PE) -> Result<Self, Error> {
        let dir = match pe.get_data_directory(ImageDirectoryEntry::Import) {
            Ok(d) => d,
            Err(e) => return Err(e),
        };

        if dir.virtual_address.0 == 0 || !pe.validate_rva(dir.virtual_address) {
            return Err(Error::InvalidRVA);
        }

        let offset = match pe.translate(PETranslation::Memory(dir.virtual_address)) {
            Ok(a) => a,
            Err(e) => return Err(e),
        };

        let size = match Self::parse_size(pe) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        let descriptors = match pe.buffer.get_slice_ref::<ImageImportDescriptor>(offset, size) {
            Ok(d) => d,
            Err(e) => return Err(e),
        };

        Ok(Self { descriptors } )
    }
    /// Gets a map of DLL names to function names/ordinals in the import directory.
    pub fn get_import_map(&self, pe: &'data PE) -> Result<HashMap<&'data str, Vec<ImportData<'data>>>, Error> {
        let mut results = HashMap::<&'data str, Vec<ImportData<'data>>>::new();

        for import in self.descriptors {
            let name = match import.get_name(&pe) {
                Ok(n) => n.as_str(),
                Err(e) => return Err(e),
            };

            let imports = match import.get_imports(&pe) {
                Ok(i) => i,
                Err(e) => return Err(e),
            };

            results.insert(name, imports);
        }

        Ok(results)
    }
    /// Only available for Windows. Resolve the import address table of all descriptors in this directory.
    #[cfg(windows)]
    pub fn resolve_iat(&self, pe: &mut PE) -> Result<(), Error> {
        for import in self.descriptors.iter() {
            match import.resolve_iat(unsafe { &mut *(pe as *mut PE) }) {
                Ok(()) => (),
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }
}

/// Represents a mutable import directory in the PE file.
pub struct ImportDirectoryMut<'data> {
    pub descriptors: &'data mut [ImageImportDescriptor]
}
impl<'data> ImportDirectoryMut<'data> {
    /// Parse a mutable import table in the PE file.
    pub fn parse(pe: &'data mut PE) -> Result<Self, Error> {
        let dir = match pe.get_data_directory(ImageDirectoryEntry::Import) {
            Ok(d) => d,
            Err(e) => return Err(e),
        };

        if dir.virtual_address.0 == 0 || !pe.validate_rva(dir.virtual_address) {
            return Err(Error::InvalidRVA);
        }

        let offset = match pe.translate(PETranslation::Memory(dir.virtual_address)) {
            Ok(a) => a,
            Err(e) => return Err(e),
        };

        let size = match ImportDirectory::parse_size(pe) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        let descriptors = match pe.buffer.get_mut_slice_ref::<ImageImportDescriptor>(offset, size) {
            Ok(d) => d,
            Err(e) => return Err(e),
        };

        Ok(Self { descriptors } )
    }
    /// Gets a map of DLL names to function names/ordinals in the import directory.
    pub fn get_import_map(&self, pe: &'data PE) -> Result<HashMap<&'data str, Vec<ImportData<'data>>>, Error> {
        let mut results = HashMap::<&'data str, Vec<ImportData<'data>>>::new();

        for import in self.descriptors.iter() {
            let name = match import.get_name(&pe) {
                Ok(n) => n.as_str(),
                Err(e) => return Err(e),
            };

            let imports = match import.get_imports(&pe) {
                Ok(i) => i,
                Err(e) => return Err(e),
            };

            results.insert(name, imports);
        }

        Ok(results)
    }
    /// Only available for Windows. Resolve the import address table of all descriptors in this directory.
    #[cfg(windows)]
    pub fn resolve_iat(&self, pe: &mut PE) -> Result<(), Error> {
        for import in self.descriptors.iter() {
            match import.resolve_iat(unsafe { &mut *(pe as *mut PE) }) {
                Ok(()) => (),
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }
}

/// An enum representing the resulting values of a relocation.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum RelocationValue {
    Relocation16(u16),
    Relocation32(u32),
    Relocation64(u64),
    None,
}

/// Represents a unit of a relocation, which contains a type and an offset in a ```u16``` value.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Relocation(pub u16);
impl Relocation {
    /// Create a new relocation entry.
    pub fn new(relocation_type: ImageRelBased, offset: u16) -> Self {
        let mut result = Self(0);
        
        result.set_type(relocation_type);
        result.set_offset(offset);

        result
    }
    /// Get the type of this relocation.
    pub fn get_type(&self) -> ImageRelBased {
        match self.0 >> 12 {
            0 => ImageRelBased::Absolute,
            1 => ImageRelBased::High,
            2 => ImageRelBased::Low,
            3 => ImageRelBased::HighLow,
            4 => ImageRelBased::HighAdj,
            5 => ImageRelBased::MachineSpecific5,
            6 => ImageRelBased::Reserved,
            7 => ImageRelBased::MachineSpecific7,
            8 => ImageRelBased::MachineSpecific8,
            9 => ImageRelBased::MachineSpecific9,
            10 => ImageRelBased::Dir64,
            _ => ImageRelBased::Unknown,
        }
    }
    /// Set the type of this relocation. It is a no-op if you supply ```ImageRelBased::Unknown```.
    pub fn set_type(&mut self, value: ImageRelBased) {
        let enum_val = match value {
            ImageRelBased::Unknown => return,
            _ => value as u16,
        };

        self.0 = (self.0 & 0xFFF) | (enum_val << 12);
    }
    /// Get the offset of this relocation.
    pub fn get_offset(&self) -> u16 {
        self.0 & 0xFFF
    }
    /// Set the offset of this relocation.
    pub fn set_offset(&mut self, offset: u16) {
        self.0 = (self.0 & 0xF000) | (offset & 0xFFF)
    }
    /// Get the address that this relocation points to.
    pub fn get_address(&self, base: RVA) -> RVA {
        RVA(base.0 + self.get_offset() as u32)
    }
    /// Get the relocation value of this relocation entry. If the type of this relocation is
    /// [ImageRelBased::HighAdj](ImageRelBased::HighAdj), ```next_relocation``` is required.
    pub fn relocate(&self, pe: &PE, base_rva: RVA, new_base: u64, next_relocation: Option<Relocation>) -> Result<RelocationValue, Error> {
        let headers = match pe.get_valid_nt_headers() {
            Ok(h) => h,
            Err(e) => return Err(e),
        };

        let offset = match pe.translate(PETranslation::Memory(self.get_address(base_rva))) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        let image_base = match headers {
            NTHeaders::NTHeaders32(h32) => h32.optional_header.image_base as u64,
            NTHeaders::NTHeaders64(h64) => h64.optional_header.image_base,
        };

        let delta = (new_base as i64) - (image_base as i64);

        match self.get_type() {
            ImageRelBased::High => {
                let high = delta & 0xFFFF0000;
                let current = match pe.buffer.get_ref::<i32>(offset) {
                    Ok(c) => c,
                    Err(e) => return Err(e),
                };

                Ok(RelocationValue::Relocation32( ( (*current as i64) + high) as u32))
            },
            ImageRelBased::Low => {
                let low = delta & 0xFFFF;
                let current = match pe.buffer.get_ref::<i32>(offset) {
                    Ok(c) => c,
                    Err(e) => return Err(e),
                };

                Ok(RelocationValue::Relocation32( ( (*current as i64) + low) as u32))
            },
            ImageRelBased::HighLow => {
                let current = match pe.buffer.get_ref::<i32>(offset) {
                    Ok(c) => c,
                    Err(e) => return Err(e),
                };

                Ok(RelocationValue::Relocation32( ( (*current as i64) + delta) as u32))
            },
            ImageRelBased::HighAdj => {
                if next_relocation.is_none() {
                    return Err(Error::InvalidRelocation);
                }

                let next_entry = next_relocation.unwrap();
                let next_rva = next_entry.get_address(base_rva);
                let current = match pe.buffer.get_ref::<i16>(offset) {
                    Ok(o) => o,
                    Err(e) => return Err(e),
                };
                let high = delta & 0xFFFF0000;
                
                let mut value = (*current as i64) << 16;
                value += next_rva.0 as i64;
                value += high;
                value >>= 16;

                Ok(RelocationValue::Relocation16(value as u16))
            },
            ImageRelBased::Dir64 => {
                let current = match pe.buffer.get_ref::<i64>(offset) {
                    Ok(o) => o,
                    Err(e) => return Err(e),
                };

                Ok(RelocationValue::Relocation64(((*current as i128) + (delta as i128)) as u64))
            },
            _ => Ok(RelocationValue::None),
        }
    }
}

/// Represents a parsed relocation entry.
///
/// This is ultimately the base component of the relocation table array: a base offset and some deltas.
/// It can be used to calculate what exactly gets rewritten and where before data is modified.
///
/// ```rust
/// use exe::PEImage;
/// use exe::types::{RelocationDirectory, RVA};
///
/// let dll = PEImage::from_disk_file("test/dll.dll").unwrap();
/// let relocation_dir = RelocationDirectory::parse(&dll.pe).unwrap();
/// assert_eq!(relocation_dir.entries.len(), 1);
///
/// let entry = &relocation_dir.entries[0];
/// let addresses = entry.relocations
///                      .iter()
///                      .map(|&x| x.get_address(entry.base_relocation.virtual_address))
///                      .collect::<Vec<RVA>>();
///
/// assert_eq!(addresses[0], RVA(0x1008));
/// ```
pub struct RelocationEntry<'data> {
    pub base_relocation: &'data ImageBaseRelocation,
    pub relocations: &'data [Relocation]
}
impl<'data> RelocationEntry<'data> {
    /// Parse a relocation entry at the given RVA.
    pub fn parse(pe: &'data PE, rva: RVA) -> Result<Self, Error> {
        let relocation_size = mem::size_of::<ImageBaseRelocation>();

        let offset = match pe.translate(PETranslation::Memory(rva)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };
            
        let base_relocation = match pe.buffer.get_ref::<ImageBaseRelocation>(offset) {
            Ok(b) => b,
            Err(e) => return Err(e),
        };
            
        let block_addr = Offset( ((offset.0 as usize) + relocation_size) as u32);
        let block_size = base_relocation.relocations();
        let relocations = match pe.buffer.get_slice_ref::<Relocation>(block_addr, block_size) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        Ok(Self { base_relocation, relocations })
    }
    /// Create a `RelocationEntry` object at the given RVA.
    pub fn create(pe: &'data mut PE, rva: RVA, base_relocation: &ImageBaseRelocation, relocations: &[Relocation]) -> Result<Self, Error> {
        let mut offset = match pe.translate(PETranslation::Memory(rva)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        match pe.buffer.write_ref(offset, base_relocation) {
            Ok(()) => (),
            Err(e) => return Err(e),
        }

        offset.0 += mem::size_of::<ImageBaseRelocation>() as u32;

        match pe.buffer.write_slice_ref(offset, relocations) {
            Ok(()) => (),
            Err(e) => return Err(e),
        }

        Self::parse(pe, rva)
    }
    /// Calculate the block size of this relocation entry.
    pub fn block_size(&self) -> u32 {
        ImageBaseRelocation::calculate_block_size(self.relocations.len())
    }
}

/// Represents a mutable parsed relocation entry.
pub struct RelocationEntryMut<'data> {
    pub base_relocation: &'data mut ImageBaseRelocation,
    pub relocations: &'data mut [Relocation],
}
impl<'data> RelocationEntryMut<'data> {
    /// Parse a mutable relocation entry at the given RVA.
    pub fn parse(pe: &'data mut PE, rva: RVA) -> Result<Self, Error> {
        let offset = match pe.translate(PETranslation::Memory(rva)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        unsafe {
            let ptr = pe.buffer.offset_to_mut_ptr(offset);
            Self::parse_unsafe(pe, ptr)
        }
    }

    /// Parse a mutable relocation entry at the given pointer.
    ///
    /// The pointer is validated against the buffer's memory. You should probably use [RelocationEntryMut::parse](RelocationEntryMut::parse),
    /// since it contains more rigorous address checking.
    pub unsafe fn parse_unsafe(pe: &'data PE, ptr: *mut u8) -> Result<Self, Error> {
        let relocation_size = mem::size_of::<ImageBaseRelocation>();
        let word_size = mem::size_of::<u16>();

        if !pe.buffer.validate_ptr(ptr) {
            return Err(Error::BadPointer);
        }

        let base_relocation = &mut *(ptr as *mut ImageBaseRelocation);
        let relocations_ptr = ptr.add(relocation_size);

        if !pe.buffer.validate_ptr(relocations_ptr) {
            return Err(Error::BadPointer);
        }

        let block_size = ( (base_relocation.size_of_block as usize) - relocation_size) / word_size;
        let end = relocations_ptr.add((block_size * word_size) - 1);

        if !pe.buffer.validate_ptr(end) {
            return Err(Error::BadPointer)
        }
            
        let relocations: &'data mut [Relocation] = slice::from_raw_parts_mut(relocations_ptr as *mut Relocation, block_size);

        Ok(Self { base_relocation, relocations })
    }
    /// Create a `RelocationEntryMut` object at the given RVA.
    pub fn create(pe: &'data mut PE, rva: RVA, base_relocation: &ImageBaseRelocation, relocations: &[Relocation]) -> Result<Self, Error> {
        let mut offset = match pe.translate(PETranslation::Memory(rva)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        match pe.buffer.write_ref(offset, base_relocation) {
            Ok(()) => (),
            Err(e) => return Err(e),
        }

        offset.0 += mem::size_of::<ImageBaseRelocation>() as u32;

        match pe.buffer.write_slice_ref(offset, relocations) {
            Ok(()) => (),
            Err(e) => return Err(e),
        }

        Self::parse(pe, rva)
    }

    /// Calculate the block size of this relocation entry.
    pub fn block_size(&self) -> u32 {
        ImageBaseRelocation::calculate_block_size(self.relocations.len())
    }
}

/// Represents the relocation directory.
///
/// It can be used to quickly calculate the relocation data necessary before committing the data
/// to memory.
///
/// ```rust
/// use exe::PEImage;
/// use exe::types::{RelocationDirectory, RelocationValue, RVA};
///
/// let dll = PEImage::from_disk_file("test/dll.dll").unwrap();
/// let relocation_dir = RelocationDirectory::parse(&dll.pe).unwrap();
/// let relocation_data = relocation_dir.relocations(&dll.pe, 0x02000000).unwrap();
/// let (rva, reloc) = relocation_data[0];
///
/// assert_eq!(rva, RVA(0x1008));
/// assert_eq!(reloc, RelocationValue::Relocation32(0x02001059));
/// ```
pub struct RelocationDirectory<'data> {
    pub entries: Vec<RelocationEntry<'data>>,
}
impl<'data> RelocationDirectory<'data> {
    /// Parse the relocation directory.
    pub fn parse(pe: &'data PE) -> Result<Self, Error> {
        let dir = match pe.get_data_directory(ImageDirectoryEntry::BaseReloc) {
            Ok(d) => d,
            Err(e) => return Err(e),
        };
        
        if dir.virtual_address.0 == 0 || !pe.validate_rva(dir.virtual_address) {
            return Err(Error::InvalidRVA);
        }

        let mut start_addr = dir.virtual_address.clone();
        let end_addr = RVA(start_addr.0 + dir.size);

        if !pe.validate_rva(end_addr) {
            return Err(Error::InvalidRVA);
        }

        let mut entries = Vec::<RelocationEntry>::new();

        while start_addr.0 < end_addr.0 {
            let entry = match RelocationEntry::parse(pe, start_addr) {
                Ok(r) => r,
                Err(e) => return Err(e),
            };
            let size = entry.block_size();
            
            entries.push(entry);
            start_addr.0 += size as u32;
        }

        Ok(Self { entries })
    }

    /// Get a vector of [`RVA`](RVA)-to-[`RelocationValue`](RelocationValue) tuples.
    ///
    /// Essentially performs the relocation without writing the values.
    pub fn relocations(&self, pe: &'data PE, new_base: u64) -> Result<Vec<(RVA, RelocationValue)>, Error> {
        let mut result = Vec::<(RVA, RelocationValue)>::new();

        for entry in &self.entries {
            let base_rva = entry.base_relocation.virtual_address.clone();
            let len = entry.relocations.len();

            for i in 0..len {
                let current = entry.relocations[i];
                let mut next: Option<Relocation> = None;
                
                if (i+1) < len {
                    next = Some(entry.relocations[i+1]);
                }

                let value = match current.relocate(pe, base_rva, new_base, next) {
                    Ok(v) => v,
                    Err(e) => return Err(e),
                };
                
                result.push((current.get_address(base_rva), value));
            }
        }

        Ok(result)
    }
    /// Grabs the relocation values from [`RelocationDirectory::relocations`](RelocationDirectory::relocations) and
    /// writes them to the PE buffer.
    pub fn relocate(&self, pe: &'data mut PE, new_base: u64) -> Result<(), Error> {
        let relocations = match self.relocations(pe, new_base) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        let ptr = pe.buffer.as_mut_ptr();

        for (rva, value) in relocations {
            let offset = match pe.translate(PETranslation::Memory(rva)) {
                Ok(o) => o,
                Err(e) => return Err(e),
            };

            let offset_ptr = unsafe { ptr.add(offset.0 as usize) };

            if !pe.buffer.validate_ptr(offset_ptr) {
                return Err(Error::BadPointer);
            }

            unsafe {
                match value {
                    RelocationValue::Relocation16(r16) => *(offset_ptr as *mut u16) = r16,
                    RelocationValue::Relocation32(r32) => *(offset_ptr as *mut u32) = r32,
                    RelocationValue::Relocation64(r64) => *(offset_ptr as *mut u64) = r64,
                    RelocationValue::None => (),
                }
            }
        }

        Ok(())
    }

    /// Add a given [`RVA`](RVA) as a relocation entry.
    pub fn add_relocation(&mut self, pe: &'data mut PE, rva: RVA) -> Result<(), Error> {
        // error out immediately if we don't have a relocation directory
        let dir = match pe.get_data_directory(ImageDirectoryEntry::BaseReloc) {
            Ok(d) => d,
            Err(e) => return Err(e),
        };
        
        if dir.virtual_address.0 == 0 || !pe.validate_rva(dir.virtual_address) {
            return Err(Error::InvalidRVA);
        }

        // first, turn all the relocations into owned objects
        let mut owned_data = self.entries
            .iter()
            .map(|x| (x.base_relocation.clone(), x.relocations.to_vec()))
            .collect::<Vec::<(ImageBaseRelocation, Vec<Relocation>)>>();

        // search the owned objects for a suitable RVA to add the relocation to
        let reloc_address = RVA(rva.0 & 0xFFFFF000);
        let relocation = match pe.get_arch() {
            Ok(a) => match a {
                Arch::X86 => Relocation::new(ImageRelBased::HighLow, (rva.0 & 0xFFF) as u16),
                Arch::X64 => Relocation::new(ImageRelBased::Dir64, (rva.0 & 0xFFF) as u16),
            },
            Err(e) => return Err(e),
        };

        let mut found_entry = false;

        for reloc_pair in &mut owned_data {
            if reloc_pair.0.virtual_address != reloc_address { continue; }
            
            reloc_pair.1.push(relocation);
            reloc_pair.0.size_of_block = ImageBaseRelocation::calculate_block_size(reloc_pair.1.len());
            found_entry = true;
            break;
        }

        if !found_entry {
            owned_data.push((ImageBaseRelocation { virtual_address: reloc_address, size_of_block: ImageBaseRelocation::calculate_block_size(1) },
                             vec![relocation]));
        }

        // sort the owned entries by base relocation address
        owned_data.sort_by(|a,b| a.0.virtual_address.0.cmp(&b.0.virtual_address.0));

        let base_addr = dir.virtual_address.clone();
        let dir_size = dir.size;
        let base_offset = match pe.translate(PETranslation::Memory(base_addr)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        // zero out the original relocation table
        match pe.buffer.write(base_offset, vec![0u8; dir_size as usize].as_slice()) {
            Ok(()) => (),
            Err(e) => return Err(e),
        }
        
        let mut write_addr = base_addr.clone();

        // create new RelocationEntry entries for all the owned data
        let mut new_relocations = Vec::<RelocationEntry<'data>>::new();

        for (base_reloc, relocations) in owned_data {
            let new_relocation = match RelocationEntry::create(unsafe { &mut *(pe as *mut PE) }, write_addr, &base_reloc, relocations.as_slice()) {
                Ok(r) => r,
                Err(e) => return Err(e),
            };

            write_addr.0 += base_reloc.size_of_block;
            new_relocations.push(new_relocation);
        }

        let new_size = write_addr.0 - base_addr.0;
        
        self.entries = new_relocations;

        let mut_dir = match pe.get_mut_data_directory(ImageDirectoryEntry::BaseReloc) {
            Ok(m) => m,
            Err(e) => return Err(e),
        };

        mut_dir.size = new_size;

        Ok(())
    }
}

/// Represents a mutable relocation directory.
pub struct RelocationDirectoryMut<'data> {
    pub entries: Vec<RelocationEntryMut<'data>>,
}
impl<'data> RelocationDirectoryMut<'data> {
    /// Parse a mutable relocation table.
    pub fn parse(pe: &'data mut PE) -> Result<Self, Error> {
        let dir = match pe.get_data_directory(ImageDirectoryEntry::BaseReloc) {
            Ok(d) => d,
            Err(e) => return Err(e),
        };
        
        if dir.virtual_address.0 == 0 || !pe.validate_rva(dir.virtual_address) {
            return Err(Error::InvalidRVA);
        }

        let start_addr = dir.virtual_address.clone();
        let end_addr = RVA(start_addr.0 + dir.size);

        if !pe.validate_rva(end_addr) {
            return Err(Error::InvalidRVA);
        }

        let start_offset = match pe.translate(PETranslation::Memory(start_addr)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };
        let end_offset = match pe.translate(PETranslation::Memory(end_addr)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        let mut entries = Vec::<RelocationEntryMut>::new();

        unsafe {
            let mut start_ptr = pe.buffer.offset_to_mut_ptr(start_offset);
            let end_ptr = pe.buffer.offset_to_ptr(end_offset);
            
            while (start_ptr as usize) < (end_ptr as usize) {
                let entry = match RelocationEntryMut::parse_unsafe(pe, start_ptr) {
                    Ok(r) => r,
                    Err(e) => return Err(e),
                };
            
                start_ptr = start_ptr.add(entry.block_size() as usize);
                entries.push(entry);
            }
        }

        Ok(Self { entries })
    }

    /// Get a vector of [`RVA`](RVA)-to-[`RelocationValue`](RelocationValue) tuples.
    ///
    /// Essentially performs the relocation without writing the values.
    pub fn relocations(&self, pe: &'data PE, new_base: u64) -> Result<Vec<(RVA, RelocationValue)>, Error> {
        let mut result = Vec::<(RVA, RelocationValue)>::new();

        for entry in &self.entries {
            let base_rva = entry.base_relocation.virtual_address.clone();
            let len = entry.relocations.len();

            for i in 0..len {
                let current = entry.relocations[i];
                let mut next: Option<Relocation> = None;
                
                if (i+1) < len {
                    next = Some(entry.relocations[i+1]);
                }

                let value = match current.relocate(pe, base_rva, new_base, next) {
                    Ok(v) => v,
                    Err(e) => return Err(e),
                };
                
                result.push((current.get_address(base_rva), value));
            }
        }

        Ok(result)
    }
    /// Grabs the relocation values from [`RelocationDirectoryMut::relocations`](RelocationDirectoryMut::relocations) and
    /// writes them to the PE buffer.
    pub fn relocate(&self, pe: &'data mut PE, new_base: u64) -> Result<(), Error> {
        let relocations = match self.relocations(pe, new_base) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        let ptr = pe.buffer.as_mut_ptr();

        for (rva, value) in relocations {
            let offset = match pe.translate(PETranslation::Memory(rva)) {
                Ok(o) => o,
                Err(e) => return Err(e),
            };

            let offset_ptr = unsafe { ptr.add(offset.0 as usize) };

            if !pe.buffer.validate_ptr(offset_ptr) {
                return Err(Error::BadPointer);
            }

            unsafe {
                match value {
                    RelocationValue::Relocation16(r16) => *(offset_ptr as *mut u16) = r16,
                    RelocationValue::Relocation32(r32) => *(offset_ptr as *mut u32) = r32,
                    RelocationValue::Relocation64(r64) => *(offset_ptr as *mut u64) = r64,
                    RelocationValue::None => (),
                }
            }
        }

        Ok(())
    }

    /// Add a given [`RVA`](RVA) as a relocation entry.
    pub fn add_relocation(&mut self, pe: &'data mut PE, rva: RVA) -> Result<(), Error> {
        // error out immediately if we don't have a relocation directory
        let dir = match pe.get_data_directory(ImageDirectoryEntry::BaseReloc) {
            Ok(d) => d,
            Err(e) => return Err(e),
        };
        
        if dir.virtual_address.0 == 0 || !pe.validate_rva(dir.virtual_address) {
            return Err(Error::InvalidRVA);
        }

        // first, turn all the relocations into owned objects
        let mut owned_data = self.entries
            .iter()
            .map(|x| (x.base_relocation.clone(), x.relocations.to_vec()))
            .collect::<Vec::<(ImageBaseRelocation, Vec<Relocation>)>>();

        // search the owned objects for a suitable RVA to add the relocation to
        let reloc_address = RVA(rva.0 & 0xFFFFF000);
        let relocation = match pe.get_arch() {
            Ok(a) => match a {
                Arch::X86 => Relocation::new(ImageRelBased::HighLow, (rva.0 & 0xFFF) as u16),
                Arch::X64 => Relocation::new(ImageRelBased::Dir64, (rva.0 & 0xFFF) as u16),
            },
            Err(e) => return Err(e),
        };

        let mut found_entry = false;

        for reloc_pair in &mut owned_data {
            if reloc_pair.0.virtual_address != reloc_address { continue; }
            
            reloc_pair.1.push(relocation);
            reloc_pair.0.size_of_block = ImageBaseRelocation::calculate_block_size(reloc_pair.1.len());
            found_entry = true;
            break;
        }

        if !found_entry {
            owned_data.push((ImageBaseRelocation { virtual_address: reloc_address, size_of_block: ImageBaseRelocation::calculate_block_size(1) },
                             vec![relocation]));
        }

        // sort the owned entries by base relocation address
        owned_data.sort_by(|a,b| a.0.virtual_address.0.cmp(&b.0.virtual_address.0));

        let base_addr = dir.virtual_address.clone();
        let dir_size = dir.size;
        let base_offset = match pe.translate(PETranslation::Memory(base_addr)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        // zero out the original relocation table
        match pe.buffer.write(base_offset, vec![0u8; dir_size as usize].as_slice()) {
            Ok(()) => (),
            Err(e) => return Err(e),
        }
        
        let mut write_addr = base_addr.clone();

        // create new RelocationEntry entries for all the owned data
        let mut new_relocations = Vec::<RelocationEntryMut<'data>>::new();

        for (base_reloc, relocations) in owned_data {
            let new_relocation = match RelocationEntryMut::create(unsafe { &mut *(pe as *mut PE) }, write_addr, &base_reloc, relocations.as_slice()) {
                Ok(r) => r,
                Err(e) => return Err(e),
            };

            write_addr.0 += base_reloc.size_of_block;
            new_relocations.push(new_relocation);
        }

        let new_size = write_addr.0 - base_addr.0;
        
        self.entries = new_relocations;

        let mut_dir = match pe.get_mut_data_directory(ImageDirectoryEntry::BaseReloc) {
            Ok(m) => m,
            Err(e) => return Err(e),
        };

        mut_dir.size = new_size;

        Ok(())
    }
}

/// Special value used to calculate a variety of fields in the resource directory taking up a single [`u32`](u32) value.
///
/// The [resource directory](ImageResourceDirectory) uses a series of DWORDs that can be flagged or unflagged, representing the presence
/// of another directory in the resources or data being pointed to. Rust doesn't have bitfields, so instead we just mask the
/// significant bit in this object and present an interface to access the data.
#[repr(packed)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct FlaggedDword(pub u32);
impl FlaggedDword {
    /// Get the flag represented by the object.
    pub fn get_flag(&self) -> bool {
        (self.0 & 0x80000000) > 0
    }
    /// Get the dword value represented by the object.
    pub fn get_dword(&self) -> u32 {
        if self.get_flag() {
            self.0 & 0x7FFFFFFF
        }
        else {
            self.0
        }
    }
}

/// A [`u32`](u32) wrapper representing offsets into a resource directory.
#[repr(packed)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct ResourceOffset(pub u32);
impl ResourceOffset {
    /// Resolve this resource offset into an [`RVA`](RVA).
    pub fn resolve(&self, pe: &PE) -> Result<RVA, Error> {
        pe.get_resource_address(*self)
    }
}
impl Address for ResourceOffset {
    fn as_offset(&self, pe: &PE) -> Result<Offset, Error> {
        let rva = match self.resolve(pe) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        rva.as_offset(pe)
    }
    fn as_rva(&self, pe: &PE) -> Result<RVA, Error> {
        self.resolve(pe)
    }
    fn as_va(&self, pe: &PE) -> Result<VA, Error> {
        let rva = match self.resolve(pe) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        rva.as_va(pe)
    }
    fn as_ptr(&self, pe: &PE) -> Result<*const u8, Error> {
        let offset = match self.as_offset(pe) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        offset.as_ptr(pe)
    }
}

/// Represents a variety of default categories for categorizing resource data.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ResourceID {
    Cursor = 1,
    Bitmap = 2,
    Icon = 3,
    Menu = 4,
    Dialog = 5,
    String = 6,
    FontDir = 7,
    Font = 8,
    Accelerator = 9,
    RCData = 10,
    MessageTable = 11,
    GroupCursor = 12,
    Reserved = 13,
    GroupIcon = 14,
    Reserved2 = 15,
    Version = 16,
    DlgInclude = 17,
    Reserved3 = 18,
    PlugPlay = 19,
    VXD = 20,
    AniCursor = 21,
    AniIcon = 22,
    HTML = 23,
    Manifest = 24,
    Unknown,
}
impl ResourceID {
    /// Convert the [`u32`](u32) value into a ```ResourceID``` value.
    pub fn from_u32(u: u32) -> Self {
        match u {
            1 => Self::Cursor,
            2 => Self::Bitmap,
            3 => Self::Icon,
            4 => Self::Menu,
            5 => Self::Dialog,
            6 => Self::String,
            7 => Self::FontDir,
            8 => Self::Font,
            9 => Self::Accelerator,
            10 => Self::RCData,
            11 => Self::MessageTable,
            12 => Self::GroupCursor,
            13 => Self::Reserved,
            14 => Self::GroupIcon,
            15 => Self::Reserved2,
            16 => Self::Version,
            17 => Self::DlgInclude,
            18 => Self::Reserved3,
            19 => Self::PlugPlay,
            20 => Self::VXD,
            21 => Self::AniCursor,
            22 => Self::AniIcon,
            23 => Self::HTML,
            24 => Self::Manifest,
            _ => Self::Unknown
        }
    }
}

/// Represents the ID value of a given resource directory entry.
///
/// [`Name`](ResourceDirectoryID::Name) typically points to a [`ImageResourceDirStringU`](ImageResourceDirStringU) object.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ResourceDirectoryID {
    ID(u32),
    Name(ResourceOffset),
}

/// Represents the data contained in the resource directory.
///
/// [`Directory`](ResourceDirectoryData::Directory) points to another [`ImageResourceDirectory`](ImageResourceDirectory)
/// object, whereas [`Data`](ResourceDirectoryData::Data) points to a [`ImageResourceDataEntry`](ImageResourceDataEntry)
/// object.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ResourceDirectoryData {
    Directory(ResourceOffset),
    Data(ResourceOffset),
}

/// Represents a directory node in the greater resource directory.
#[derive(Clone)]
pub struct ResourceNode<'data> {
    pub directory: &'data ImageResourceDirectory,
    pub entries: &'data [ImageResourceDirectoryEntry],
}
impl<'data> ResourceNode<'data> {
    /// Parse a resource directory node with the given [`ResourceOffset`](ResourceOffset).
    ///
    /// If the offset goes outside the bounds of the directory, a [`Error::BufferTooSmall`](Error::BufferTooSmall) error
    /// is returned.
    pub fn parse(pe: &'data PE, offset: ResourceOffset) -> Result<ResourceNode<'data>, Error> {
        let resolved_offset = match offset.resolve(pe) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        let mut image_offset = match pe.translate(PETranslation::Memory(resolved_offset)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };
        
        if !pe.validate_offset(image_offset) {
            return Err(Error::InvalidRVA)
        }
       
        let directory = match pe.buffer.get_ref::<ImageResourceDirectory>(image_offset) {
            Ok(d) => d,
            Err(e) => return Err(e),
        };

        image_offset.0 += mem::size_of::<ImageResourceDirectory>() as u32;

        if !pe.validate_offset(image_offset) {
            return Err(Error::InvalidRVA)
        }
        
        let entries = match pe.buffer.get_slice_ref::<ImageResourceDirectoryEntry>(image_offset, directory.entries()) {
            Ok(e) => e,
            Err(e) => return Err(e),
        };

        Ok(Self { directory, entries })
    }
}

/// Represents a mutable directory node in the greater resource directory.
pub struct ResourceNodeMut<'data> {
    pub directory: &'data mut ImageResourceDirectory,
    pub entries: &'data mut [ImageResourceDirectoryEntry],
}
impl<'data> ResourceNodeMut<'data> {
    /// Parse a mutable resource directory node with the given [`ResourceOffset`](ResourceOffset).
    ///
    /// If the offset goes outside the bounds of the directory, a [`Error::BufferTooSmall`](Error::BufferTooSmall) error
    /// is returned.
    pub fn parse(pe: &'data mut PE, offset: ResourceOffset) -> Result<Self, Error> {
        let resolved_offset = match offset.resolve(pe) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        let image_offset = match pe.translate(PETranslation::Memory(resolved_offset)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };
        
        if !pe.validate_offset(image_offset) {
            return Err(Error::InvalidRVA)
        }

        unsafe {
            let ptr = pe.buffer.offset_to_mut_ptr(image_offset);

            Self::parse_unsafe(pe, ptr)
        }
    }
    /// Parse a mutable resource node at the given pointer.
    ///
    /// The pointer is verified against the buffer before parsing. You should probably use [`ResourceNodeMut::parse`](ResourceNodeMut::parse)
    /// unless you really need to use a pointer, as that function has more rigorous address checking.
    pub unsafe fn parse_unsafe(pe: &'data PE, mut ptr: *mut u8) -> Result<Self, Error> {
        if !pe.buffer.validate_ptr(ptr) {
            return Err(Error::BadPointer);
        }
            
        let directory = &mut *(ptr as *mut ImageResourceDirectory);
            
        ptr = ptr.add(mem::size_of::<ImageResourceDirectory>());
            
        if !pe.buffer.validate_ptr(ptr as *const u8) {
            return Err(Error::BadPointer)
        }
        
        let entries = slice::from_raw_parts_mut(ptr as *mut ImageResourceDirectoryEntry, directory.entries());

        Ok(Self { directory, entries })
    }
}

/// Represents a flattened node of data in a given resource tree.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct FlattenedResourceDataEntry {
    /// The type ID of this resource, or alternatively, depth 1 of the resource tree.
    pub type_id: ResourceDirectoryID,
    /// The resource ID of this resource, or alternatively, depth 2 of the resource tree.
    pub rsrc_id: ResourceDirectoryID,
    /// The language ID of this resource, or alternatively, depth 3 of the resource tree.
    pub lang_id: ResourceDirectoryID,
    /// The data leaf ultimately representing this resource.
    pub data: ResourceOffset,
}
impl FlattenedResourceDataEntry {
    /// Get the data entry pointed to by the ```data``` offset.
    pub fn get_data_entry<'data>(&self, pe: &'data PE) -> Result<&'data ImageResourceDataEntry, Error> {
        let rva = match self.data.resolve(pe) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        let offset = match pe.translate(PETranslation::Memory(rva)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        pe.buffer.get_ref::<ImageResourceDataEntry>(offset)
    }
    /// Get a mutable data entry pointed to by the ```data``` offset.
    pub fn get_mut_data_entry<'data>(&self, pe: &'data mut PE) -> Result<&'data mut ImageResourceDataEntry, Error> {
        let rva = match self.data.resolve(pe) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        let offset = match pe.translate(PETranslation::Memory(rva)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        pe.buffer.get_mut_ref::<ImageResourceDataEntry>(offset)
    }
}

/// Represents a resource directory, containing flattened resources and the root node of the resource tree.
pub struct ResourceDirectory<'data> {
    pub root_node: ResourceNode<'data>,
    pub resources: Vec<FlattenedResourceDataEntry>,
}
impl<'data> ResourceDirectory<'data> {
    /// Parse the resource directory in the given PE file.
    pub fn parse(pe: &'data PE) -> Result<Self, Error> {
        let mut resources = Vec::<FlattenedResourceDataEntry>::new();
        
        let root_node = match ResourceNode::parse(pe, ResourceOffset(0)) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        for type_entry in root_node.entries {
            let id_offset = match type_entry.get_data() {
                ResourceDirectoryData::Data(_) => return Err(Error::CorruptDataDirectory),
                ResourceDirectoryData::Directory(d) => d,
            };

            let id_node = match ResourceNode::parse(pe, id_offset) {
                Ok(n) => n,
                Err(e) => return Err(e),
            };

            for id_entry in id_node.entries {
                let lang_offset = match id_entry.get_data() {
                    ResourceDirectoryData::Data(_) => return Err(Error::CorruptDataDirectory),
                    ResourceDirectoryData::Directory(d) => d,
                };

                let lang_node = match ResourceNode::parse(pe, lang_offset) {
                    Ok(n) => n,
                    Err(e) => return Err(e),
                };

                for lang_entry in lang_node.entries {
                    let data_offset = match lang_entry.get_data() {
                        ResourceDirectoryData::Directory(_) => return Err(Error::CorruptDataDirectory),
                        ResourceDirectoryData::Data(d) => d,
                    };

                    resources.push(FlattenedResourceDataEntry {
                        type_id: type_entry.get_id(),
                        rsrc_id: id_entry.get_id(),
                        lang_id: lang_entry.get_id(),
                        data: data_offset,
                    });
                }
            }
        }

        Ok(Self { root_node, resources })
    }
    /// Filter the parsed resources by the given default [`ResourceID`](ResourceID).
    pub fn filter_by_type(&self, id: ResourceID) -> Vec<FlattenedResourceDataEntry> {
        self.resources
            .iter()
            .filter(|x| match x.type_id {
                ResourceDirectoryID::Name(_) => false,
                ResourceDirectoryID::ID(v) => ResourceID::from_u32(v) == id,
            })
            .map(|&x| x)
            .collect()
    }
}

/// Represents a mutable resource directory, containing flattened resources and the root node of the resource tree.
pub struct ResourceDirectoryMut<'data> {
    pub root_node: ResourceNodeMut<'data>,
    pub resources: Vec<FlattenedResourceDataEntry>,
}
impl<'data> ResourceDirectoryMut<'data> {
    /// Parse a mutable resource directory in the given PE file.
    pub fn parse(pe: &'data mut PE) -> Result<Self, Error> {
        let mut resources = Vec::<FlattenedResourceDataEntry>::new();

        let dir_size = match pe.get_data_directory(ImageDirectoryEntry::Resource) {
            Ok(d) => d.size,
            Err(e) => return Err(e),
        };

        let rva = match ResourceOffset(0).resolve(pe) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        let offset = match pe.translate(PETranslation::Memory(rva)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        unsafe {
            let ptr = pe.buffer.offset_to_mut_ptr(offset);
        
            let root_node = match ResourceNodeMut::parse_unsafe(pe, ptr) {
                Ok(r) => r,
                Err(e) => return Err(e),
            };

            // call iter() specifically to prevent an implicit call to into_iter()
            for type_entry in root_node.entries.iter() {
                let id_offset = match type_entry.get_data() {
                    ResourceDirectoryData::Data(_) => return Err(Error::CorruptDataDirectory),
                    ResourceDirectoryData::Directory(d) => d,
                };

                if id_offset.0 > dir_size {
                    return Err(Error::BufferTooSmall);
                }

                let id_ptr = ptr.add(id_offset.0 as usize);

                if !pe.buffer.validate_ptr(id_ptr as *const u8) {
                    return Err(Error::BadPointer);
                }
            
                let id_node = match ResourceNodeMut::parse_unsafe(pe, id_ptr) {
                    Ok(n) => n,
                    Err(e) => return Err(e),
                };

                for id_entry in id_node.entries {
                    let lang_offset = match id_entry.get_data() {
                        ResourceDirectoryData::Data(_) => return Err(Error::CorruptDataDirectory),
                        ResourceDirectoryData::Directory(d) => d,
                    };

                    if lang_offset.0 > dir_size {
                        return Err(Error::BufferTooSmall);
                    }

                    let lang_ptr = ptr.add(lang_offset.0 as usize);

                    if !pe.buffer.validate_ptr(lang_ptr as *const u8) {
                        return Err(Error::BadPointer);
                    }

                    let lang_node = match ResourceNodeMut::parse_unsafe(pe, lang_ptr) {
                        Ok(n) => n,
                        Err(e) => return Err(e),
                    };

                    for lang_entry in lang_node.entries {
                        let data_offset = match lang_entry.get_data() {
                            ResourceDirectoryData::Directory(_) => return Err(Error::CorruptDataDirectory),
                            ResourceDirectoryData::Data(d) => d,
                        };

                        resources.push(FlattenedResourceDataEntry {
                            type_id: type_entry.get_id(),
                            rsrc_id: id_entry.get_id(),
                            lang_id: lang_entry.get_id(),
                            data: data_offset,
                        });
                    }
                }
            }

            Ok(Self { root_node, resources })
        }
    }
    /// Filter the parsed resources by the given default [`ResourceID`](ResourceID).
    pub fn filter_by_type(&self, id: ResourceID) -> Vec<FlattenedResourceDataEntry> {
        self.resources
            .iter()
            .filter(|x| match x.type_id {
                ResourceDirectoryID::Name(_) => false,
                ResourceDirectoryID::ID(v) => ResourceID::from_u32(v) == id,
            })
            .map(|&x| x)
            .collect()
    }
}

pub type DebugDirectory = ImageDebugDirectory;

/// Represents either a 32-bit or a 64-bit TLS directory.
pub enum TLSDirectory<'data> {
    TLS32(&'data ImageTLSDirectory32),
    TLS64(&'data ImageTLSDirectory64),
}
impl<'data> TLSDirectory<'data> {
    pub fn parse(pe: &'data PE) -> Result<Self, Error> {
        let arch = match pe.get_arch() {
            Ok(a) => a,
            Err(e) => return Err(e),
        };

        match arch {
            Arch::X86 => match ImageTLSDirectory32::parse(pe) {
                Ok(tls32) => Ok(TLSDirectory::TLS32(tls32)),
                Err(e) => return Err(e),
            },
            Arch::X64 => match ImageTLSDirectory64::parse(pe) {
                Ok(tls64) => Ok(TLSDirectory::TLS64(tls64)),
                Err(e) => return Err(e),
            },
        }
    }
}

/// Represents a mutable 32-bit or a 64-bit TLS directory.
pub enum TLSDirectoryMut<'data> {
    TLS32(&'data mut ImageTLSDirectory32),
    TLS64(&'data mut ImageTLSDirectory64),
}
impl<'data> TLSDirectoryMut<'data> {
    pub fn parse(pe: &'data mut PE) -> Result<Self, Error> {
        let arch = match pe.get_arch() {
            Ok(a) => a,
            Err(e) => return Err(e),
        };

        match arch {
            Arch::X86 => match ImageTLSDirectory32::parse_mut(pe) {
                Ok(tls32) => Ok(TLSDirectoryMut::TLS32(tls32)),
                Err(e) => return Err(e),
            },
            Arch::X64 => match ImageTLSDirectory64::parse_mut(pe) {
                Ok(tls64) => Ok(TLSDirectoryMut::TLS64(tls64)),
                Err(e) => return Err(e),
            },
        }
    }
}

bitflags! {
    /// A series of bitflags representing the file flags for the [`VS_FIXEDFILEINFO`](https://docs.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo)
    /// structure.
    pub struct VSFileFlags: u32 {
        const DEBUG = 0x00000001;
        const PRERELEASE = 0x00000002;
        const PATCHED = 0x00000004;
        const PRIVATEBUILD = 0x00000008;
        const INFOINFERRED = 0x00000010;
        const SPECIALBUILD = 0x00000020;
    }
}

/// An enum representing the OS flags for the [`VS_FIXEDFILEINFO`](https://docs.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo)
/// structure.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum VSFileOS {
    Unknown = 0x00000000,
    Windows16 = 0x00000001,
    PM16 = 0x00000002,
    PM32 = 0x00000003,
    Windows32 = 0x00000004,
    DOS = 0x00010000,
    DOSWindows16 = 0x00010001,
    DOSWindows32 = 0x00010004,
    OS216 = 0x00020000,
    OS216PM16 = 0x00020002,
    OS232 = 0x00030000,
    OS232PM32 = 0x00030003,
    NT = 0x00040000,
    NTWindows32 = 0x00040004,
}
impl VSFileOS {
    pub fn from_u32(u: u32) -> Self {
        match u {
            0x00000001 => Self::Windows16,
            0x00000002 => Self::PM16,
            0x00000003 => Self::PM32,
            0x00000004 => Self::Windows32,
            0x00010000 => Self::DOS,
            0x00010001 => Self::DOSWindows16,
            0x00010004 => Self::DOSWindows32,
            0x00020000 => Self::OS216,
            0x00020002 => Self::OS216PM16,
            0x00030000 => Self::OS232,
            0x00030003 => Self::OS232PM32,
            0x00040000 => Self::NT,
            0x00040004 => Self::NTWindows32,
            _ => Self::Unknown,
        }
    }
}

/// An enum representing the file type for the [`VS_FIXEDFILEINFO`](https://docs.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo)
/// structure.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum VSFileType {
    Unknown = 0x00000000,
    App = 0x00000001,
    DLL = 0x00000002,
    Drv = 0x00000003,
    Font = 0x00000004,
    VXD = 0x00000005,
    StaticLib = 0x00000007,
}
impl VSFileType {
    pub fn from_u32(u: u32) -> Self {
        match u {
            0x00000001 => Self::App,
            0x00000002 => Self::DLL,
            0x00000003 => Self::Drv,
            0x00000004 => Self::Font,
            0x00000005 => Self::VXD,
            0x00000007 => Self::StaticLib,
            _ => Self::Unknown,
        }
    }
}

/// An enum representing the file subtype for drivers in the [`VS_FIXEDFILEINFO`](https://docs.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo)
/// structure.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum VSFileSubtypeDrv {
    Unknown = 0x00000000,
    Printer = 0x00000001,
    Keyboard = 0x00000002,
    Language = 0x00000003,
    Display = 0x00000004,
    Mouse = 0x00000005,
    Network = 0x00000006,
    System = 0x00000007,
    Installable = 0x00000008,
    Sound = 0x00000009,
    Comm = 0x0000000A,
    VersionedPrinter = 0x0000000C,
}
impl VSFileSubtypeDrv {
    pub fn from_u32(u: u32) -> Self {
        match u {
            0x00000001 => Self::Printer,
            0x00000002 => Self::Keyboard,
            0x00000003 => Self::Language,
            0x00000004 => Self::Display,
            0x00000005 => Self::Mouse,
            0x00000006 => Self::Network,
            0x00000007 => Self::System,
            0x00000008 => Self::Installable,
            0x00000009 => Self::Sound,
            0x0000000A => Self::Comm,
            0x0000000C => Self::VersionedPrinter,
            _ => Self::Unknown,
        }
    }
}
    
/// An enum representing the file subtype for fonts in the [`VS_FIXEDFILEINFO`](https://docs.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo)
/// structure.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum VSFileSubtypeFont {
    Unknown = 0x00000000,
    Raster = 0x00000001,
    Vector = 0x00000002,
    TrueType = 0x00000003,
}
impl VSFileSubtypeFont {
    pub fn from_u32(u: u32) -> Self {
        match u {
            0x00000001 => Self::Raster,
            0x00000002 => Self::Vector,
            0x00000003 => Self::TrueType,
            _ => Self::Unknown,
        }
    }
}

/// Represents a [`VS_FIXEDFILEINFO`](https://docs.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo) structure.
#[repr(C)]
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct VSFixedFileInfo {
    pub signature: u32,
    pub struct_version: u32,
    pub file_version_ms: u32,
    pub file_version_ls: u32,
    pub product_version_ms: u32,
    pub product_version_ls: u32,
    pub file_flags_mask: u32,
    pub file_flags: VSFileFlags,
    pub file_os: u32,
    pub file_type: u32,
    pub file_subtype: u32,
    pub file_date_ms: u32,
    pub file_date_ls: u32,
}

/// Represents a [`String`](https://docs.microsoft.com/en-us/windows/win32/menurc/string-str) structure.
pub struct VSString<'data> {
    pub length: &'data u16,
    pub value_length: &'data u16,
    pub type_: &'data u16,
    pub key: &'data [WChar],
    pub value: &'data [WChar],
}
impl<'data> VSString<'data> {
    /// Parse a `VSString` object at the given [`RVA`](RVA).
    pub fn parse(pe: &'data PE, rva: RVA) -> Result<Self, Error> {
        let mut consumed = 0usize;
        let mut offset = match pe.translate(PETranslation::Memory(rva)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        let length = match pe.buffer.get_ref::<u16>(offset) {
            Ok(l) => l,
            Err(e) => return Err(e),
        };
        consumed += mem::size_of::<u16>();
        offset.0 += mem::size_of::<u16>() as u32;
        if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }

        let value_length = match pe.buffer.get_ref::<u16>(offset) {
            Ok(l) => l,
            Err(e) => return Err(e),
        };
        consumed += mem::size_of::<u16>();
        offset.0 += mem::size_of::<u16>() as u32;
        if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }

        let type_value = match pe.buffer.get_ref::<u16>(offset) {
            Ok(l) => l,
            Err(e) => return Err(e),
        };
        consumed += mem::size_of::<u16>();
        offset.0 += mem::size_of::<u16>() as u32;
        if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }

        let key = match pe.buffer.get_widestring(offset, None) {
            Ok(w) => w,
            Err(e) => return Err(e),
        };
        let key_size = key.len() * mem::size_of::<WChar>();
        consumed += key_size;
        offset.0 += key_size as u32;
        if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }

        offset.0 = align(offset.0 as usize, 4) as u32;
        
        let value = match pe.buffer.get_widestring(offset, None) {
            Ok(w) => w,
            Err(e) => return Err(e),
        };
        let value_size = value.len() * mem::size_of::<WChar>();
        consumed += value_size;
        offset.0 += value_size as u32;
        if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }

        Ok(Self {
            length,
            value_length,
            type_: type_value,
            key,
            value,
        })
    }
}

/// Represents a [`StringTable`](https://docs.microsoft.com/en-us/windows/win32/menurc/stringtable) structure.
pub struct VSStringTable<'data> {
    pub length: &'data u16,
    pub value_length: &'data u16,
    pub type_: &'data u16,
    pub key: &'data [WChar],
    pub children: Vec<VSString<'data>>,
}
impl<'data> VSStringTable<'data> {
    /// Parse a `VSStringTable` structure at the given RVA.
    pub fn parse(pe: &'data PE, rva: RVA) -> Result<Self, Error> {
        let mut consumed = 0usize;
        let mut offset = match pe.translate(PETranslation::Memory(rva)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        let base_offset = offset.clone();
        let length = match pe.buffer.get_ref::<u16>(offset) {
            Ok(l) => l,
            Err(e) => return Err(e),
        };
        
        consumed += mem::size_of::<u16>();
        offset.0 += mem::size_of::<u16>() as u32;
        if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }

        let value_length = match pe.buffer.get_ref::<u16>(offset) {
            Ok(l) => l,
            Err(e) => return Err(e),
        };
        
        consumed += mem::size_of::<u16>();
        offset.0 += mem::size_of::<u16>() as u32;
        if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }

        let type_value = match pe.buffer.get_ref::<u16>(offset) {
            Ok(l) => l,
            Err(e) => return Err(e),
        };
        
        consumed += mem::size_of::<u16>();
        offset.0 += mem::size_of::<u16>() as u32;
        if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }

        let key = match pe.buffer.get_widestring(offset, None) {
            Ok(w) => w,
            Err(e) => return Err(e),
        };
        
        let key_size = key.len() * mem::size_of::<WChar>();
        consumed += key_size;
        offset.0 += key_size as u32;
        if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }

        offset.0 = align(offset.0 as usize, 4) as u32;

        let mut children = Vec::<VSString>::new();

        while consumed < (*length as usize) {
            let rva = match pe.pe_type {
                PEType::Disk => match offset.as_rva(&pe) {
                    Ok(r) => r,
                    Err(e) => return Err(e),
                },
                PEType::Memory => RVA(offset.0),
            };
            
            let child = match VSString::parse(&pe, rva) {
                Ok(c) => c,
                Err(e) => return Err(e),
            };

            offset.0 += *child.length as u32;
            offset.0 = align(offset.0 as usize, 4) as u32;
            consumed = (offset.0 - base_offset.0) as usize;
            children.push(child);
        }
        
        Ok(Self {
            length,
            value_length,
            type_: type_value,
            key,
            children,
        })
    }
    /// Grab the key data as a u32 value. Useful for grabbing the code page and language ID from the text representation.
    pub fn key_as_u32(&self) -> Result<u32, std::num::ParseIntError> {
        let key_str = self.key.as_u16_str().to_string_lossy();

        u32::from_str_radix(key_str.as_str(), 16)
    }
    /// Grab the codepage value of this string table.
    pub fn get_code_page(&self) -> Result<u16, std::num::ParseIntError> {
        let key_val = match self.key_as_u32() {
            Ok(k) => k,
            Err(e) => return Err(e),
        };

        Ok((key_val & 0xFFFF) as u16)
    }
    /// Grab the codepage value of this string table.
    pub fn get_lang_id(&self) -> Result<u16, std::num::ParseIntError> {
        let key_val = match self.key_as_u32() {
            Ok(k) => k,
            Err(e) => return Err(e),
        };

        Ok((key_val >> 16) as u16)
    }
    /// Grab the string table data as a key/value [`HashMap`](HashMap) value.
    pub fn string_map(&self) -> HashMap<String, String> {
        let mut result = HashMap::<String, String>::new();

        for entry in &self.children {
            result.insert(entry.key.as_u16_str().to_string_lossy(), entry.value.as_u16_str().to_string_lossy());
        }

        result
    }
}

/// Represents a [`StringFileInfo`](https://docs.microsoft.com/en-us/windows/win32/menurc/stringfileinfo) structure.
pub struct VSStringFileInfo<'data> {
    pub length: &'data u16,
    pub value_length: &'data u16,
    pub type_: &'data u16,
    pub key: &'data [WChar],
    pub children: Vec<VSStringTable<'data>>,
}
impl<'data> VSStringFileInfo<'data> {
    /// Parse a `VSStringFileInfo` structure at the given [`RVA`](RVA).
    pub fn parse(pe: &'data PE, rva: RVA) -> Result<Self, Error> {
        let mut consumed = 0usize;
        let mut offset = match pe.translate(PETranslation::Memory(rva)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        let base_offset = offset.clone();
        let length = match pe.buffer.get_ref::<u16>(offset) {
            Ok(l) => l,
            Err(e) => return Err(e),
        };
        
        consumed += mem::size_of::<u16>();
        offset.0 += mem::size_of::<u16>() as u32;
        if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }

        let value_length = match pe.buffer.get_ref::<u16>(offset) {
            Ok(l) => l,
            Err(e) => return Err(e),
        };
        
        consumed += mem::size_of::<u16>();
        offset.0 += mem::size_of::<u16>() as u32;
        if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }

        let type_value = match pe.buffer.get_ref::<u16>(offset) {
            Ok(l) => l,
            Err(e) => return Err(e),
        };
        
        consumed += mem::size_of::<u16>();
        offset.0 += mem::size_of::<u16>() as u32;
        if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }

        let key = match pe.buffer.get_widestring(offset, None) {
            Ok(w) => w,
            Err(e) => return Err(e),
        };
        
        let key_size = key.len() * mem::size_of::<WChar>();
        consumed += key_size;
        offset.0 += key_size as u32;
        if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }

        offset.0 = align(offset.0 as usize, 4) as u32;

        let mut children = Vec::<VSStringTable>::new();

        while consumed < (*length as usize) {
            let rva = match pe.pe_type {
                PEType::Disk => match offset.as_rva(&pe) {
                    Ok(r) => r,
                    Err(e) => return Err(e),
                },
                PEType::Memory => RVA(offset.0),
            };
            
            let child = match VSStringTable::parse(&pe, rva) {
                Ok(c) => c,
                Err(e) => return Err(e),
            };

            offset.0 += *child.length as u32;
            offset.0 = align(offset.0 as usize, 4) as u32;
            consumed = (offset.0 - base_offset.0) as usize;
            children.push(child);
        }
        
        Ok(Self {
            length,
            value_length,
            type_: type_value,
            key,
            children,
        })
    }
}

/// Represents a DWORD in the [`VSVar`](VSVar) structure which contains a language ID and a language codepage.
#[repr(C)]
pub struct VarDword {
    lang_id: u16,
    codepage: u16,
}

/// Represents a [`Var`](https://docs.microsoft.com/en-us/windows/win32/menurc/var-str) structure.
pub struct VSVar<'data> {
    pub length: &'data u16,
    pub value_length: &'data u16,
    pub type_: &'data u16,
    pub key: &'data [WChar],
    pub children: Vec<&'data VarDword>,
}
impl<'data> VSVar<'data> {
    /// Parse a `VSVar` structure at the given [`RVA`](RVA).
    pub fn parse(pe: &'data PE, rva: RVA) -> Result<Self, Error> {
        let mut consumed = 0usize;
        let mut offset = match pe.translate(PETranslation::Memory(rva)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        let base_offset = offset.clone();
        let length = match pe.buffer.get_ref::<u16>(offset) {
            Ok(l) => l,
            Err(e) => return Err(e),
        };
        
        consumed += mem::size_of::<u16>();
        offset.0 += mem::size_of::<u16>() as u32;
        if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }

        let value_length = match pe.buffer.get_ref::<u16>(offset) {
            Ok(l) => l,
            Err(e) => return Err(e),
        };
        
        consumed += mem::size_of::<u16>();
        offset.0 += mem::size_of::<u16>() as u32;
        if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }

        let type_value = match pe.buffer.get_ref::<u16>(offset) {
            Ok(l) => l,
            Err(e) => return Err(e),
        };
        
        consumed += mem::size_of::<u16>();
        offset.0 += mem::size_of::<u16>() as u32;
        if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }

        let key = match pe.buffer.get_widestring(offset, None) {
            Ok(w) => w,
            Err(e) => return Err(e),
        };
        
        let key_size = key.len() * mem::size_of::<WChar>();
        consumed += key_size;
        offset.0 += key_size as u32;
        if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }

        offset.0 = align(offset.0 as usize, 4) as u32;

        let mut children = Vec::<&'data VarDword>::new();

        while consumed < (*length as usize) {
            let child = match pe.buffer.get_ref::<VarDword>(offset) {
                Ok(c) => c,
                Err(e) => return Err(e),
            };

            offset.0 += mem::size_of::<VarDword>() as u32;
            offset.0 = align(offset.0 as usize, 4) as u32;
            consumed = (offset.0 - base_offset.0) as usize;
            children.push(child);
        }
        
        Ok(Self {
            length,
            value_length,
            type_: type_value,
            key,
            children,
        })
    }
}

/// Represents a [`VarFileInfo`](https://docs.microsoft.com/en-us/windows/win32/menurc/varfileinfo) structure.
pub struct VSVarFileInfo<'data> {
    pub length: &'data u16,
    pub value_length: &'data u16,
    pub type_: &'data u16,
    pub key: &'data [WChar],
    pub children: Vec<VSVar<'data>>,
}
impl<'data> VSVarFileInfo<'data> {
    /// Parse a `VSVarFileInfo` structure at the given [`RVA`](RVA).
    pub fn parse(pe: &'data PE, rva: RVA) -> Result<Self, Error> {
        let mut consumed = 0usize;
        let mut offset = match pe.translate(PETranslation::Memory(rva)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        let base_offset = offset.clone();
        let length = match pe.buffer.get_ref::<u16>(offset) {
            Ok(l) => l,
            Err(e) => return Err(e),
        };
        
        consumed += mem::size_of::<u16>();
        offset.0 += mem::size_of::<u16>() as u32;
        if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }

        let value_length = match pe.buffer.get_ref::<u16>(offset) {
            Ok(l) => l,
            Err(e) => return Err(e),
        };
        
        consumed += mem::size_of::<u16>();
        offset.0 += mem::size_of::<u16>() as u32;
        if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }

        let type_value = match pe.buffer.get_ref::<u16>(offset) {
            Ok(l) => l,
            Err(e) => return Err(e),
        };
        
        consumed += mem::size_of::<u16>();
        offset.0 += mem::size_of::<u16>() as u32;
        if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }

        let key = match pe.buffer.get_widestring(offset, None) {
            Ok(w) => w,
            Err(e) => return Err(e),
        };
        
        let key_size = key.len() * mem::size_of::<WChar>();
        consumed += key_size;
        offset.0 += key_size as u32;
        if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }

        offset.0 = align(offset.0 as usize, 4) as u32;

        let mut children = Vec::<VSVar>::new();

        while consumed < (*length as usize) {
            let rva = match pe.pe_type {
                PEType::Disk => match offset.as_rva(&pe) {
                    Ok(r) => r,
                    Err(e) => return Err(e),
                },
                PEType::Memory => RVA(offset.0),
            };
            
            let child = match VSVar::parse(&pe, rva) {
                Ok(c) => c,
                Err(e) => return Err(e),
            };

            offset.0 += *child.length as u32;
            offset.0 = align(offset.0 as usize, 4) as u32;
            consumed = (offset.0 - base_offset.0) as usize;
            children.push(child);
        }
        
        Ok(Self {
            length,
            value_length,
            type_: type_value,
            key,
            children,
        })
    }
}

/// Represents a [`VS_VERSIONINFO`](https://docs.microsoft.com/en-us/windows/win32/menurc/vs-versioninfo) structure.
pub struct VSVersionInfo<'data> {
    pub length: &'data u16,
    pub value_length: &'data u16,
    pub type_: &'data u16,
    pub key: &'data [WChar],
    pub value: Option<&'data VSFixedFileInfo>,
    pub string_file_info: Option<VSStringFileInfo<'data>>,
    pub var_file_info: Option<VSVarFileInfo<'data>>,
}
impl<'data> VSVersionInfo<'data> {
    /// Parse a `VSVersionInfo` structure from the given [`PE`](PE)'s resource directory. This will return
    /// [`Error::CorruptDataDirectory`](Error::CorruptDataDirectory) if it can't find the [`Version`](ResourceID::Version) resource.
    pub fn parse(pe: &'data PE) -> Result<Self, Error> {
        let resource_dir = match ResourceDirectory::parse(pe) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        let version_rsrc = resource_dir.filter_by_type(ResourceID::Version);
        if version_rsrc.len() == 0 { return Err(Error::CorruptDataDirectory); }

        let rsrc_node = match version_rsrc[0].get_data_entry(pe) {
            Ok(d) => d,
            Err(e) => return Err(e),
        };
        
        let mut consumed = 0usize;
        let mut offset = match pe.translate(PETranslation::Memory(rsrc_node.offset_to_data)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        let base_offset = offset.clone();
        let length = match pe.buffer.get_ref::<u16>(offset) {
            Ok(l) => l,
            Err(e) => return Err(e),
        };
        
        consumed += mem::size_of::<u16>();
        offset.0 += mem::size_of::<u16>() as u32;
        if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }

        let value_length = match pe.buffer.get_ref::<u16>(offset) {
            Ok(l) => l,
            Err(e) => return Err(e),
        };
        
        consumed += mem::size_of::<u16>();
        offset.0 += mem::size_of::<u16>() as u32;
        if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }

        let type_value = match pe.buffer.get_ref::<u16>(offset) {
            Ok(l) => l,
            Err(e) => return Err(e),
        };
        
        consumed += mem::size_of::<u16>();
        offset.0 += mem::size_of::<u16>() as u32;
        if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }

        let key = match pe.buffer.get_widestring(offset, None) {
            Ok(w) => w,
            Err(e) => return Err(e),
        };
        
        let key_size = key.len() * mem::size_of::<WChar>();
        consumed += key_size;
        offset.0 += key_size as u32;
        if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }

        offset.0 = align(offset.0 as usize, 4) as u32;

        let value;
        
        if *value_length == 0 {
            value = None;
        }
        else
        {
            value = match pe.buffer.get_ref::<VSFixedFileInfo>(offset) {
                Ok(v) => Some(v),
                Err(e) => return Err(e),
            };
            
            let struct_size = mem::size_of::<VSFixedFileInfo>();
            offset.0 += struct_size as u32;
            consumed = (offset.0 - base_offset.0) as usize;
            if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }
        }

        offset.0 = align(offset.0 as usize, 4) as u32;
        let string_file_info;

        if consumed >= *length as usize {
            string_file_info = None;
        }
        else {
            let rva = match pe.pe_type { // compensate for potentially translated offset
                PEType::Disk => match offset.as_rva(pe) {
                    Ok(r) => r,
                    Err(e) => return Err(e),
                },
                PEType::Memory => RVA(offset.0),
            };
           
            let string_file_info_tmp = match VSStringFileInfo::parse(pe, rva) {
                Ok(s) => s,
                Err(e) => return Err(e),
            };

            offset.0 += *string_file_info_tmp.length as u32;
            consumed = (offset.0 - base_offset.0) as usize;
            if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }

            string_file_info = Some(string_file_info_tmp);
        }

        offset.0 = align(offset.0 as usize, 4) as u32;
        let var_file_info;

        if consumed >= *length as usize {
            var_file_info = None;
        }
        else {
            let rva = match pe.pe_type {
                PEType::Disk => match offset.as_rva(pe) {
                    Ok(r) => r,
                    Err(e) => return Err(e),
                },
                PEType::Memory => RVA(offset.0),
            };
            
            let var_file_info_tmp = match VSVarFileInfo::parse(pe, rva) {
                Ok(s) => s,
                Err(e) => return Err(e),
            };

            offset.0 += *var_file_info_tmp.length as u32;
            consumed = (offset.0 - base_offset.0) as usize;
            if consumed > *length as usize { return Err(Error::CorruptDataDirectory); }

            var_file_info = Some(var_file_info_tmp);
        }
        
        Ok(Self {
            length,
            value_length,
            type_: type_value,
            key,
            value,
            string_file_info,
            var_file_info,
        })
    }
}
