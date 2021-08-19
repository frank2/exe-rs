//! This module contains Rust types to help with the parsing of PE files.

use std::collections::HashMap;
use std::mem;
use std::slice;

use widestring::U16Str;

use crate::{PE, PETranslation, Error};
use crate::headers::*;

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
#[repr(packed)]
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
/// use exe::PE;
/// use exe::types::{RelocationDirectory, RVA};
///
/// let buffer = std::fs::read("test/dll.dll").unwrap();
/// let dll = PE::new_disk(buffer.as_slice());
/// let relocation_dir = RelocationDirectory::parse(&dll).unwrap();
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
        let mut offset = match rva.as_offset(pe) {
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
            let ptr = match pe.buffer.offset_to_mut_ptr(offset) {
                Ok(p) => p,
                Err(e) => return Err(e),
            };

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
        let mut offset = match rva.as_offset(pe) {
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
/// use exe::PE;
/// use exe::types::{RelocationDirectory, RelocationValue, RVA};
///
/// let buffer = std::fs::read("test/dll.dll").unwrap();
/// let dll = PE::new_disk(buffer.as_slice());
/// let relocation_dir = RelocationDirectory::parse(&dll).unwrap();
/// let relocation_data = relocation_dir.relocations(&dll, 0x02000000).unwrap();
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

        let ptr = match pe.buffer.as_mut_ptr() {
            Ok(p) => p,
            Err(e) => return Err(e),
        };

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
    pub fn add_relocation(&mut self, pe: &'data mut PE, rva: RVA) -> Result<&RelocationEntry<'data>, Error> {
        let dir = match pe.get_data_directory(ImageDirectoryEntry::BaseReloc) {
            Ok(d) => d,
            Err(e) => return Err(e),
        };
        
        if dir.virtual_address.0 == 0 || !pe.validate_rva(dir.virtual_address) {
            return Err(Error::InvalidRVA);
        }

        let start_addr = dir.virtual_address.clone();
        let end_addr = RVA(start_addr.0 + dir.size);
        let base_reloc = ImageBaseRelocation { virtual_address: RVA(rva.0 & 0xFFFFF000), size_of_block: ImageBaseRelocation::calculate_block_size(1) };

        let relocation = match pe.get_arch() {
            Ok(a) => match a {
                Arch::X86 => Relocation::new(ImageRelBased::HighLow, (rva.0 & 0xFFF) as u16),
                Arch::X64 => Relocation::new(ImageRelBased::Dir64, (rva.0 & 0xFFF) as u16),
            },
            Err(e) => return Err(e),
        };

        let mut_dir = match pe.get_mut_data_directory(ImageDirectoryEntry::BaseReloc) {
            Ok(m) => m,
            Err(e) => return Err(e),
        };

        mut_dir.size += base_reloc.size_of_block;

        let entry = match RelocationEntry::create(pe, end_addr, &base_reloc, &[relocation]) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        self.entries.push(entry);

        Ok(&self.entries[self.entries.len()-1])
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
            let mut start_ptr = match pe.buffer.offset_to_mut_ptr(start_offset) {
                Ok(p) => p,
                Err(e) => return Err(e),
            };
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

        let ptr = match pe.buffer.as_mut_ptr() {
            Ok(p) => p,
            Err(e) => return Err(e),
        };

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

    /// Add a given [`RVA`](RVA) as a mutable relocation entry.
    pub fn add_relocation(&mut self, pe: &'data mut PE, rva: RVA) -> Result<&RelocationEntryMut<'data>, Error> {
        let dir = match pe.get_data_directory(ImageDirectoryEntry::BaseReloc) {
            Ok(d) => d,
            Err(e) => return Err(e),
        };
        
        if dir.virtual_address.0 == 0 || !pe.validate_rva(dir.virtual_address) {
            return Err(Error::InvalidRVA);
        }

        let start_addr = dir.virtual_address.clone();
        let end_addr = RVA(start_addr.0 + dir.size);
        let base_reloc = ImageBaseRelocation { virtual_address: RVA(rva.0 & 0xFFFFF000), size_of_block: ImageBaseRelocation::calculate_block_size(1) };

        let relocation = match pe.get_arch() {
            Ok(a) => match a {
                Arch::X86 => Relocation::new(ImageRelBased::HighLow, (rva.0 & 0xFFF) as u16),
                Arch::X64 => Relocation::new(ImageRelBased::Dir64, (rva.0 & 0xFFF) as u16),
            },
            Err(e) => return Err(e),
        };

        let mut_dir = match pe.get_mut_data_directory(ImageDirectoryEntry::BaseReloc) {
            Ok(m) => m,
            Err(e) => return Err(e),
        };

        mut_dir.size += base_reloc.size_of_block;

        let entry = match RelocationEntryMut::create(pe, end_addr, &base_reloc, &[relocation]) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        self.entries.push(entry);

        Ok(&self.entries[self.entries.len()-1])
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
    pub fn parse(pe: &'data mut PE, offset: ResourceOffset) -> Result<ResourceNodeMut<'data>, Error> {
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
            let ptr = match pe.buffer.offset_to_mut_ptr(image_offset) {
                Ok(p) => p,
                Err(e) => return Err(e),
            };

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
            let ptr = match pe.buffer.offset_to_mut_ptr(offset) {
                Ok(p) => p,
                Err(e) => return Err(e),
            };
        
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
