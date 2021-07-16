//! This module contains Rust types to help with the parsing of PE files.

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

/// Represents a C-style character unit. Basically a wrapper for ```u8```.
#[repr(packed)]
#[derive(Copy, Clone, Default, Eq, PartialEq, Debug)]
pub struct CChar(pub u8);

/* borrowed from pe-rs */
/// Syntactic sugar to get functionality out of C-char referenced slices.
pub trait CCharString {
    /// Get the zero-terminated representation of this string, or ```None``` if it is not zero-terminated.
    fn zero_terminated(&self) -> Option<&Self>;
    /// Get the string slice as a ```&str```.
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

/// Represents a UTF16 character unit. Basically a wrapper for ```u16```.
#[repr(packed)]
#[derive(Copy, Clone, Default, Eq, PartialEq, Debug)]
pub struct WChar(pub u16);

/// Syntactic sugar for dealing with UTF16 referenced slices.
pub trait WCharString {
    /// Get the zero-terminated representation of this string, or ```None``` if it is not zero-terminated.
    fn zero_terminated(&self) -> Option<&Self>;
    /// Get the string slice as a ```&U16Str```.
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
#[repr(packed)]
#[derive(Copy, Clone, Default, Eq, PartialEq, Debug)]
pub struct Offset(pub u32);
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
#[repr(packed)]
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
#[repr(packed)]
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
#[repr(packed)]
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
/// use exe::headers::ImageDirectoryEntry;
/// use exe::types::{DataDirectory, RVA};
///
/// let dll = PE::from_file("test/dll.dll").unwrap();
/// let relocation_dir = dll.resolve_data_directory(ImageDirectoryEntry::BaseReloc).unwrap();
///
/// if let DataDirectory::BaseReloc(relocation_table) = relocation_dir {
///    assert_eq!(relocation_table.len(), 1);
///
///    let entry = &relocation_table[0];
///    let addresses = entry.relocations
///                         .iter()
///                         .map(|&x| x.get_address(entry.base_relocation.virtual_address))
///                         .collect::<Vec<RVA>>();
///
///    assert_eq!(addresses[0], RVA(0x1008));
/// }
/// ```
pub struct RelocationEntry<'data> {
    pub base_relocation: &'data ImageBaseRelocation,
    pub relocations: &'data [Relocation]
}
impl<'data> RelocationEntry<'data> {
    /// Parse a relocation entry at the given RVA.
    pub fn parse(pe: &'data PE, rva: RVA) -> Result<Self, Error> {
        let relocation_size = mem::size_of::<ImageBaseRelocation>();
        let word_size = mem::size_of::<u16>();

        let offset = match pe.translate(PETranslation::Memory(rva)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };
            
        let base_relocation = match pe.buffer.get_ref::<ImageBaseRelocation>(offset) {
            Ok(b) => b,
            Err(e) => return Err(e),
        };
            
        let block_addr = Offset( ((offset.0 as usize) + relocation_size) as u32);
        let block_size = ( (base_relocation.size_of_block as usize) - relocation_size) / word_size;
        let relocations = match pe.buffer.get_slice_ref::<Relocation>(block_addr, block_size) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        Ok(Self { base_relocation, relocations })
    }
    /// Parse a relocation table with the given data directory.
    pub fn parse_table(pe: &'data PE, dir: &ImageDataDirectory) -> Result<Vec<RelocationEntry<'data>>, Error> {
        if dir.virtual_address.0 == 0 || !pe.validate_rva(dir.virtual_address) {
            return Err(Error::InvalidRVA);
        }

        let mut start_addr = dir.virtual_address.clone();
        let end_addr = RVA(start_addr.0 + dir.size);

        if !pe.validate_rva(end_addr) {
            return Err(Error::InvalidRVA);
        }

        let mut result = Vec::<RelocationEntry>::new();

        while start_addr.0 < end_addr.0 {
            let entry = match RelocationEntry::parse(pe, start_addr) {
                Ok(r) => r,
                Err(e) => return Err(e),
            };
            let size = entry.size();
            
            result.push(entry);
            start_addr.0 += size as u32;
        }

        Ok(result)
    }
    /// Get the size of this relocation entry in bytes.
    pub fn size(&self) -> usize {
        mem::size_of::<ImageBaseRelocation>() + (self.relocations.len() * mem::size_of::<Relocation>())
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

    /// Parse a mutable relocation table with the given data directory.
    pub fn parse_table(pe: &'data mut PE, dir: &ImageDataDirectory) -> Result<Vec<RelocationEntryMut<'data>>, Error> {
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

        let mut result = Vec::<RelocationEntryMut>::new();

        unsafe {
            let mut start_ptr = pe.buffer.offset_to_mut_ptr(start_offset);
            let end_ptr = pe.buffer.offset_to_ptr(end_offset);
            
            while (start_ptr as usize) < (end_ptr as usize) {
                let entry = match Self::parse_unsafe(pe, start_ptr) {
                    Ok(r) => r,
                    Err(e) => return Err(e),
                };
            
                start_ptr = start_ptr.add(entry.size());
                result.push(entry);
            }
        }

        Ok(result)
    }
    /// Get the size of this relocation entry in bytes.
    pub fn size(&self) -> usize {
        mem::size_of::<ImageBaseRelocation>() + (self.relocations.len() * mem::size_of::<Relocation>())
    }
}

/// Syntactic sugar for handling the relocation directory.
///
/// It can be used to quickly calculate the relocation data necessary before committing the data
/// to memory.
///
/// ```rust
/// use exe::PE;
/// use exe::headers::ImageDirectoryEntry;
/// use exe::types::{DataDirectory, RelocationTable, RelocationValue, RVA};
///
/// let dll = PE::from_file("test/dll.dll").unwrap();
/// let relocation_dir = dll.resolve_data_directory(ImageDirectoryEntry::BaseReloc).unwrap();
///
/// if let DataDirectory::BaseReloc(relocation_table) = relocation_dir {
///    let relocation_data = relocation_table.relocations(&dll, 0x02000000).unwrap();
///    let (rva, reloc) = relocation_data[0];
///
///    assert_eq!(rva, RVA(0x1008));
///    assert_eq!(reloc, RelocationValue::Relocation32(0x02001059));
/// }
/// ```
pub trait RelocationTable<'data> {
    /// Get the relocation values of the given relocation table.
    fn relocations(&self, pe: &'data PE, new_base: u64) -> Result<Vec<(RVA, RelocationValue)>, Error>;
    /// Relocate a PE image based on the relocation table.
    fn relocate(&self, pe: &'data mut PE, new_base: u64) -> Result<(), Error>;
}

impl<'data> RelocationTable<'data> for Vec<RelocationEntry<'data>> {
    fn relocations(&self, pe: &'data PE, new_base: u64) -> Result<Vec<(RVA, RelocationValue)>, Error> {
        let mut result = Vec::<(RVA, RelocationValue)>::new();

        for entry in self {
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
    fn relocate(&self, pe: &'data mut PE, new_base: u64) -> Result<(), Error> {
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
}

impl<'data> RelocationTable<'data> for Vec<RelocationEntryMut<'data>> {
    fn relocations(&self, pe: &'data PE, new_base: u64) -> Result<Vec<(RVA, RelocationValue)>, Error> {
        let mut result = Vec::<(RVA, RelocationValue)>::new();

        for entry in self {
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
    fn relocate(&self, pe: &'data mut PE, new_base: u64) -> Result<(), Error> {
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
}

/// An enum representing a data directory object.
///
/// Currently, the following data directories are supported:
/// * [ImageDirectoryEntry::Export](ImageDirectoryEntry::Export)
/// * [ImageDirectoryEntry::Import](ImageDirectoryEntry::Import)
/// * [ImageDirectoryEntry::BaseReloc](ImageDirectoryEntry::BaseReloc)
///
pub enum DataDirectory<'data> {
    Export(&'data ImageExportDirectory),
    Import(&'data [ImageImportDescriptor]),
    BaseReloc(Vec<RelocationEntry<'data>>),
    Unsupported,
}

/// An enum representing a mutable data directory object.
pub enum DataDirectoryMut<'data> {
    Export(&'data mut ImageExportDirectory),
    Import(&'data mut [ImageImportDescriptor]),
    BaseReloc(Vec<RelocationEntryMut<'data>>),
    Unsupported,
}
