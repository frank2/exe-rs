//! This module contains all the headers necessary to parse various aspects of a PE file.
//!
//! Objects taken directly from C are typically prefixed with "Image" and will closely
//! resemble the names of their C counterparts, but named to conform to Rust standards.
//! For example, ```IMAGE_DIRECTORY_ENTRY``` is known as [`ImageDirectoryEntry`](ImageDirectoryEntry) in
//! this library.

use bitflags::bitflags;

use chrono::offset::TimeZone;
use chrono::{Local as LocalTime};

use pkbuffer::{Castable, VecBuffer};

use std::clone::Clone;
use std::cmp;
use std::collections::HashMap;
use std::default::Default;
use std::mem;
use std::slice;

#[cfg(feature="win32")] use winapi::shared::minwindef::FARPROC;
#[cfg(feature="win32")] use winapi::um::errhandlingapi::GetLastError;
#[cfg(feature="win32")] use winapi::um::libloaderapi::{LoadLibraryA, GetProcAddress};
#[cfg(feature="win32")] use winapi::um::winnt::LPCSTR;

use crate::*;
use crate::types::*;

pub const DOS_SIGNATURE: u16    = 0x5A4D;
pub const OS2_SIGNATURE: u16    = 0x454E;
pub const OS2_SIGNATURE_LE: u16 = 0x454C;
pub const VXD_SIGNATURE: u16    = 0x454C;
pub const NT_SIGNATURE: u32     = 0x00004550;

pub const HDR32_MAGIC: u16 = 0x010B;
pub const HDR64_MAGIC: u16 = 0x020B;
pub const ROM_MAGIC: u16   = 0x0107;

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Castable, Debug)]
pub struct ImageDOSHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: Offset,
}
impl Default for ImageDOSHeader {
    fn default() -> Self {
        Self {
            e_magic: DOS_SIGNATURE,
            e_cblp: 0x90,
            e_cp: 0x03,
            e_crlc: 0x0,
            e_cparhdr: 0x04,
            e_minalloc: 0x0,
            e_maxalloc: 0xFFFF,
            e_ss: 0x0,
            e_sp: 0xB8,
            e_csum: 0x0,
            e_ip: 0x0,
            e_cs: 0x0,
            e_lfarlc: 0x40,
            e_ovno: 0x0,
            e_res: [0u16; 4],
            e_oemid: 0x0,
            e_oeminfo: 0x0,
            e_res2: [0u16; 10],
            e_lfanew: Offset(0xE0),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ImageFileMachine {
    Unknown     = 0x0000,
    TargetHost  = 0x0001,
    I386        = 0x014C,
    R3000       = 0x0162,
    R4000       = 0x0166,
    R10000      = 0x0168,
    WCEMIPSV2   = 0x0169,
    Alpha       = 0x0184,
    SH3         = 0x01A2,
    SH3DSP      = 0x01A3,
    SH3E        = 0x01A4,
    SH4         = 0x01A6,
    SH5         = 0x01A8,
    ARM         = 0x01C0,
    Thumb       = 0x01C2,
    ARMNT       = 0x01C4,
    AM33        = 0x01D3,
    PowerPC     = 0x01F0,
    PowerPCFP   = 0x01F1,
    IA64        = 0x0200,
    MIPS16      = 0x0266,
    Alpha64     = 0x0284,
    MIPSFPU     = 0x0366,
    MIPSFPU16   = 0x0466,
    TRICORE     = 0x0520,
    CEF         = 0x0CEF,
    EBC         = 0x0EBC,
    AMD64       = 0x8664,
    M32R        = 0x9041,
    ARM64       = 0xAA64,
    CEE         = 0xC0EE,
}

bitflags! {
    /// A bitflag structure representing file characteristics in the file header.
    #[repr(C)]
    pub struct FileCharacteristics: u16 {
        const RELOCS_STRIPPED         = 0x0001;
        const EXECUTABLE_IMAGE        = 0x0002;
        const LINE_NUMS_STRIPPED      = 0x0004;
        const LOCAL_SYMS_STRIPPED     = 0x0008;
        const AGGRESSIVE_WS_TRIM      = 0x0010;
        const LARGE_ADDRESS_AWARE     = 0x0020;
        const BYTES_REVERSED_LO       = 0x0080;
        const MACHINE_32BIT           = 0x0100;
        const DEBUG_STRIPPED          = 0x0200;
        const REMOVABLE_RUN_FROM_SWAP = 0x0400;
        const NET_RUN_FROM_SWAP       = 0x0800;
        const SYSTEM                  = 0x1000;
        const DLL                     = 0x2000;
        const UP_SYSTEM_ONLY          = 0x4000;
        const BYTES_REVERSED_HI       = 0x8000;
    }
}
unsafe impl Castable for FileCharacteristics { }

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Castable, Debug)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: Offset,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: FileCharacteristics,
}
impl ImageFileHeader {
    /// Get the default ImageFileHeader object for x86.
    fn default_x86() -> Self {
        ImageFileHeader::default()
    }
    /// Get the default ImageFileHeader object for x64.
    fn default_x64() -> Self {
        Self {
            machine: ImageFileMachine::AMD64 as u16,
            number_of_sections: 0,
            time_date_stamp: LocalTime.timestamp_opt(0, 0).unwrap().timestamp() as u32,
            pointer_to_symbol_table: Offset(0),
            number_of_symbols: 0,
            size_of_optional_header: mem::size_of::<ImageOptionalHeader64>() as u16 + ((mem::size_of::<ImageDataDirectory>() * 16) as u16),
            characteristics: FileCharacteristics::EXECUTABLE_IMAGE | FileCharacteristics::MACHINE_32BIT,
        }
    }
}
impl Default for ImageFileHeader {
    fn default() -> Self {
        Self {
            machine: ImageFileMachine::I386 as u16,
            number_of_sections: 0,
            time_date_stamp: LocalTime.timestamp_opt(0, 0).unwrap().timestamp() as u32,
            pointer_to_symbol_table: Offset(0),
            number_of_symbols: 0,
            size_of_optional_header: (mem::size_of::<ImageOptionalHeader32>() as u16) + ((mem::size_of::<ImageDataDirectory>() * 16) as u16),
            characteristics: FileCharacteristics::EXECUTABLE_IMAGE | FileCharacteristics::MACHINE_32BIT,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ImageSubsystem {
    Unknown                  = 0,
    Native                   = 1,
    WindowsGUI               = 2,
    WindowsCUI               = 3,
    OS2CUI                   = 5,
    POSIXCUI                 = 7,
    NativeWindows            = 8,
    WindowsCEGUI             = 9,
    EFIApplication           = 10,
    EFIBootServiceDriver     = 11,
    EFIRuntimeDriver         = 12,
    EFIROM                   = 13,
    XBox                     = 14,
    WindowsBootApplication   = 16,
    XBoxCodeCatalog          = 17,
}

bitflags! {
    /// A series of bitflags representing DLL characteristics.
    #[repr(C)]
    pub struct DLLCharacteristics: u16 {
        const RESERVED1             = 0x0001;
        const RESERVED2             = 0x0002;
        const RESERVED4             = 0x0004;
        const RESERVED8             = 0x0008;
        const HIGH_ENTROPY_VA       = 0x0020;
        const DYNAMIC_BASE          = 0x0040;
        const FORCE_INTEGRITY       = 0x0080;
        const NX_COMPAT             = 0x0100;
        const NO_ISOLATION          = 0x0200;
        const NO_SEH                = 0x0400;
        const NO_BIND               = 0x0800;
        const APPCONTAINER          = 0x1000;
        const WDM_DRIVER            = 0x2000;
        const GUARD_CF              = 0x4000;
        const TERMINAL_SERVER_AWARE = 0x8000;
    }
}
unsafe impl Castable for DLLCharacteristics { }

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Castable, Debug)]
pub struct ImageOptionalHeader32 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: RVA,
    pub base_of_code: RVA,
    pub base_of_data: RVA,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: DLLCharacteristics,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}
impl Default for ImageOptionalHeader32 {
    fn default() -> Self {
        Self {
            magic: HDR32_MAGIC,
            major_linker_version: 0xE,
            minor_linker_version: 0x0,
            size_of_code: 0x0,
            size_of_initialized_data: 0x0,
            size_of_uninitialized_data: 0x0,
            address_of_entry_point: RVA(0x1000),
            base_of_code: RVA(0x1000),
            base_of_data: RVA(0),
            image_base: 0x400000,
            section_alignment: 0x1000,
            file_alignment: 0x400,
            major_operating_system_version: 4,
            minor_operating_system_version: 0,
            major_image_version: 4,
            minor_image_version: 0,
            major_subsystem_version: 4,
            minor_subsystem_version: 0,
            win32_version_value: 0,
            size_of_image: 0,
            size_of_headers: 0,
            checksum: 0,
            subsystem: ImageSubsystem::WindowsGUI as u16,
            dll_characteristics: DLLCharacteristics::DYNAMIC_BASE | DLLCharacteristics::NX_COMPAT | DLLCharacteristics::TERMINAL_SERVER_AWARE,
            size_of_stack_reserve: 0x40000,
            size_of_stack_commit: 0x2000,
            size_of_heap_reserve: 0x100000,
            size_of_heap_commit: 0x1000,
            loader_flags: 0,
            number_of_rva_and_sizes: 0x10,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Castable, Debug)]
pub struct ImageOptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: RVA,
    pub base_of_code: RVA,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: DLLCharacteristics,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}
impl Default for ImageOptionalHeader64 {
    fn default() -> Self {
        Self {
            magic: HDR64_MAGIC,
            major_linker_version: 0xE,
            minor_linker_version: 0x0,
            size_of_code: 0x0,
            size_of_initialized_data: 0x0,
            size_of_uninitialized_data: 0x0,
            address_of_entry_point: RVA(0x1000),
            base_of_code: RVA(0x1000),
            image_base: 0x140000000,
            section_alignment: 0x1000,
            file_alignment: 0x400,
            major_operating_system_version: 6,
            minor_operating_system_version: 0,
            major_image_version: 0,
            minor_image_version: 0,
            major_subsystem_version: 6,
            minor_subsystem_version: 0,
            win32_version_value: 0,
            size_of_image: 0,
            size_of_headers: 0,
            checksum: 0,
            subsystem: ImageSubsystem::WindowsGUI as u16,
            dll_characteristics: DLLCharacteristics::DYNAMIC_BASE | DLLCharacteristics::NX_COMPAT | DLLCharacteristics::TERMINAL_SERVER_AWARE,
            size_of_stack_reserve: 0x100000,
            size_of_stack_commit: 0x1000,
            size_of_heap_reserve: 0x100000,
            size_of_heap_commit: 0x1000,
            loader_flags: 0,
            number_of_rva_and_sizes: 0x10,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Castable, Debug)]
pub struct ImageNTHeaders32 {
    pub signature: u32,
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader32,
}
impl Default for ImageNTHeaders32 {
    fn default() -> Self {
        Self {
            signature: NT_SIGNATURE,
            file_header: ImageFileHeader::default_x86(),
            optional_header: ImageOptionalHeader32::default(),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Castable, Debug)]
pub struct ImageNTHeaders64 {
    pub signature: u32,
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader64,
}
impl Default for ImageNTHeaders64 {
    fn default() -> Self {
        Self {
            signature: NT_SIGNATURE,
            file_header: ImageFileHeader::default_x64(),
            optional_header: ImageOptionalHeader64::default(),
        }
    }
}

bitflags! {
    /// A series of bitflags representing section characteristics.
    #[repr(C)]
    pub struct SectionCharacteristics: u32 {
        /// Reserved for future use.
        const TYPE_REG               = 0x00000000;
        /// Reserved for future use.
        const TYPE_DSECT             = 0x00000001;
        /// Reserved for future use.
        const TYPE_NOLOAD            = 0x00000002;
        /// Reserved for future use.
        const TYPE_GROUP             = 0x00000004;
        /// The section should not be padded to the next boundary.
        /// This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES.
        /// This is valid only for object files.
        const TYPE_NO_PAD            = 0x00000008;
        /// Reserved for future use.
        const TYPE_COPY              = 0x00000010;
        /// The section contains executable code.
        const CNT_CODE               = 0x00000020;
        /// The section contains initialized data.
        const CNT_INITIALIZED_DATA   = 0x00000040;
        /// The section contains uninitialized data.
        const CNT_UNINITIALIZED_DATA = 0x00000080;
        /// Reserved for future use.
        const LNK_OTHER              = 0x00000100;
        /// The section contains comments or other information.
        /// The .drectve section has this type. This is valid for object files only.
        const LNK_INFO               = 0x00000200;
        /// Reserved for future use.
        const TYPE_OVER              = 0x00000400;
        /// The section will not become part of the image.
        /// This is valid only for object files.
        const LNK_REMOVE             = 0x00000800;
        /// The section contains COMDAT data. This is valid only for object files.
        const LNK_COMDAT             = 0x00001000;
        /// Unknown/Reserved.
        const RESERVED               = 0x00002000;
        /// Unknown flag.
        const MEM_PROTECTED          = 0x00004000;
        /// Unknown flag.
        const NO_DEFER_SPEC_EXC      = 0x00004000;
        /// The section contains data referenced through the global pointer (GP).
        const GPREL                  = 0x00008000;
        /// Reserved for future use.
        const MEM_FARDATA            = 0x00008000;
        /// Reserved for future use.
        const MEM_SYSHEAP            = 0x00010000;
        /// Reserved for future use.
        const MEM_PURGEABLE          = 0x00020000;
        /// Reserved for future use.
        const MEM_16BIT              = 0x00020000;
        /// Reserved for future use.
        const MEM_LOCKED             = 0x00040000;
        /// Reserved for future use.
        const MEM_PRELOAD            = 0x00080000;
        /// Align data on a 1-byte boundary. Valid only for object files.
        const ALIGN_1BYTES           = 0x00100000;
        /// Align data on a 2-byte boundary. Valid only for object files.
        const ALIGN_2BYTES           = 0x00200000;
        /// Align data on a 4-byte boundary. Valid only for object files.
        const ALIGN_4BYTES           = 0x00300000;
        /// Align data on an 8-byte boundary. Valid only for object files.
        const ALIGN_8BYTES           = 0x00400000;
        /// Align data on a 16-byte boundary. Valid only for object files.
        const ALIGN_16BYTES          = 0x00500000;
        /// Align data on a 32-byte boundary. Valid only for object files.
        const ALIGN_32BYTES          = 0x00600000;
        /// Align data on a 64-byte boundary. Valid only for object files.
        const ALIGN_64BYTES          = 0x00700000;
        /// Align data on a 128-byte boundary. Valid only for object files.
        const ALIGN_128BYTES         = 0x00800000;
        /// Align data on a 256-byte boundary. Valid only for object files.
        const ALIGN_256BYTES         = 0x00900000;
        /// Align data on a 512-byte boundary. Valid only for object files.
        const ALIGN_512BYTES         = 0x00A00000;
        /// Align data on a 1024-byte boundary. Valid only for object files.
        const ALIGN_1024BYTES        = 0x00B00000;
        /// Align data on a 2048-byte boundary. Valid only for object files.
        const ALIGN_2048BYTES        = 0x00C00000;
        /// Align data on a 4096-byte boundary. Valid only for object files.
        const ALIGN_4096BYTES        = 0x00D00000;
        /// Align data on an 8192-byte boundary. Valid only for object files.
        const ALIGN_8192BYTES        = 0x00E00000;
        /// Mask for alignment.
        const ALIGN_MASK             = 0x00F00000;
        /// The section contains extended relocations.
        const LNK_NRELOC_OVFL        = 0x01000000;
        /// The section can be discarded as needed.
        const MEM_DISCARDABLE        = 0x02000000;
        /// The section cannot be cached.
        const MEM_NOT_CACHED         = 0x04000000;
        /// The section is not pageable.
        const MEM_NOT_PAGED          = 0x08000000;
        /// The section can be shared in memory.
        const MEM_SHARED             = 0x10000000;
        /// The section can be executed as code.
        const MEM_EXECUTE            = 0x20000000;
        /// The section can be read.
        const MEM_READ               = 0x40000000;
        /// The section can be written to.
        const MEM_WRITE              = 0x80000000;
    }
}
unsafe impl Castable for SectionCharacteristics { }

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Castable, Debug)]
pub struct ImageSectionHeader {
    pub name: [CChar; 8],
    pub virtual_size: u32,
    pub virtual_address: RVA,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: Offset,
    pub pointer_to_relocations: Offset,
    pub pointer_to_linenumbers: Offset,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: SectionCharacteristics,
}
impl ImageSectionHeader {
    /// Set the name of this section.
    ///
    /// The name will be truncated to eight bytes. If ```name``` is [`None`](Option::None), it
    /// zeroes out the name field.
    pub fn set_name(&mut self, name: Option<&str>) {
        self.name.copy_from_slice((0..8)
                                  .map(|_| CChar(0))
                                  .collect::<Vec<CChar>>()
                                  .as_slice());
        
        if name.is_none() {
            return;
        }

        let new_name = name.unwrap();
        let name_len = cmp::min(new_name.len(),8);
        let name_vec = new_name
            .as_bytes()[..name_len]
            .iter()
            .map(|&x| CChar(x))
            .collect::<Vec<CChar>>();
        let padding = (0..(8-name_len))
            .map(|_| CChar(0))
            .collect::<Vec<CChar>>();
        
        self.name.copy_from_slice(name_vec
                                  .iter()
                                  .chain(padding.iter())
                                  .map(|&x| x)
                                  .collect::<Vec<CChar>>()
                                  .as_slice());
    }

    /// Check whether the given [`Offset`](Offset) is in this section.
    pub fn has_offset(&self, offset: Offset) -> bool {
        let start = self.pointer_to_raw_data;
        let end = Offset(start.0 + self.size_of_raw_data);

        start.0 <= offset.0 && offset.0 < end.0
    }
    /// Check whether the given [`RVA`](RVA) is in this section.
    pub fn has_rva(&self, rva: RVA) -> bool {
        let start = self.virtual_address;
        let end = RVA(start.0 + self.virtual_size);

        start.0 <= rva.0 && rva.0 < end.0
    }
    
    /// Check if the given section is aligned to the file boundary.
    pub fn is_aligned_to_file<P: PE>(&self, pe: &P) -> bool {
        pe.is_aligned_to_file(self.pointer_to_raw_data)
    }
    /// Check if the given section is aligned to the section boundary.
    pub fn is_aligned_to_section<P: PE>(&self, pe: &P) -> bool {
        pe.is_aligned_to_section(self.virtual_address)
    }

    /// Get the offset to the data this section represents. This essentially performs the same task as
    /// [`PE::translate`](PE::translate).
    pub fn data_offset(&self, pe_type: PEType) -> usize {
        match pe_type {
            PEType::Disk => self.pointer_to_raw_data.into(),
            PEType::Memory => self.virtual_address.into(),
        }
    }

    /// Get the size of this section.
    pub fn data_size(&self, pe_type: PEType) -> usize {
        match pe_type {
            PEType::Disk => self.size_of_raw_data as usize,
            PEType::Memory => self.virtual_size as usize,
        }
    }

    /// Read a slice of the data this section represents.
    ///
    /// The address and size chosen is relative to the PE argument's [type](PEType).
    pub fn read<'data, P: PE>(&'data self, pe: &'data P) -> Result<&'data [u8], Error> {
        let offset = self.data_offset(pe.get_type());
        let size = self.data_size(pe.get_type());
        let result = pe.read(offset.into(), size)?;
        Ok(result)
    }
    /// Read a mutable slice of the data this section represents.
    ///
    /// The address and size chosen is relative to the PE argument's [type](PEType).
    pub fn read_mut<'data, P: PE>(&'data self, pe: &'data mut P) -> Result<&'data mut [u8], Error> {
        let offset = self.data_offset(pe.get_type());
        let size = self.data_size(pe.get_type());
        let result = pe.read_mut(offset.into(), size)?;
        Ok(result)
    }
    /// Write data to this section.
    ///
    /// It returns [`Error::OutOfBounds`](Error::OutOfBounds) if the data overflows the section.
    /// The address and size chosen is relative to the PE argument's [type](PEType).
    pub fn write<P: PE, B: AsRef<[u8]>>(&self, pe: &mut P, data: B) -> Result<(), Error> {
        let buf = data.as_ref();
        let offset = self.data_offset(pe.get_type());
        let size = self.data_size(pe.get_type());

        if buf.len() > size {
            return Err(Error::OutOfBounds(size, buf.len()));
        }

        pe.write(offset, buf)?;
        Ok(())
    }
}
impl Default for ImageSectionHeader {
    fn default() -> Self {
        Self {
            name: [CChar(0); 8],
            virtual_size: 0,
            virtual_address: RVA(0),
            size_of_raw_data: 0,
            pointer_to_raw_data: Offset(0),
            pointer_to_relocations: Offset(0),
            pointer_to_linenumbers: Offset(0),
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: SectionCharacteristics::empty(),
        }
    }
}
    
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ImageDirectoryEntry {
    Export         = 0,
    Import         = 1,
    Resource       = 2,
    Exception      = 3,
    Security       = 4,
    BaseReloc      = 5,
    Debug          = 6,
    Architecture   = 7,
    GlobalPTR      = 8,
    TLS            = 9,
    LoadConfig     = 10,
    BoundImport    = 11,
    IAT            = 12,
    DelayImport    = 13,
    COMDescriptor  = 14,
    Reserved       = 15,
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Default, Castable, Debug)]
pub struct ImageDataDirectory {
    pub virtual_address: RVA,
    pub size: u32,
}
impl ImageDataDirectory {
    /// Parse an object at the given data directory
    pub fn cast<'data, T: Castable, P: PE>(&self, pe: &'data P) -> Result<&'data T, Error> {
        if self.virtual_address.0 == 0 || !pe.validate_rva(self.virtual_address) {
            return Err(Error::InvalidRVA(self.virtual_address));
        }

        let offset = pe.translate(PETranslation::Memory(self.virtual_address))?;
        let result = pe.get_ref::<T>(offset)?;
        Ok(result)
    }
    /// Parse a mutable object at the given data directory
    pub fn cast_mut<'data, T: Castable, P: PE>(&self, pe: &'data mut P) -> Result<&'data mut T, Error> {
        if self.virtual_address.0 == 0 || !pe.validate_rva(self.virtual_address) {
            return Err(Error::InvalidRVA(self.virtual_address));
        }

        let offset = pe.translate(PETranslation::Memory(self.virtual_address))?;
        let result = pe.get_mut_ref::<T>(offset)?;
        Ok(result)
    }
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Castable, Debug)]
pub struct ImageExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: RVA,
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: RVA, // [Thunk32; number_of_functions]
    pub address_of_names: RVA, // [RVA; number_of_names]
    pub address_of_name_ordinals: RVA, // [u16; number_of_names]
}
impl ImageExportDirectory {
    /// Parse the export table in the PE file.
    pub fn parse<'data, P: PE>(pe: &'data P) -> Result<&'data ImageExportDirectory, Error> {
        pe.cast_directory::<Self>(ImageDirectoryEntry::Export)
    }

    /// Parse a mutable export table in the PE file.
    pub fn parse_mut<'data, P: PE>(pe: &'data mut P) -> Result<&'data mut ImageExportDirectory, Error> {
        let dir = pe.get_data_directory(ImageDirectoryEntry::Export)?;

        if dir.virtual_address.0 == 0 || !pe.validate_rva(dir.virtual_address) {
            return Err(Error::InvalidRVA(dir.virtual_address));
        }

        let offset = pe.translate(PETranslation::Memory(dir.virtual_address))?;
        let result = pe.get_mut_ref::<ImageExportDirectory>(offset)?;
        Ok(result)
    }
    
    /// Get the name of this export module.
    pub fn get_name<'data, P: PE>(&self, pe: &'data P) -> Result<&'data [CChar], Error> {
        if self.name.0 == 0 {
            return Err(Error::InvalidRVA(self.name));
        }
        
        match pe.translate(PETranslation::Memory(self.name)) {
            Err(e) => return Err(e),
            Ok(a) => pe.get_cstring(a, false, None),
        }
    }
    /// Get the mutable name of this export module.
    pub fn get_mut_name<'data, P: PE>(&self, pe: &'data mut P) -> Result<&'data mut [CChar], Error> {
        if self.name.0 == 0 {
            return Err(Error::InvalidRVA(self.name));
        }

        match pe.translate(PETranslation::Memory(self.name)) {
            Err(e) => return Err(e),
            Ok(a) => pe.get_mut_cstring(a, false, None),
        }
    }
    /// Get the function array of this export entry. This array represents thunk data pointing to either
    /// ordinals [`ThunkData::Ordinal`](ThunkData::Ordinal), forwarder strings ([`ThunkData::ForwarderString`](ThunkData::ForwarderString)
    /// or function data [`ThunkData::Function`](ThunkData::Function).
    pub fn get_functions<'data, P: PE>(&self, pe: &'data P) -> Result<&'data [Thunk32], Error> {
        if self.address_of_functions.0 == 0 {
            return Err(Error::InvalidRVA(self.address_of_functions));
        }

        match pe.translate(PETranslation::Memory(self.address_of_functions)) {
            Err(e) => return Err(e),
            Ok(a) => {
                let result = pe.get_slice_ref::<Thunk32>(a, self.number_of_functions as usize)?;
                Ok(result)
            }
        }
    }
    /// Get the mutable function array of this export entry.
    pub fn get_mut_functions<'data, P: PE>(&self, pe: &'data mut P) -> Result<&'data mut [Thunk32], Error> {
        if self.address_of_functions.0 == 0 {
            return Err(Error::InvalidRVA(self.address_of_functions));
        }

        match pe.translate(PETranslation::Memory(self.address_of_functions)) {
            Err(e) => return Err(e),
            Ok(a) => {
                let result = pe.get_mut_slice_ref::<Thunk32>(a, self.number_of_functions as usize)?;
                Ok(result)
            },
        }
    }
    /// Get the name array of this export entry. This array represents RVA values pointing to zero-terminated
    /// C-style strings.
    pub fn get_names<'data, P: PE>(&self, pe: &'data P) -> Result<&'data [RVA], Error> {
        if self.address_of_names.0 == 0 {
            return Err(Error::InvalidRVA(self.address_of_names));
        }

        match pe.translate(PETranslation::Memory(self.address_of_names)) {
            Err(e) => return Err(e),
            Ok(a) => {
                let result = pe.get_slice_ref::<RVA>(a, self.number_of_names as usize)?;
                Ok(result)
            }
        }
    }
    /// Get the mutable name array of this export entry.
    pub fn get_mut_names<'data, P: PE>(&self, pe: &'data mut P) -> Result<&'data mut [RVA], Error> {
        if self.address_of_names.0 == 0 {
            return Err(Error::InvalidRVA(self.address_of_names));
        }

        match pe.translate(PETranslation::Memory(self.address_of_names)) {
            Err(e) => return Err(e),
            Ok(a) => {
                let result = pe.get_mut_slice_ref::<RVA>(a, self.number_of_names as usize)?;
                Ok(result)
            }
        }
    }
    /// Get the name ordinal array of this export entry.
    /// 
    /// This array mirrors the names array. Values in this array are indexes into the functions array,
    /// representing a name-to-function mapping.
    pub fn get_name_ordinals<'data, P: PE>(&self, pe: &'data P) -> Result<&'data [u16], Error> {
        if self.address_of_name_ordinals.0 == 0 {
            return Err(Error::InvalidRVA(self.address_of_name_ordinals));
        }

        match pe.translate(PETranslation::Memory(self.address_of_name_ordinals)) {
            Err(e) => return Err(e),
            Ok(a) => {
                let result = pe.get_slice_ref::<u16>(a, self.number_of_names as usize)?;
                Ok(result)
            },
        }
    }
    /// Get the mutable name ordinal array of this export entry.
    pub fn get_mut_name_ordinals<'data, P: PE>(&self, pe: &'data mut P) -> Result<&'data mut [u16], Error> {
        if self.address_of_name_ordinals.0 == 0 {
            return Err(Error::InvalidRVA(self.address_of_name_ordinals));
        }

        match pe.translate(PETranslation::Memory(self.address_of_name_ordinals)) {
            Err(e) => return Err(e),
            Ok(a) => {
                let result = pe.get_mut_slice_ref::<u16>(a, self.number_of_names as usize)?;
                Ok(result)
            }
        }
    }
    /// Get a mapping of exports to thunk data for this export entry.
    ///
    /// This maps exported names to thunk data, which can be an ordinal ([`ThunkData::Ordinal`](ThunkData::Ordinal)),
    /// a function ([`ThunkData::Function`](ThunkData::Function)) or a forwarder string
    /// ([`ThunkData::ForwarderString`](ThunkData::ForwarderString)).
    pub fn get_export_map<'data, P: PE>(&self, pe: &'data P) -> Result<HashMap<&'data str, ThunkData>, Error> {
        let mut result: HashMap<&'data str, ThunkData> = HashMap::<&'data str, ThunkData>::new();

        let directory = pe.get_data_directory(ImageDirectoryEntry::Export)?;
        let start = directory.virtual_address.clone();
        let end = RVA(start.0 + directory.size);

        let functions = self.get_functions(pe)?;
        let names = self.get_names(pe)?;
        let ordinals = self.get_name_ordinals(pe)?;

        for index in 0u32..self.number_of_names {
            let name_rva = names[index as usize];
            if name_rva.0 == 0 { continue; }

            let name_offset = match pe.translate(PETranslation::Memory(name_rva)) {
                Ok(o) => o,
                Err(_) => continue, /* we continue instead of returning the error to be greedy with parsing */
            };

            let name = match pe.get_cstring(name_offset, false, None) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let ordinal = ordinals[index as usize];
            let function = functions[ordinal as usize].parse_export(start, end);

            let name_str = match name.as_str() {
                Ok(s) => s,
                Err(_) => continue,
            };
            
            result.insert(name_str, function);
        }

        Ok(result)
    }

    /// Get an export name by a provided hash algorithm.
    pub fn get_export_name_by_hash<'data, T, P: PE>(&self, pe: &'data P, hash_fn: fn(&str) -> T, hash_val: T) -> Result<Option<&'data str>, Error>
    where
        T: PartialEq
    {
        let names = self.get_names(pe)?;
        
        for index in 0u32..self.number_of_names {
            let name_rva = names[index as usize];
            if name_rva.0 == 0 { continue; }

            let name_offset = pe.translate(PETranslation::Memory(name_rva))?;
            let name = pe.get_cstring(name_offset, false, None)?;
            let name_str = name.as_str()?;
            let hash_result = hash_fn(name_str);

            if hash_result == hash_val {
                return Ok(Some(name_str));
            }
        }

        Ok(None)
    }
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Castable, Debug)]
pub struct ImageImportDescriptor {
    pub original_first_thunk: RVA,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: RVA,
    pub first_thunk: RVA,
}
impl ImageImportDescriptor {
    fn parse_thunk_array_size<P: PE>(&self, pe: &P, rva: RVA) -> Result<usize, Error> {
        if rva.0 == 0 {
            return Err(Error::InvalidRVA(rva));
        }

        let arch = pe.get_arch()?;        
        let mut thunks = 0usize;
        let mut indexer = pe.translate(PETranslation::Memory(rva))?;

        loop {
            match arch {
                // sometimes this can be unaligned... thanks Microsoft
                Arch::X86 => match unsafe { pe.force_get_ref::<Thunk32>(indexer) } {
                    Ok(r) => { if r.0 == 0 { break; } },
                    Err(e) => return Err(Error::from(e)),
                },
                Arch::X64 => match unsafe { pe.force_get_ref::<Thunk64>(indexer) } {
                    Ok(r) => { if r.0 == 0 { break; } },
                    Err(e) => return Err(Error::from(e)),
                },
            };

            thunks += 1;
            indexer += match arch {
                Arch::X86 => mem::size_of::<Thunk32>(),
                Arch::X64 => mem::size_of::<Thunk64>(),
            };
        }

        Ok(thunks)
    }
    fn parse_thunk_array<'data, P: PE>(&self, pe: &'data P, rva: RVA) -> Result<Vec<Thunk<'data>>, Error> {
        if rva.0 == 0 {
            return Err(Error::InvalidRVA(rva));
        }

        let arch = pe.get_arch()?;
        let thunks = self.parse_thunk_array_size(pe, rva)?;
        let offset = pe.translate(PETranslation::Memory(rva))?;
        
        match arch {
            Arch::X86 => match unsafe { pe.force_get_slice_ref::<Thunk32>(offset, thunks) } {
                Ok(s) => Ok(s.iter().map(|x| Thunk::Thunk32(x)).collect()),
                Err(e) => Err(Error::from(e)),
            },
            Arch::X64 => match unsafe { pe.force_get_slice_ref::<Thunk64>(offset, thunks) } {
                Ok(s) => Ok(s.iter().map(|x| Thunk::Thunk64(x)).collect()),
                Err(e) => Err(Error::from(e)),
            },
        }
    }
    fn parse_mut_thunk_array<'data, P: PE>(&self, pe: &'data mut P, rva: RVA) -> Result<Vec<ThunkMut<'data>>, Error> {
        if rva.0 == 0 {
            return Err(Error::InvalidRVA(rva));
        }

        let arch = pe.get_arch()?;
        let thunks = self.parse_thunk_array_size(pe, rva)?;
        let offset = pe.translate(PETranslation::Memory(rva))?;

        match arch {
            Arch::X86 => match unsafe { pe.force_get_mut_slice_ref::<Thunk32>(offset, thunks) } {
                Ok(s) => Ok(s.iter_mut().map(|x| ThunkMut::Thunk32(x)).collect()),
                Err(e) => Err(Error::from(e)),
            },
            Arch::X64 => match unsafe { pe.force_get_mut_slice_ref::<Thunk64>(offset, thunks) } {
                Ok(s) => Ok(s.iter_mut().map(|x| ThunkMut::Thunk64(x)).collect()),
                Err(e) => Err(Error::from(e)),
            },
        }
    }

    /// Get the thunk array pointed to by the ```original_first_thunk``` field.
    pub fn get_original_first_thunk<'data, P: PE>(&self, pe: &'data P) -> Result<Vec<Thunk<'data>>, Error> {
        self.parse_thunk_array(pe, self.original_first_thunk)
    }
    /// Get the mutable thunk array pointed to by the ```original_first_thunk``` field.
    pub fn get_mut_original_first_thunk<'data, P: PE>(&self, pe: &'data mut P) -> Result<Vec<ThunkMut<'data>>, Error> {
        self.parse_mut_thunk_array(pe, self.original_first_thunk)
    }

    /// Get the name of the module represented by this import descriptor entry.
    pub fn get_name<'data, P: PE>(&self, pe: &'data P) -> Result<&'data [CChar], Error> {
        let offset = pe.translate(PETranslation::Memory(self.name))?;
        let result = pe.get_cstring(offset, false, None)?;
        Ok(result)
    }
    /// Get the mutable name of the module represented by this import descriptor entry.
    pub fn get_mut_name<'data, P: PE>(&self, pe: &'data mut P) -> Result<&'data mut [CChar], Error> {
        let offset = pe.translate(PETranslation::Memory(self.name))?;
        let result = pe.get_mut_cstring(offset, false, None)?;
        Ok(result)
    }

    /// Get the first thunk array.
    ///
    /// This array typically represents where in memory imports get resolved to.
    pub fn get_first_thunk<'data, P: PE>(&self, pe: &'data P) -> Result<Vec<Thunk<'data>>, Error> {
        self.parse_thunk_array(pe, self.first_thunk)
    }
    /// Get the mutable first thunk array.
    pub fn get_mut_first_thunk<'data, P: PE>(&self, pe: &'data mut P) -> Result<Vec<ThunkMut<'data>>, Error> {
        self.parse_mut_thunk_array(pe, self.first_thunk)
    }

    /// Get the thunk array that represents the imports, also known as the "import lookup table."
    ///
    /// This thunk array can either come from the `original_first_thunk` value or the `first_thunk` value.
    pub fn get_lookup_thunks<'data, P: PE>(&self, pe: &'data P) -> Result<Vec<Thunk<'data>>, Error> {
        match self.get_original_first_thunk(pe) {
            Ok(t) => Ok(t),
            Err(e) => {
                if let Error::InvalidRVA(_) = e { () } else { return Err(e) }
                
                self.get_first_thunk(pe)
            },
        }
    }

    /// Get the imports represented by this import descriptor.
    ///
    /// This resolves the import table and returns a vector of [`ImportData`](ImportData) objects.
    pub fn get_imports<'data, P: PE>(&self, pe: &'data P) -> Result<Vec<ImportData<'data>>, Error> {
        let mut results = Vec::<ImportData<'data>>::new();
        let thunks = self.get_lookup_thunks(pe)?;
        
        for thunk in thunks {
            let thunk_data = match thunk {
                Thunk::Thunk32(t32) => t32.parse_import(),
                Thunk::Thunk64(t64) => t64.parse_import(),
            };

            match thunk_data {
                ThunkData::Ordinal(x) => results.push(ImportData::Ordinal(x)),
                ThunkData::ImportByName(rva) => {
                    let import = ImageImportByName::parse(pe, rva)?;
                    let s = import.name.as_str()?;
                    results.push(ImportData::ImportByName(s));
                },
                _ => (),
            }
        }

        Ok(results)
    }

    /// Only available for Windows. Resolve the import address table of this import descriptor.
    ///
    /// In other words, perform the importation of the functions with `LoadLibrary` and `GetProcAddress`
    /// and store them in the import address table.
    #[cfg(feature="win32")]
    pub fn resolve_iat<P: PE>(&self, pe: &mut P) -> Result<(), Error> {
        let dll_name = match self.get_name(pe) {
            Ok(d) => match d.as_str() {
                Ok(s) => s,
                Err(e) => return Err(e),
            },
            Err(e) => return Err(e),
        };

        let dll_handle = unsafe { LoadLibraryA(dll_name.as_ptr() as LPCSTR) };

        if dll_handle == std::ptr::null_mut() {
            return Err(Error::Win32Error(unsafe { GetLastError() }));
        }
        
        let lookup_table: Vec<Thunk> = match self.get_original_first_thunk(pe) {
            Ok(l) => l,
            Err(_) => match self.get_first_thunk(pe) {
                Ok(l2) => l2,
                Err(e) => return Err(e),
            }
        };

        let mut lookup_results = Vec::<FARPROC>::new();

        for lookup in lookup_table {
            let thunk_data = match lookup {
                Thunk::Thunk32(t32) => t32.parse_import(),
                Thunk::Thunk64(t64) => t64.parse_import(),
            };

            let thunk_result = match thunk_data {
                ThunkData::Ordinal(o) => unsafe { GetProcAddress(dll_handle, o as LPCSTR) },
                ThunkData::ImportByName(rva) => {
                    let import_by_name = ImageImportByName::parse(pe, rva)?;
                    let import_str = import_by_name.name.as_str()?;
                    unsafe { GetProcAddress(dll_handle, import_str.as_ptr() as LPCSTR) }
                },
                _ => return Err(Error::CorruptDataDirectory),
            };

            if thunk_result == std::ptr::null_mut() {
                return Err(Error::Win32Error(unsafe { GetLastError() }));
            }

            lookup_results.push(thunk_result);
        }

        let mut address_table = self.get_mut_first_thunk(pe)?;
        
        if address_table.len() != lookup_results.len() {
            return Err(Error::CorruptDataDirectory);
        }

        for i in 0..address_table.len() {
            let lookup_entry = &lookup_results[i];
            let address_entry = &mut address_table[i];
                
            match address_entry {
                ThunkMut::Thunk32(ref mut t32) => **t32 = Thunk32(*lookup_entry as u32),
                ThunkMut::Thunk64(ref mut t64) => **t64 = Thunk64(*lookup_entry as u64),
            }
        }

        Ok(())
    }
}

/// Represents an ```IMAGE_IMPORT_BY_NAME``` structure.
///
/// ```IMAGE_IMPORT_BY_NAME``` is a variable-sized C structure, which is unsupported in Rust. So, we make
/// a special case for imports by name to try and still retain consistent functionality. This is why
/// this struct is a series of references instead of itself being a raw reference into data. Ultimately,
/// the locations of the two references in memory is equivalent to the C struct.
#[derive(Copy, Clone, Debug)]
pub struct ImageImportByName<'data> {
    pub hint: &'data u16,
    pub name: &'data [CChar],
}
impl<'data> ImageImportByName<'data> {
    /// Get an ```ImageImportByName``` object at the given RVA.
    pub fn parse<P: PE>(pe: &'data P, rva: RVA) -> Result<Self, Error> {
        let offset = pe.translate(PETranslation::Memory(rva))?;        
        let hint = pe.get_ref::<u16>(offset)?;
        let name = pe.get_cstring(offset + mem::size_of::<u16>(), true, None)?;

        Ok(ImageImportByName { hint, name })
    }
}

/// Represents a mutable ```IMAGE_IMPORT_BY_NAME``` structure.
pub struct ImageImportByNameMut<'data> {
    pub hint: &'data mut u16,
    pub name: &'data mut [CChar],
}
impl<'data> ImageImportByNameMut<'data> {
    /// Get a mutable ```ImageImportByName``` object at the given RVA.
    pub fn parse<P: PE>(pe: &'data mut P, rva: RVA) -> Result<Self, Error> {
        let mut offset = pe.translate(PETranslation::Memory(rva))?;

        unsafe {
            let mut ptr = pe.offset_to_mut_ptr(offset)?;

            let hint = &mut *(ptr as *mut u16);
            let u16_size = mem::size_of::<u16>();

            ptr = ptr.add(u16_size);

            if !pe.validate_ptr(ptr) {
                return Err(Error::BadPointer(ptr));
            }

            offset += u16_size;

            let name_size = pe.get_cstring_size(offset, true, None)?;            
            let name = slice::from_raw_parts_mut(ptr as *mut CChar, name_size);

            Ok(Self { hint, name })
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
/// An enum containing relocation types.
pub enum ImageRelBased {
    Absolute = 0,
    High = 1,
    Low = 2,
    HighLow = 3,
    HighAdj = 4,
    MachineSpecific5 = 5,
    Reserved = 6,
    MachineSpecific7 = 7,
    MachineSpecific8 = 8,
    MachineSpecific9 = 9,
    Dir64 = 10,
    Unknown
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Castable, Debug)]
pub struct ImageBaseRelocation {
    pub virtual_address: RVA,
    pub size_of_block: u32,
}
impl ImageBaseRelocation {
    /// Calculate the size of a relocation block with `blocks` entries.
    pub fn calculate_block_size(blocks: usize) -> u32 {
        let relocation_size = mem::size_of::<Self>();
        let word_size = mem::size_of::<u16>();

        (relocation_size + (blocks * word_size)) as u32
    }

    /// Get the number of relocation entries in this block.
    pub fn relocations(&self) -> usize {
        let relocation_size = mem::size_of::<Self>();
        let word_size = mem::size_of::<u16>();

        ((self.size_of_block as usize) - relocation_size) / word_size
    }
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Castable, Debug)]
pub struct ImageResourceDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub number_of_named_entries: u16,
    pub number_of_id_entries: u16,
}
impl ImageResourceDirectory {
    /// Get the number of entries this resource directory has.
    pub fn entries(&self) -> usize {
        (self.number_of_named_entries as usize) + (self.number_of_id_entries as usize)
    }
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Castable, Debug)]
pub struct ImageResourceDirectoryEntry {
    pub name: FlaggedDword,
    pub offset_to_data: FlaggedDword,
}
impl ImageResourceDirectoryEntry {
    /// Get the ID of this directory entry.
    ///
    /// The ID can either be a [name](ResourceDirectoryID::Name) or a numeric [ID](ResourceDirectoryID::ID).
    pub fn get_id(&self) -> ResourceDirectoryID {
        if self.name.get_flag() {
            ResourceDirectoryID::Name(ResourceOffset(self.name.get_dword()))
        }
        else {
            ResourceDirectoryID::ID(self.name.get_dword())
        }
    }
    /// Get the offset to the data this entry represents.
    ///
    /// This can be either [data](ResourceDirectoryData::Data) or [another directory](ResourceDirectoryData::Directory).
    pub fn get_data(&self) -> ResourceDirectoryData {
        if self.offset_to_data.get_flag() {
            ResourceDirectoryData::Directory(ResourceOffset(self.offset_to_data.get_dword()))
        }
        else {
            ResourceDirectoryData::Data(ResourceOffset(self.offset_to_data.get_dword()))
        }
    }
}

/// Represents an ```IMAGE_RESOURCE_DIR_STRING``` structure.
///
/// See [`ImageImportByName`](ImageImportByName) for an explanation as to why this structure
/// is different from the others.
#[derive(Clone, Debug)]
pub struct ImageResourceDirString<'data> {
    pub length: &'data u16,
    pub name: &'data [CChar],
}
impl<'data> ImageResourceDirString<'data> {
    /// Get a ```ImageResourceDirString``` object at the given RVA.
    pub fn parse<P: PE>(pe: &'data P, rva: RVA) -> Result<Self, Error> {
        let offset = pe.translate(PETranslation::Memory(rva))?;        
        let length = pe.get_ref::<u16>(offset)?;        
        let name = pe.get_slice_ref::<CChar>(offset + mem::size_of::<u16>(), *length as usize)?;

        Ok(Self { length, name })
    }
}

/// Represents a mutable ```IMAGE_RESOURCE_DIR_STRING``` structure.
///
/// See [`ImageImportByName`](ImageImportByName) for an explanation as to why this structure
/// is different from the others.
pub struct ImageResourceDirStringMut<'data> {
    pub length: &'data mut u16,
    pub name: &'data mut [CChar],
}
impl<'data> ImageResourceDirStringMut<'data> {
    /// Get a mutable ```ImageResourceDirString``` object at the given RVA.
    pub fn parse<P: PE>(pe: &'data mut P, rva: RVA) -> Result<Self, Error> {
        let offset = pe.translate(PETranslation::Memory(rva))?;

        unsafe {
            let mut ptr = pe.offset_to_mut_ptr(offset)?;
            let length = &mut *(ptr as *mut u16);
            let u16_size = mem::size_of::<u16>();

            ptr = ptr.add(u16_size);

            if !pe.validate_ptr(ptr) {
                return Err(Error::BadPointer(ptr));
            }

            let name = slice::from_raw_parts_mut(ptr as *mut CChar, *length as usize);

            Ok(Self { length, name })
        }
    }
}

/// Represents an ```IMAGE_RESOURCE_DIR_STRING_U``` structure.
///
/// See [`ImageImportByName`](ImageImportByName) for an explanation as to why this structure
/// is different from the others.
#[derive(Clone, Debug)]
pub struct ImageResourceDirStringU<'data> {
    pub length: &'data u16,
    pub name: &'data [WChar],
}
impl<'data> ImageResourceDirStringU<'data> {
    /// Get a ```ImageResourceDirStringU``` object at the given RVA.
    pub fn parse<P: PE>(pe: &'data P, rva: RVA) -> Result<Self, Error> {
        let offset = pe.translate(PETranslation::Memory(rva))?;        
        let length = pe.get_ref::<u16>(offset)?;
        let name = pe.get_slice_ref::<WChar>(offset + mem::size_of::<u16>(), *length as usize)?;

        Ok(Self { length, name })
    }
}

/// Represents a mutable ```IMAGE_RESOURCE_DIR_STRING_U``` structure.
///
/// See [`ImageImportByName`](ImageImportByName) for an explanation as to why this structure
/// is different from the others.
pub struct ImageResourceDirStringUMut<'data> {
    pub length: &'data mut u16,
    pub name: &'data mut [WChar],
}
impl<'data> ImageResourceDirStringUMut<'data> {
    /// Get a mutable ```ImageResourceDirStringU``` object at the given RVA.
    pub fn parse<P: PE>(pe: &'data mut P, rva: RVA) -> Result<Self, Error> {
        let offset = pe.translate(PETranslation::Memory(rva))?;
        
        unsafe {
            let mut ptr = pe.offset_to_mut_ptr(offset)?;
            let length = &mut *(ptr as *mut u16);
            let u16_size = mem::size_of::<u16>();

            ptr = ptr.add(u16_size);

            if !pe.validate_ptr(ptr) {
                return Err(Error::BadPointer(ptr));
            }

            let name = slice::from_raw_parts_mut(ptr as *mut WChar, *length as usize);

            Ok(Self { length, name })
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Castable, Debug)]
pub struct ImageResourceDataEntry {
    pub offset_to_data: RVA,
    pub size: u32,
    pub code_page: u32,
    pub reserved: u32,
}
impl ImageResourceDataEntry {
    /// Read the data pointed to by this data entry.
    pub fn read<'data, P: PE>(&self, pe: &'data P) -> Result<&'data [u8], Error> {
        if self.offset_to_data.0 == 0 || !pe.validate_rva(self.offset_to_data) {
            return Err(Error::InvalidRVA(self.offset_to_data));
        }

        let offset = pe.translate(PETranslation::Memory(self.offset_to_data))?;
        let result = pe.read(offset, self.size as usize)?;
        Ok(result)
    }
    /// Read mutable data pointed to by this directory entry.
    pub fn read_mut<'data, P: PE>(&self, pe: &'data mut P) -> Result<&'data mut [u8], Error> {
        if self.offset_to_data.0 == 0 || !pe.validate_rva(self.offset_to_data) {
            return Err(Error::InvalidRVA(self.offset_to_data));
        }

        let offset = pe.translate(PETranslation::Memory(self.offset_to_data))?;
        let result = pe.read_mut(offset, self.size as usize)?;
        Ok(result)
    }
    /// Write data to the directory entry.
    ///
    /// Returns [`Error::OutOfBounds`](Error::OutOfBounds) if the data overflows the buffer
    /// provided by the directory entry.
    pub fn write<P: PE, B: AsRef<[u8]>>(&self, pe: &mut P, data: B) -> Result<(), Error> {
        if self.offset_to_data.0 == 0 || !pe.validate_rva(self.offset_to_data) {
            return Err(Error::InvalidRVA(self.offset_to_data));
        }

        let offset = pe.translate(PETranslation::Memory(self.offset_to_data))?;
        let buf = data.as_ref();

        if (buf.len() as u32) > self.size {
            return Err(Error::OutOfBounds(self.size as usize, buf.len()));
        }

        pe.write(offset, buf)?;
        Ok(())
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ImageDebugType {
    Unknown = 0,
    COFF = 1,
    CodeView = 2,
    FPO = 3,
    Misc = 4,
    Exception = 5,
    FixUp = 6,
    Borland = 9,
}
impl ImageDebugType {
    /// Convert the [`u32`](u32) value to an `ImageDebugType` enum variant.
    pub fn from_u32(u: u32) -> Self {
        match u {
            1 => Self::COFF,
            2 => Self::CodeView,
            3 => Self::FPO,
            4 => Self::Misc,
            5 => Self::Exception,
            6 => Self::FixUp,
            9 => Self::Borland,
            _ => Self::Unknown,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Castable, Debug)]
pub struct ImageDebugDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub type_: u32,
    pub size_of_data: u32,
    pub address_of_raw_data: RVA,
    pub pointer_to_raw_data: Offset,
}
impl ImageDebugDirectory {
    /// Parse the debug directory in the PE file.
    pub fn parse<'data, P: PE>(pe: &'data P) -> Result<&'data Self, Error> {
        pe.cast_directory::<Self>(ImageDirectoryEntry::Debug)
    }
}

bitflags! {
    /// A series of bitflags representing TLS directory characteristics.
    #[repr(C)]
    pub struct TLSCharacteristics: u32 {
        const ALIGN_1BYTES           = 0x00100000;
        const ALIGN_2BYTES           = 0x00200000;
        const ALIGN_4BYTES           = 0x00300000;
        const ALIGN_8BYTES           = 0x00400000;
        const ALIGN_16BYTES          = 0x00500000;
        const ALIGN_32BYTES          = 0x00600000;
        const ALIGN_64BYTES          = 0x00700000;
        const ALIGN_128BYTES         = 0x00800000;
        const ALIGN_256BYTES         = 0x00900000;
        const ALIGN_512BYTES         = 0x00A00000;
        const ALIGN_1024BYTES        = 0x00B00000;
        const ALIGN_2048BYTES        = 0x00C00000;
        const ALIGN_4096BYTES        = 0x00D00000;
        const ALIGN_8192BYTES        = 0x00E00000;
        const ALIGN_MASK             = 0x00F00000;
    }
}
unsafe impl Castable for TLSCharacteristics {}
    
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Castable, Debug)]
pub struct ImageTLSDirectory32 {
    pub start_address_of_raw_data: VA32,
    pub end_address_of_raw_data: VA32,
    pub address_of_index: VA32,
    pub address_of_callbacks: VA32,
    pub size_of_zero_fill: u32,
    pub characteristics: TLSCharacteristics,
}
impl ImageTLSDirectory32 {
    /// Get the 32-bit TLS directory from the [`PE`](PE) object.
    pub fn parse<'data, P: PE>(pe: &'data P) -> Result<&'data Self, Error> {
        pe.cast_directory::<Self>(ImageDirectoryEntry::TLS)
    }

    /// Get a mutable 32-bit TLS directory from the [`PE`](PE) object.
    pub fn parse_mut<'data, P: PE>(pe: &'data mut P) -> Result<&'data mut Self, Error> {
        pe.cast_directory_mut::<Self>(ImageDirectoryEntry::TLS)
    }

    /// Get the size of the raw data buffer.
    pub fn get_raw_data_size(&self) -> usize {
        (self.end_address_of_raw_data.0 - self.start_address_of_raw_data.0) as usize
    }

    /// Read a slice of the raw data buffer.
    pub fn read<'data, P: PE>(&self, pe: &'data P) -> Result<&'data [u8], Error> {
        let size = self.get_raw_data_size();
        let offset = self.start_address_of_raw_data.as_offset(pe)?;
        let result = pe.read(offset.into(), size)?;
        Ok(result)
    }

    /// Read a mutable slice of the raw data buffer.
    pub fn read_mut<'data, P: PE>(&self, pe: &'data mut P) -> Result<&'data mut [u8], Error> {
        let size = self.get_raw_data_size();
        let offset = self.start_address_of_raw_data.as_offset(pe)?;
        let result = pe.read_mut(offset.into(), size)?;
        Ok(result)
    }

    /// Write to the raw data buffer.
    ///
    /// Returns a [`Error::OutOfBounds`](Error::OutOfBounds) error if the given data
    /// overflows the buffer space.
    pub fn write<P: PE, B: AsRef<[u8]>>(&self, pe: &mut P, data: B) -> Result<(), Error> {
        let size = self.get_raw_data_size();
        let offset = self.start_address_of_raw_data.as_offset(pe)?;
        let buf = data.as_ref();

        if buf.len() > size {
            return Err(Error::OutOfBounds(size, buf.len()));
        }

        pe.write(offset.into(), buf)?;
        Ok(())
    }

    /// Get the size of the callback array pointed to by this directory.
    pub fn get_callback_size<P: PE>(&self, pe: &P) -> Result<usize, Error> {
        let rva = self.address_of_callbacks.as_rva(pe)?;
        let offset = pe.translate(PETranslation::Memory(rva))?;
        let mut result = 0usize;
        let mut scan_offset = offset.clone();

        loop {
            let callback = pe.get_ref::<VA32>(scan_offset)?;
            
            scan_offset += mem::size_of::<VA32>();

            if callback.0 == 0 {
                return Ok(result);
            }

            result += 1;
        }
    }

    /// Get the callbacks array from the TLS directory.
    pub fn get_callbacks<'data, P: PE>(&self, pe: &'data P) -> Result<&'data [VA32], Error> {
        let rva = self.address_of_callbacks.as_rva(pe)?;
        let offset = pe.translate(PETranslation::Memory(rva))?;
        let size = self.get_callback_size(pe)?;
        let result = pe.get_slice_ref::<VA32>(offset, size)?;
        Ok(result)
    }

    /// Get a mutable array of the callbacks in this TLS directory.
    pub fn get_mut_callbacks<'data, P: PE>(&self, pe: &'data mut P) -> Result<&'data mut [VA32], Error> {
        let rva = self.address_of_callbacks.as_rva(pe)?;
        let offset = pe.translate(PETranslation::Memory(rva))?;
        let size = self.get_callback_size(pe)?;
        let result = pe.get_mut_slice_ref::<VA32>(offset, size)?;
        Ok(result)
    }
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Castable, Debug)]
pub struct ImageTLSDirectory64 {
    pub start_address_of_raw_data: VA64,
    pub end_address_of_raw_data: VA64,
    pub address_of_index: VA64,
    pub address_of_callbacks: VA64,
    pub size_of_zero_fill: u32,
    pub characteristics: TLSCharacteristics,
}
impl ImageTLSDirectory64 {
    /// Get the 64-bit TLS directory from the [`PE`](PE) object.
    pub fn parse<'data, P: PE>(pe: &'data P) -> Result<&'data Self, Error> {
        pe.cast_directory::<Self>(ImageDirectoryEntry::TLS)
    }

    /// Get a mutable 64-bit TLS directory from the [`PE`](PE) object.
    pub fn parse_mut<'data, P: PE>(pe: &'data mut P) -> Result<&'data mut Self, Error> {
        pe.cast_directory_mut::<Self>(ImageDirectoryEntry::TLS)
    }

    /// Get the size of the raw data buffer.
    pub fn get_raw_data_size(&self) -> usize {
        (self.end_address_of_raw_data.0 - self.start_address_of_raw_data.0) as usize
    }

    /// Read a slice of the raw data buffer.
    pub fn read<'data, P: PE>(&self, pe: &'data P) -> Result<&'data [u8], Error> {
        let size = self.get_raw_data_size();
        let offset = self.start_address_of_raw_data.as_offset(pe)?;
        let result = pe.read(offset.into(), size)?;
        Ok(result)
    }

    /// Read a mutable slice of the raw data buffer.
    pub fn read_mut<'data, P: PE>(&self, pe: &'data mut P) -> Result<&'data mut [u8], Error> {
        let size = self.get_raw_data_size();
        let offset = self.start_address_of_raw_data.as_offset(pe)?;
        let result = pe.read_mut(offset.into(), size)?;
        Ok(result)
    }

    /// Write to the raw data buffer.
    ///
    /// Returns a [`Error::OutOfBounds`](Error::OutOfBounds) error if the given data
    /// overflows the buffer space.
    pub fn write<P: PE, B: AsRef<[u8]>>(&self, pe: &mut P, data: B) -> Result<(), Error> {
        let size = self.get_raw_data_size();
        let offset = self.start_address_of_raw_data.as_offset(pe)?;
        let buf = data.as_ref();

        if buf.len() > size {
            return Err(Error::OutOfBounds(size, buf.len()));
        }

        let result = pe.write(offset.into(), buf)?;
        Ok(result)
    }

    /// Get the size of the callback array pointed to by this directory.
    pub fn get_callback_size<P: PE>(&self, pe: &P) -> Result<usize, Error> {
        let rva = self.address_of_callbacks.as_rva(pe)?;
        let offset = pe.translate(PETranslation::Memory(rva))?;
        let mut result = 0usize;
        let mut scan_offset = offset.clone();

        loop {
            let callback = pe.get_ref::<VA64>(scan_offset)?;
             
            scan_offset += mem::size_of::<VA64>();

            if callback.0 == 0 {
                 return Ok(result);
            }

            result += 1;
        }
    }

    /// Get the callbacks array from the TLS directory.
    pub fn get_callbacks<'data, P: PE>(&self, pe: &'data P) -> Result<&'data [VA64], Error> {
        let rva = self.address_of_callbacks.as_rva(pe)?;
        let offset = pe.translate(PETranslation::Memory(rva))?;
        let size = self.get_callback_size(pe)?;
        let result = pe.get_slice_ref::<VA64>(offset, size)?;
        Ok(result)
    }

    /// Get a mutable array of the callbacks in this TLS directory.
    pub fn get_mut_callbacks<'data, P: PE>(&self, pe: &'data mut P) -> Result<&'data mut [VA64], Error> {
        let rva = self.address_of_callbacks.as_rva(pe)?;
        let offset = pe.translate(PETranslation::Memory(rva))?;
        let size = self.get_callback_size(pe)?;
        let result = pe.get_mut_slice_ref::<VA64>(offset, size)?;
        Ok(result)
    }
}

/// Represent an entry in a resource-encoded icon group.
///
/// See [the Microsoft Icons article](https://learn.microsoft.com/en-us/previous-versions/ms997538(v=msdn.10)?redirectedfrom=MSDN)
/// for a thorough explanation.
#[repr(packed)]
#[derive(Copy, Clone, Eq, PartialEq, Castable, Debug)]
pub struct GrpIconDirEntry {
    pub width: u8,
    pub height: u8,
    pub color_count: u8,
    pub reserved: u8,
    pub planes: u16,
    pub bit_count: u16,
    pub bytes_in_res: u32,
    pub id: u16,
}
impl GrpIconDirEntry {
    /// Convert this icon directory entry from a resource directory (`GrpIconDirEntry`)
    /// to a file directory ([`IconDirEntry`](IconDirEntry)).
    pub fn to_icon_dir_entry(&self) -> IconDirEntry {
        IconDirEntry {
            width: self.width,
            height: self.height,
            color_count: self.color_count,
            reserved: self.reserved,
            planes: self.planes,
            bit_count: self.bit_count,
            bytes_in_res: self.bytes_in_res,
            image_offset: 0,
        }
    }
}

/// Represent a directory in a resource-encoded icon group.
///
/// See [the Microsoft Icons article](https://learn.microsoft.com/en-us/previous-versions/ms997538(v=msdn.10)?redirectedfrom=MSDN)
/// for a thorough explanation.
#[derive(Clone)]
pub struct GrpIconDir<'data> {
    pub reserved: &'data u16,
    pub icon_type: &'data u16,
    pub count: &'data u16,
    pub entries: &'data [GrpIconDirEntry]
}
impl<'data> GrpIconDir<'data> {
    /// Parse a resource icon at the given RVA.
    pub fn parse<P: PE>(pe: &'data P, rva: RVA) -> Result<Self, Error> {
        let offset = pe.translate(PETranslation::Memory(rva))?;
        let reserved = pe.get_ref::<u16>(offset)?;
        let icon_type = pe.get_ref::<u16>(offset+2)?;
        let count = pe.get_ref::<u16>(offset+4)?;
        let entries = pe.get_slice_ref::<GrpIconDirEntry>(offset+6, *count as usize)?;

        Ok(Self { reserved, icon_type, count, entries })
    }
    /// Convert this resource icon into a file icon.
    ///
    /// In other words, compile this group icon directory into an icon file.
    pub fn to_icon_buffer<P: PE>(&self, pe: &'data P) -> Result<VecBuffer, Error> {
        let icon_vec = IconDirVec {
            reserved: *self.reserved,
            icon_type: *self.icon_type,
            count: *self.count,
            entries: self.entries.iter().map(|x| x.to_icon_dir_entry()).collect(),
        };
        let mut icon_buf = icon_vec.to_vec_buffer()?;
        let resource_dir = ResourceDirectory::parse(pe)?;

        for index in 0..self.entries.len() {
            let entry = &self.entries[index];
            let id = ResolvedDirectoryID::ID(entry.id as u32);
            let search = resource_dir.filter(Some(ResolvedDirectoryID::ID(ResourceID::Icon as u32)), Some(id), None);
            if search.len() == 0 { return Err(Error::ResourceNotFound); }

            let entry = search[0].get_data_entry(pe)?;
            let offset = icon_buf.len();
            let data = entry.read(pe)?;

            icon_buf.append_slice_ref::<u8>(data)?;
            let vec_dir = IconDirMut::parse(&mut icon_buf)?;
            vec_dir.entries[index].image_offset = offset as u32;
        }

        Ok(icon_buf)
    }
}

/// Represent a mutable directory in a resource-encoded icon group.
///
/// See [the Microsoft Icons article](https://learn.microsoft.com/en-us/previous-versions/ms997538(v=msdn.10)?redirectedfrom=MSDN)
/// for a thorough explanation.
pub struct GrpIconDirMut<'data> {
    pub reserved: &'data mut u16,
    pub icon_type: &'data mut u16,
    pub count: &'data mut u16,
    pub entries: &'data mut [GrpIconDirEntry]
}
impl<'data> GrpIconDirMut<'data> {
    /// Parse a mutable resource icon at the given RVA.
    pub fn parse<P: PE>(pe: &'data mut P, rva: RVA) -> Result<Self, Error> {
        let offset = pe.translate(PETranslation::Memory(rva))?;

        unsafe {
            let mut ptr = pe.offset_to_mut_ptr(offset)?;
            let reserved = &mut *(ptr as *mut u16);

            ptr = pe.offset_to_mut_ptr(offset+2)?;
            let icon_type = &mut *(ptr as *mut u16);

            ptr = pe.offset_to_mut_ptr(offset+4)?;
            let count = &mut *(ptr as *mut u16);
            let entries = pe.get_mut_slice_ref::<GrpIconDirEntry>(offset+6, *count as usize)?;

            Ok(Self { reserved, icon_type, count, entries })
        }
    }
    /// Convert this resource icon into a file icon.
    ///
    /// In other words, compile this group icon directory into an icon file.
    pub fn to_icon_buffer<P: PE>(&self, pe: &'data P) -> Result<VecBuffer, Error> {
        let icon_vec = IconDirVec {
            reserved: *self.reserved,
            icon_type: *self.icon_type,
            count: *self.count,
            entries: self.entries.iter().map(|x| x.to_icon_dir_entry()).collect(),
        };
        let mut icon_buf = icon_vec.to_vec_buffer()?;
        let resource_dir = ResourceDirectory::parse(pe)?;

        for index in 0..self.entries.len() {
            let entry = &self.entries[index];
            let id = ResolvedDirectoryID::ID(entry.id as u32);
            let search = resource_dir.filter(Some(ResolvedDirectoryID::ID(ResourceID::Icon as u32)), Some(id), None);
            if search.len() == 0 { return Err(Error::ResourceNotFound); }

            let entry = search[0].get_data_entry(pe)?;
            let offset = icon_buf.len();
            let data = entry.read(pe)?;

            icon_buf.append_slice_ref::<u8>(data)?;
            let vec_dir = IconDirMut::parse(&mut icon_buf)?;
            vec_dir.entries[index].image_offset = offset as u32;
        }

        Ok(icon_buf)
    }
}
