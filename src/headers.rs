//! This module contains all the headers necessary to parse various aspects of a PE file.
//!
//! Objects taken directly from C are typically prefixed with "Image" and will closely
//! resemble the names of their C counterparts, but named to conform to Rust standards.
//! For example, ```IMAGE_DIRECTORY_ENTRY``` is known as [`ImageDirectoryEntry`](ImageDirectoryEntry) in
//! this library.

use bitflags::bitflags;

use chrono::offset::{Offset as ChronoOffset};
use chrono::offset::TimeZone;
use chrono::{Local as LocalTime};

use std::clone::Clone;
use std::cmp;
use std::collections::HashMap;
use std::default::Default;
use std::mem;
use std::slice;

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

#[repr(packed)]
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
impl Clone for ImageDOSHeader {
    fn clone(&self) -> Self {
        // I have no idea why this is usafe but something similar below isn't.
        unsafe {
            Self {
                e_magic: self.e_magic,
                e_cblp: self.e_cblp,
                e_cp: self.e_cp,
                e_crlc: self.e_crlc,
                e_cparhdr: self.e_cparhdr,
                e_minalloc: self.e_minalloc,
                e_maxalloc: self.e_maxalloc,
                e_ss: self.e_ss,
                e_sp: self.e_sp,
                e_csum: self.e_csum,
                e_ip: self.e_ip,
                e_cs: self.e_cs,
                e_lfarlc: self.e_lfarlc,
                e_ovno: self.e_ovno,
                e_res: self.e_res.clone(),
                e_oemid: self.e_oemid,
                e_oeminfo: self.e_oeminfo,
                e_res2: self.e_res2.clone(),
                e_lfanew: self.e_lfanew,
            }
        }
    }
    fn clone_from(&mut self, source: &Self) {
        self.e_magic = source.e_magic;
        self.e_cblp = source.e_cblp;
        self.e_cp = source.e_cp;
        self.e_crlc = source.e_crlc;
        self.e_cparhdr = source.e_cparhdr;
        self.e_minalloc = source.e_minalloc;
        self.e_maxalloc = source.e_maxalloc;
        self.e_ss = source.e_ss;
        self.e_sp = source.e_sp;
        self.e_csum = source.e_csum;
        self.e_ip = source.e_ip;
        self.e_cs = source.e_cs;
        self.e_lfarlc = source.e_lfarlc;
        self.e_ovno = source.e_ovno;
        unsafe { self.e_res = source.e_res.clone(); }
        self.e_oemid = source.e_oemid;
        self.e_oeminfo = source.e_oeminfo;
        unsafe { self.e_res2 = source.e_res2.clone(); }
        self.e_lfanew = source.e_lfanew;
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

#[repr(packed)]
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
            time_date_stamp: LocalTime.timestamp(0, 0).timestamp() as u32,
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
            time_date_stamp: LocalTime.timestamp(0, 0).timestamp() as u32,
            pointer_to_symbol_table: Offset(0),
            number_of_symbols: 0,
            size_of_optional_header: (mem::size_of::<ImageOptionalHeader32>() as u16) + ((mem::size_of::<ImageDataDirectory>() * 16) as u16),
            characteristics: FileCharacteristics::EXECUTABLE_IMAGE | FileCharacteristics::MACHINE_32BIT,
        }
    }
}
impl Clone for ImageFileHeader {
    fn clone(&self) -> Self {
        Self {
            machine: self.machine,
            number_of_sections: self.number_of_sections,
            time_date_stamp: self.time_date_stamp,
            pointer_to_symbol_table: self.pointer_to_symbol_table,
            number_of_symbols: self.number_of_symbols,
            size_of_optional_header: self.size_of_optional_header,
            characteristics: self.characteristics,
        }
    }
    fn clone_from(&mut self, source: &Self) {
        self.machine = source.machine;
        self.number_of_sections = source.number_of_sections;
        self.time_date_stamp = source.time_date_stamp;
        self.pointer_to_symbol_table = source.pointer_to_symbol_table;
        self.number_of_symbols = source.number_of_symbols;
        self.size_of_optional_header = source.size_of_optional_header;
        self.characteristics = source.characteristics;
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

#[repr(packed)]
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
impl Clone for ImageOptionalHeader32 {
    fn clone(&self) -> Self {
        Self {
            magic: self.magic,
            major_linker_version: self.major_linker_version,
            minor_linker_version: self.minor_linker_version,
            size_of_code: self.size_of_code,
            size_of_initialized_data: self.size_of_initialized_data,
            size_of_uninitialized_data: self.size_of_uninitialized_data,
            address_of_entry_point: self.address_of_entry_point,
            base_of_code: self.base_of_code,
            base_of_data: self.base_of_data,
            image_base: self.image_base,
            section_alignment: self.section_alignment,
            file_alignment: self.file_alignment,
            major_operating_system_version: self.major_operating_system_version,
            minor_operating_system_version: self.minor_operating_system_version,
            major_image_version: self.major_image_version,
            minor_image_version: self.minor_image_version,
            major_subsystem_version: self.major_subsystem_version,
            minor_subsystem_version: self.minor_subsystem_version,
            win32_version_value: self.win32_version_value,
            size_of_image: self.size_of_image,
            size_of_headers: self.size_of_headers,
            checksum: self.checksum,
            subsystem: self.subsystem,
            dll_characteristics: self.dll_characteristics,
            size_of_stack_reserve: self.size_of_stack_reserve,
            size_of_stack_commit: self.size_of_stack_commit,
            size_of_heap_reserve: self.size_of_heap_reserve,
            size_of_heap_commit: self.size_of_heap_commit,
            loader_flags: self.loader_flags,
            number_of_rva_and_sizes: self.number_of_rva_and_sizes,
        }
    }

    fn clone_from(&mut self, source: &Self) {
        self.magic = source.magic;
        self.major_linker_version = source.major_linker_version;
        self.minor_linker_version = source.minor_linker_version;
        self.size_of_code = source.size_of_code;
        self.size_of_initialized_data = source.size_of_initialized_data;
        self.size_of_uninitialized_data = source.size_of_uninitialized_data;
        self.address_of_entry_point = source.address_of_entry_point;
        self.base_of_code = source.base_of_code;
        self.base_of_data = source.base_of_data;
        self.image_base = source.image_base;
        self.section_alignment = source.section_alignment;
        self.file_alignment = source.file_alignment;
        self.major_operating_system_version = source.major_operating_system_version;
        self.minor_operating_system_version = source.minor_operating_system_version;
        self.major_image_version = source.major_image_version;
        self.minor_image_version = source.minor_image_version;
        self.major_subsystem_version = source.major_subsystem_version;
        self.minor_subsystem_version = source.minor_subsystem_version;
        self.win32_version_value = source.win32_version_value;
        self.size_of_image = source.size_of_image;
        self.size_of_headers = source.size_of_headers;
        self.checksum = source.checksum;
        self.subsystem = source.subsystem;
        self.dll_characteristics = source.dll_characteristics;
        self.size_of_stack_reserve = source.size_of_stack_reserve;
        self.size_of_stack_commit = source.size_of_stack_commit;
        self.size_of_heap_reserve = source.size_of_heap_reserve;
        self.size_of_heap_commit = source.size_of_heap_commit;
        self.loader_flags = source.loader_flags;
        self.number_of_rva_and_sizes = source.number_of_rva_and_sizes;
    }
}

#[repr(packed)]
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
impl Clone for ImageOptionalHeader64 {
    fn clone(&self) -> Self {
        Self {
            magic: self.magic,
            major_linker_version: self.major_linker_version,
            minor_linker_version: self.minor_linker_version,
            size_of_code: self.size_of_code,
            size_of_initialized_data: self.size_of_initialized_data,
            size_of_uninitialized_data: self.size_of_uninitialized_data,
            address_of_entry_point: self.address_of_entry_point,
            base_of_code: self.base_of_code,
            image_base: self.image_base,
            section_alignment: self.section_alignment,
            file_alignment: self.file_alignment,
            major_operating_system_version: self.major_operating_system_version,
            minor_operating_system_version: self.minor_operating_system_version,
            major_image_version: self.major_image_version,
            minor_image_version: self.minor_image_version,
            major_subsystem_version: self.major_subsystem_version,
            minor_subsystem_version: self.minor_subsystem_version,
            win32_version_value: self.win32_version_value,
            size_of_image: self.size_of_image,
            size_of_headers: self.size_of_headers,
            checksum: self.checksum,
            subsystem: self.subsystem,
            dll_characteristics: self.dll_characteristics,
            size_of_stack_reserve: self.size_of_stack_reserve,
            size_of_stack_commit: self.size_of_stack_commit,
            size_of_heap_reserve: self.size_of_heap_reserve,
            size_of_heap_commit: self.size_of_heap_commit,
            loader_flags: self.loader_flags,
            number_of_rva_and_sizes: self.number_of_rva_and_sizes,
        }
    }

    fn clone_from(&mut self, source: &Self) {
        self.magic = source.magic;
        self.major_linker_version = source.major_linker_version;
        self.minor_linker_version = source.minor_linker_version;
        self.size_of_code = source.size_of_code;
        self.size_of_initialized_data = source.size_of_initialized_data;
        self.size_of_uninitialized_data = source.size_of_uninitialized_data;
        self.address_of_entry_point = source.address_of_entry_point;
        self.base_of_code = source.base_of_code;
        self.image_base = source.image_base;
        self.section_alignment = source.section_alignment;
        self.file_alignment = source.file_alignment;
        self.major_operating_system_version = source.major_operating_system_version;
        self.minor_operating_system_version = source.minor_operating_system_version;
        self.major_image_version = source.major_image_version;
        self.minor_image_version = source.minor_image_version;
        self.major_subsystem_version = source.major_subsystem_version;
        self.minor_subsystem_version = source.minor_subsystem_version;
        self.win32_version_value = source.win32_version_value;
        self.size_of_image = source.size_of_image;
        self.size_of_headers = source.size_of_headers;
        self.checksum = source.checksum;
        self.subsystem = source.subsystem;
        self.dll_characteristics = source.dll_characteristics;
        self.size_of_stack_reserve = source.size_of_stack_reserve;
        self.size_of_stack_commit = source.size_of_stack_commit;
        self.size_of_heap_reserve = source.size_of_heap_reserve;
        self.size_of_heap_commit = source.size_of_heap_commit;
        self.loader_flags = source.loader_flags;
        self.number_of_rva_and_sizes = source.number_of_rva_and_sizes;
    }
}

#[repr(packed)]
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
impl Clone for ImageNTHeaders32 {
    fn clone(&self) -> Self {
        Self {
            signature: self.signature,
            file_header: self.file_header.clone(),
            optional_header: self.optional_header.clone(),
        }
    }
    fn clone_from(&mut self, source: &Self) {
        self.signature = source.signature;
        self.file_header = source.file_header.clone();
        self.optional_header = source.optional_header.clone();
    }
}

#[repr(packed)]
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
impl Clone for ImageNTHeaders64 {
    fn clone(&self) -> Self {
        Self {
            signature: self.signature,
            file_header: self.file_header.clone(),
            optional_header: self.optional_header.clone(),
        }
    }
    fn clone_from(&mut self, source: &Self) {
        self.signature = source.signature;
        self.file_header = source.file_header.clone();
        self.optional_header = source.optional_header.clone();
    }
}

bitflags! {
    /// A series of bitflags representing section characteristics.
    pub struct SectionCharacteristics: u32 {
        const TYPE_REG               = 0x00000000;
        const TYPE_DSECT             = 0x00000001;
        const TYPE_NOLOAD            = 0x00000002;
        const TYPE_GROUP             = 0x00000004;
        const TYPE_NO_PAD            = 0x00000008;
        const TYPE_COPY              = 0x00000010;
        const CNT_CODE               = 0x00000020;
        const CNT_INITIALIZED_DATA   = 0x00000040;
        const CNT_UNINITIALIZED_DATA = 0x00000080;
        const LNK_OTHER              = 0x00000100;
        const LNK_INFO               = 0x00000200;
        const TYPE_OVER              = 0x00000400;
        const LNK_REMOVE             = 0x00000800;
        const LNK_COMDAT             = 0x00001000;
        const RESERVED               = 0x00002000;
        const MEM_PROTECTED          = 0x00004000;
        const NO_DEFER_SPEC_EXC      = 0x00004000;
        const GPREL                  = 0x00008000;
        const MEM_FARDATA            = 0x00008000;
        const MEM_SYSHEAP            = 0x00010000;
        const MEM_PURGEABLE          = 0x00020000;
        const MEM_16BIT              = 0x00020000;
        const MEM_LOCKED             = 0x00040000;
        const MEM_PRELOAD            = 0x00080000;
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
        const LNK_NRELOC_OVFL        = 0x01000000;
        const MEM_DISCARDABLE        = 0x02000000;
        const MEM_NOT_CACHED         = 0x04000000;
        const MEM_NOT_PAGED          = 0x08000000;
        const MEM_SHARED             = 0x10000000;
        const MEM_EXECUTE            = 0x20000000;
        const MEM_READ               = 0x40000000;
        const MEM_WRITE              = 0x80000000;
    }
}

#[repr(packed)]
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
    /// Set the name of this section. The name will be truncated to eight bytes. If ```name``` is [`None`](Option::None), it
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
    pub fn is_aligned_to_file(&self, pe: &PE) -> bool {
        pe.is_aligned_to_file(self.pointer_to_raw_data)
    }
    /// Check if the given section is aligned to the section boundary.
    pub fn is_aligned_to_section(&self, pe: &PE) -> bool {
        pe.is_aligned_to_section(self.virtual_address)
    }

    /// Get the offset to the data this section represents. This essentially performs the same task as
    /// [`PE::translate`](PE::translate).
    pub fn data_offset(&self, pe_type: PEType) -> Offset {
        match pe_type {
            PEType::Disk => self.pointer_to_raw_data,
            PEType::Memory => Offset(self.virtual_address.0),
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
    pub fn read<'data>(&'data self, pe: &'data PE) -> Result<&'data [u8], Error> {
        let offset = self.data_offset(pe.pe_type);
        let size = self.data_size(pe.pe_type);

        pe.buffer.read(offset, size)
    }
    /// Read a mutable slice of the data this section represents.
    ///
    /// The address and size chosen is relative to the PE argument's [type](PEType).
    pub fn read_mut<'data>(&'data self, pe: &'data mut PE) -> Result<&'data mut [u8], Error> {
        let offset = self.data_offset(pe.pe_type);
        let size = self.data_size(pe.pe_type);

        pe.buffer.read_mut(offset, size)
    }
    /// Write data to this section. It returns [`Error::BufferTooSmall`](Error::BufferTooSmall) if the data
    /// overflows the section.
    ///
    /// The address and size chosen is relative to the PE argument's [type](PEType).
    pub fn write(&self, pe: &mut PE, data: &[u8]) -> Result<(), Error> {
        let offset = self.data_offset(pe.pe_type);
        let size = self.data_size(pe.pe_type);

        if data.len() > size {
            return Err(Error::BufferTooSmall);
        }

        pe.buffer.write(offset, data)
    }
}
impl Clone for ImageSectionHeader {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            virtual_size: self.virtual_size,
            virtual_address: self.virtual_address,
            size_of_raw_data: self.size_of_raw_data,
            pointer_to_raw_data: self.pointer_to_raw_data,
            pointer_to_relocations: self.pointer_to_relocations,
            pointer_to_linenumbers: self.pointer_to_linenumbers,
            number_of_relocations: self.number_of_relocations,
            number_of_linenumbers: self.number_of_linenumbers,
            characteristics: self.characteristics,
        }
    }
    fn clone_from(&mut self, source: &Self) {
        self.name = source.name.clone();
        self.virtual_size = source.virtual_size;
        self.virtual_address = source.virtual_address;
        self.size_of_raw_data = source.size_of_raw_data;
        self.pointer_to_raw_data = source.pointer_to_raw_data;
        self.pointer_to_relocations = source.pointer_to_relocations;
        self.pointer_to_linenumbers = source.pointer_to_linenumbers;
        self.number_of_relocations = source.number_of_relocations;
        self.number_of_linenumbers = source.number_of_linenumbers;
        self.characteristics = source.characteristics;
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

#[repr(packed)]
#[derive(Default)]
pub struct ImageDataDirectory {
    pub virtual_address: RVA,
    pub size: u32,
}
impl Clone for ImageDataDirectory {
    fn clone(&self) -> Self {
        Self {
            virtual_address: self.virtual_address,
            size: self.size,
        }
    }

    fn clone_from(&mut self, source: &Self) {
        self.virtual_address = source.virtual_address;
        self.size = source.size;
    }
}

#[repr(packed)]
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
    pub fn parse<'data>(pe: &'data PE) -> Result<&'data ImageExportDirectory, Error> {
        let dir = match pe.get_data_directory(ImageDirectoryEntry::Export) {
            Ok(d) => d,
            Err(e) => return Err(e),
        };

        if dir.virtual_address.0 == 0 || !pe.validate_rva(dir.virtual_address) {
            return Err(Error::InvalidRVA);
        }

        let offset = match pe.translate(PETranslation::Memory(dir.virtual_address)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        pe.buffer.get_ref::<ImageExportDirectory>(offset)
    }

    /// Parse a mutable export table in the PE file.
    pub fn parse_mut<'data>(pe: &'data mut PE) -> Result<&'data mut ImageExportDirectory, Error> {
        let dir = match pe.get_data_directory(ImageDirectoryEntry::Export) {
            Ok(d) => d,
            Err(e) => return Err(e),
        };

        if dir.virtual_address.0 == 0 || !pe.validate_rva(dir.virtual_address) {
            return Err(Error::InvalidRVA);
        }

        let offset = match pe.translate(PETranslation::Memory(dir.virtual_address)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        pe.buffer.get_mut_ref::<ImageExportDirectory>(offset)
    }
    
    /// Get the name of this export module.
    pub fn get_name<'data>(&self, pe: &'data PE) -> Result<&'data [CChar], Error> {
        if self.name.0 == 0 {
            return Err(Error::InvalidRVA);
        }
        
        match pe.translate(PETranslation::Memory(self.name)) {
            Err(e) => return Err(e),
            Ok(a) => pe.buffer.get_cstring(a, false, None),
        }
    }
    /// Get the mutable name of this export module.
    pub fn get_mut_name<'data>(&self, pe: &'data mut PE) -> Result<&'data mut [CChar], Error> {
        if self.name.0 == 0 {
            return Err(Error::InvalidRVA);
        }

        match pe.translate(PETranslation::Memory(self.name)) {
            Err(e) => return Err(e),
            Ok(a) => pe.buffer.get_mut_cstring(a, false, None),
        }
    }
    /// Get the function array of this export entry. This array represents thunk data pointing to either
    /// ordinals [`ThunkData::Ordinal`](ThunkData::Ordinal), forwarder strings ([`ThunkData::ForwarderString`](ThunkData::ForwarderString)
    /// or function data [`ThunkData::Function`](ThunkData::Function).
    pub fn get_functions<'data>(&self, pe: &'data PE) -> Result<&'data [Thunk32], Error> {
        if self.address_of_functions.0 == 0 {
            return Err(Error::InvalidRVA);
        }

        match pe.translate(PETranslation::Memory(self.address_of_functions)) {
            Err(e) => return Err(e),
            Ok(a) => pe.buffer.get_slice_ref::<Thunk32>(a, self.number_of_functions as usize),
        }
    }
    /// Get the mutable function array of this export entry.
    pub fn get_mut_functions<'data>(&self, pe: &'data mut PE) -> Result<&'data mut [Thunk32], Error> {
        if self.address_of_functions.0 == 0 {
            return Err(Error::InvalidRVA);
        }

        match pe.translate(PETranslation::Memory(self.address_of_functions)) {
            Err(e) => return Err(e),
            Ok(a) => pe.buffer.get_mut_slice_ref::<Thunk32>(a, self.number_of_functions as usize),
        }
    }
    /// Get the name array of this export entry. This array represents RVA values pointing to zero-terminated
    /// C-style strings.
    pub fn get_names<'data>(&self, pe: &'data PE) -> Result<&'data [RVA], Error> {
        if self.address_of_names.0 == 0 {
            return Err(Error::InvalidRVA);
        }

        match pe.translate(PETranslation::Memory(self.address_of_names)) {
            Err(e) => return Err(e),
            Ok(a) => pe.buffer.get_slice_ref::<RVA>(a, self.number_of_names as usize),
        }
    }
    /// Get the mutable name array of this export entry.
    pub fn get_mut_names<'data>(&self, pe: &'data mut PE) -> Result<&'data mut [RVA], Error> {
        if self.address_of_names.0 == 0 {
            return Err(Error::InvalidRVA);
        }

        match pe.translate(PETranslation::Memory(self.address_of_names)) {
            Err(e) => return Err(e),
            Ok(a) => pe.buffer.get_mut_slice_ref::<RVA>(a, self.number_of_names as usize),
        }
    }
    /// Get the name ordinal array of this export entry. This array mirrors the names array. Values in this
    /// array are indexes into the functions array, representing a name-to-function mapping.
    pub fn get_name_ordinals<'data>(&self, pe: &'data PE) -> Result<&'data [u16], Error> {
        if self.address_of_name_ordinals.0 == 0 {
            return Err(Error::InvalidRVA);
        }

        match pe.translate(PETranslation::Memory(self.address_of_name_ordinals)) {
            Err(e) => return Err(e),
            Ok(a) => pe.buffer.get_slice_ref::<u16>(a, self.number_of_names as usize),
        }
    }
    /// Get the mutable name ordinal array of this export entry.
    pub fn get_mut_name_ordinals<'data>(&self, pe: &'data mut PE) -> Result<&'data mut [u16], Error> {
        if self.address_of_name_ordinals.0 == 0 {
            return Err(Error::InvalidRVA);
        }

        match pe.translate(PETranslation::Memory(self.address_of_name_ordinals)) {
            Err(e) => return Err(e),
            Ok(a) => pe.buffer.get_mut_slice_ref::<u16>(a, self.number_of_names as usize),
        }
    }
    /// Get a mapping of exports to thunk data for this export entry. This maps exported names to thunk data, which can
    /// be an ordinal ([`ThunkData::Ordinal`](ThunkData::Ordinal)), a function ([`ThunkData::Function`](ThunkData::Function))
    /// or a forwarder string ([`ThunkData::ForwarderString`](ThunkData::ForwarderString)).
    pub fn get_export_map<'data>(&self, pe: &'data PE) -> Result<HashMap<&'data str, ThunkData>, Error> {
        let mut result: HashMap<&'data str, ThunkData> = HashMap::<&'data str, ThunkData>::new();

        let directory = match pe.get_data_directory(ImageDirectoryEntry::Export) {
            Ok(d) => d,
            Err(e) => return Err(e),
        };

        let start = directory.virtual_address.clone();
        let end = RVA(start.0 + directory.size);

        let functions = match self.get_functions(pe) {
            Ok(f) => f,
            Err(e) => return Err(e),
        };

        let names = match self.get_names(pe) {
            Ok(n) => n,
            Err(e) => return Err(e),
        };

        let ordinals = match self.get_name_ordinals(pe) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        for index in 0u32..self.number_of_names {
            let name_rva = names[index as usize];
            if name_rva.0 == 0 { continue; }

            let name_offset = match pe.translate(PETranslation::Memory(name_rva)) {
                Ok(o) => o,
                Err(_) => continue, /* we continue instead of returning the error to be greedy with parsing */
            };

            let name = match pe.buffer.get_cstring(name_offset, false, None) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let ordinal = ordinals[index as usize];
            let function = functions[ordinal as usize].parse_export(start, end);

            result.insert(name.as_str(), function);
        }

        Ok(result)
    }
}
impl Clone for ImageExportDirectory {
    fn clone(&self) -> Self {
        Self {
            characteristics: self.characteristics,
            time_date_stamp: self.time_date_stamp,
            major_version: self.major_version,
            minor_version: self.minor_version,
            name: self.name,
            base: self.base,
            number_of_functions: self.number_of_functions,
            number_of_names: self.number_of_names,
            address_of_functions: self.address_of_functions,
            address_of_names: self.address_of_names,
            address_of_name_ordinals: self.address_of_name_ordinals,
        }
    }
    fn clone_from(&mut self, source: &Self) {
        self.characteristics = source.characteristics;
        self.time_date_stamp = source.time_date_stamp;
        self.major_version = source.major_version;
        self.minor_version = source.minor_version;
        self.name = source.name;
        self.base = source.base;
        self.number_of_functions = source.number_of_functions;
        self.number_of_names = source.number_of_names;
        self.address_of_functions = source.address_of_functions;
        self.address_of_names = source.address_of_names;
        self.address_of_name_ordinals = source.address_of_name_ordinals;
    }
}

#[repr(packed)]
pub struct ImageImportDescriptor {
    pub original_first_thunk: RVA,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: RVA,
    pub first_thunk: RVA,
}
impl ImageImportDescriptor {
    fn parse_thunk_array_size(&self, pe: &PE, rva: RVA) -> Result<usize, Error> {
        if rva.0 == 0 {
            return Err(Error::InvalidRVA);
        }

        let arch = match pe.get_arch() {
            Ok(a) => a,
            Err(e) => return Err(e),
        };
        
        let mut thunks = 0usize;
        let mut indexer = match pe.translate(PETranslation::Memory(rva)) {
            Ok(i) => i,
            Err(e) => return Err(e),
        };

        loop {
            if !pe.validate_offset(indexer) {
                return Err(Error::InvalidOffset);
            }

            match arch {
                Arch::X86 => match pe.buffer.get_ref::<Thunk32>(indexer) {
                    Ok(r) => { if r.0 == 0 { break; } },
                    Err(e) => return Err(e),
                },
                Arch::X64 => match pe.buffer.get_ref::<Thunk64>(indexer) {
                    Ok(r) => { if r.0 == 0 { break; } },
                    Err(e) => return Err(e),
                },
            };

            thunks += 1;
            indexer.0 += match arch {
                Arch::X86 => mem::size_of::<Thunk32>() as u32,
                Arch::X64 => mem::size_of::<Thunk64>() as u32,
            };
        }

        Ok(thunks)
    }
    fn parse_thunk_array<'data>(&self, pe: &'data PE, rva: RVA) -> Result<Vec<Thunk<'data>>, Error> {
        if rva.0 == 0 {
            return Err(Error::InvalidRVA);
        }

        let arch = match pe.get_arch() {
            Ok(a) => a,
            Err(e) => return Err(e),
        };

        let thunks = match self.parse_thunk_array_size(pe, rva) {
            Ok(t) => t,
            Err(e) => return Err(e),
        };

        let offset = match pe.translate(PETranslation::Memory(rva)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        match arch {
            Arch::X86 => match pe.buffer.get_slice_ref::<Thunk32>(offset, thunks) {
                Ok(s) => Ok(s.iter().map(|x| Thunk::Thunk32(x)).collect()),
                Err(e) => Err(e),
            },
            Arch::X64 => match pe.buffer.get_slice_ref::<Thunk64>(offset, thunks) {
                Ok(s) => Ok(s.iter().map(|x| Thunk::Thunk64(x)).collect()),
                Err(e) => Err(e),
            },
        }
    }
    fn parse_mut_thunk_array<'data>(&self, pe: &'data mut PE, rva: RVA) -> Result<Vec<ThunkMut<'data>>, Error> {
        if rva.0 == 0 {
            return Err(Error::InvalidRVA);
        }

        let arch = match pe.get_arch() {
            Ok(a) => a,
            Err(e) => return Err(e),
        };

        let thunks = match self.parse_thunk_array_size(pe, rva) {
            Ok(t) => t,
            Err(e) => return Err(e),
        };

        let offset = match pe.translate(PETranslation::Memory(rva)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        match arch {
            Arch::X86 => match pe.buffer.get_mut_slice_ref::<Thunk32>(offset, thunks) {
                Ok(s) => Ok(s.iter_mut().map(|x| ThunkMut::Thunk32(x)).collect()),
                Err(e) => Err(e),
            },
            Arch::X64 => match pe.buffer.get_mut_slice_ref::<Thunk64>(offset, thunks) {
                Ok(s) => Ok(s.iter_mut().map(|x| ThunkMut::Thunk64(x)).collect()),
                Err(e) => Err(e),
            },
        }
    }

    /// Get the thunk array pointed to by the ```original_first_thunk``` field.
    pub fn get_original_first_thunk<'data>(&self, pe: &'data PE) -> Result<Vec<Thunk<'data>>, Error> {
        self.parse_thunk_array(pe, self.original_first_thunk)
    }
    /// Get the mutable thunk array pointed to by the ```original_first_thunk``` field.
    pub fn get_mut_original_first_thunk<'data>(&self, pe: &'data mut PE) -> Result<Vec<ThunkMut<'data>>, Error> {
        self.parse_mut_thunk_array(pe, self.original_first_thunk)
    }

    /// Get the name of the module represented by this import descriptor entry.
    pub fn get_name<'data>(&self, pe: &'data PE) -> Result<&'data [CChar], Error> {
        let offset = match pe.translate(PETranslation::Memory(self.name)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        pe.buffer.get_cstring(offset, false, None)
    }
    /// Get the mutable name of the module represented by this import descriptor entry.
    pub fn get_mut_name<'data>(&self, pe: &'data mut PE) -> Result<&'data mut [CChar], Error> {
        let offset = match pe.translate(PETranslation::Memory(self.name)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        pe.buffer.get_mut_cstring(offset, false, None)
    }

    /// Get the first thunk array. This array typically represents where in memory imports get resolved to.
    pub fn get_first_thunk<'data>(&self, pe: &'data PE) -> Result<Vec<Thunk<'data>>, Error> {
        self.parse_thunk_array(pe, self.first_thunk)
    }
    /// Get the mutable first thunk array.
    pub fn get_mut_first_thunk<'data>(&self, pe: &'data mut PE) -> Result<Vec<ThunkMut<'data>>, Error> {
        self.parse_mut_thunk_array(pe, self.first_thunk)
    }

    /// Get the thunk array that represents the imports. This thunk array can either come from the
    /// OFT or the FT.
    pub fn get_lookup_thunks<'data>(&self, pe: &'data PE) -> Result<Vec<Thunk<'data>>, Error> {
        match self.get_original_first_thunk(pe) {
            Ok(t) => Ok(t),
            Err(e) => {
                if e != Error::InvalidRVA {
                    return Err(e)
                }

                self.get_first_thunk(pe)
            },
        }
    }

    /// Get the imports represented by this import descriptor. This resolves the import table and returns a series of strings
    /// representing both [`ImageImportByName`](ImageImportByName) structures as well as import ordinals.
    pub fn get_imports(&self, pe: &PE) -> Result<Vec<String>, Error> {
        let mut results = Vec::<String>::new();
        let thunks = match self.get_lookup_thunks(pe) {
            Ok(t) => t,
            Err(e) => return Err(e),
        };

        for thunk in thunks {
            let thunk_data = match thunk {
                Thunk::Thunk32(t32) => t32.parse_import(),
                Thunk::Thunk64(t64) => t64.parse_import(),
            };

            match thunk_data {
                ThunkData::Ordinal(x) => results.push(String::from(format!("#{}", x))),
                ThunkData::ImportByName(rva) => {
                    match ImageImportByName::parse(pe, rva) {
                        Ok(i) => results.push(String::from(i.name.as_str())),
                        Err(_) => continue,
                    }
                }
                _ => (),
            }
        }

        Ok(results)
    }
}
impl Clone for ImageImportDescriptor {
    fn clone(&self) -> Self {
        Self {
            original_first_thunk: self.original_first_thunk,
            time_date_stamp: self.time_date_stamp,
            forwarder_chain: self.forwarder_chain,
            name: self.name,
            first_thunk: self.first_thunk,
        }
    }
    fn clone_from(&mut self, source: &Self) {
        self.original_first_thunk = source.original_first_thunk;
        self.time_date_stamp = source.time_date_stamp;
        self.forwarder_chain = source.forwarder_chain;
        self.name = source.name;
        self.first_thunk = source.first_thunk;
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
    pub fn parse(pe: &'data PE, rva: RVA) -> Result<Self, Error> {
        let offset = match pe.translate(PETranslation::Memory(rva)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };
        
        let hint = match pe.buffer.get_ref::<u16>(offset) {
            Ok(h) => h,
            Err(e) => return Err(e),
        };
        let name = match pe.buffer.get_cstring(Offset(offset.0 + (mem::size_of::<u16>() as u32)), true, None) {
            Ok(n) => n,
            Err(e) => return Err(e),
        };

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
    pub fn parse(pe: &'data mut PE, rva: RVA) -> Result<Self, Error> {
        let mut offset = match pe.translate(PETranslation::Memory(rva)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        unsafe {
            let mut ptr = match pe.buffer.offset_to_mut_ptr(offset) {
                Ok(p) => p,
                Err(e) => return Err(e),
            };

            let hint = &mut *(ptr as *mut u16);
            let u16_size = mem::size_of::<u16>();

            ptr = ptr.add(u16_size);

            if !pe.buffer.validate_ptr(ptr) {
                return Err(Error::BadPointer);
            }

            offset.0 += u16_size as u32;

            let name_size = match pe.buffer.get_cstring_size(offset, true, None) {
                Ok(s) => s,
                Err(e) => return Err(e),
            };
            
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

#[repr(packed)]
pub struct ImageBaseRelocation {
    pub virtual_address: RVA,
    pub size_of_block: u32,
}
impl Clone for ImageBaseRelocation {
    fn clone(&self) -> Self {
        Self {
            virtual_address: self.virtual_address,
            size_of_block: self.size_of_block,
        }
    }
    fn clone_from(&mut self, source: &Self) {
        self.virtual_address = source.virtual_address;
        self.size_of_block = source.size_of_block;
    }
}

#[repr(packed)]
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
impl Clone for ImageResourceDirectory {
    fn clone(&self) -> Self {
        Self {
            characteristics: self.characteristics,
            time_date_stamp: self.time_date_stamp,
            major_version: self.major_version,
            minor_version: self.minor_version,
            number_of_named_entries: self.number_of_named_entries,
            number_of_id_entries: self.number_of_id_entries,
        }
    }
    fn clone_from(&mut self, source: &Self) {
        self.characteristics = source.characteristics;
        self.time_date_stamp = source.time_date_stamp;
        self.major_version = source.major_version;
        self.minor_version = source.minor_version;
        self.number_of_named_entries = source.number_of_named_entries;
        self.number_of_id_entries = source.number_of_id_entries;
    }
}

#[repr(packed)]
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
impl Clone for ImageResourceDirectoryEntry {
    fn clone(&self) -> Self {
        Self {
            name: self.name,
            offset_to_data: self.offset_to_data,
        }
    }
    fn clone_from(&mut self, source: &Self) {
        self.name = source.name;
        self.offset_to_data = source.offset_to_data;
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
    pub fn parse(pe: &'data PE, rva: RVA) -> Result<Self, Error> {
        let offset = match pe.translate(PETranslation::Memory(rva)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };
        
        let length = match pe.buffer.get_ref::<u16>(offset) {
            Ok(h) => h,
            Err(e) => return Err(e),
        };
        
        let name = match pe.buffer.get_slice_ref::<CChar>(Offset(offset.0 + (mem::size_of::<u16>() as u32)), *length as usize) {
            Ok(n) => n,
            Err(e) => return Err(e),
        };

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
    pub fn parse(pe: &'data mut PE, rva: RVA) -> Result<Self, Error> {
        let mut offset = match pe.translate(PETranslation::Memory(rva)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        unsafe {
            let mut ptr = match pe.buffer.offset_to_mut_ptr(offset) {
                Ok(p) => p,
                Err(e) => return Err(e),
            };

            let length = &mut *(ptr as *mut u16);
            let u16_size = mem::size_of::<u16>();

            ptr = ptr.add(u16_size);

            if !pe.buffer.validate_ptr(ptr) {
                return Err(Error::BadPointer);
            }

            offset.0 += u16_size as u32;
            
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
    pub fn parse(pe: &'data PE, rva: RVA) -> Result<Self, Error> {
        let offset = match pe.translate(PETranslation::Memory(rva)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };
        
        let length = match pe.buffer.get_ref::<u16>(offset) {
            Ok(h) => h,
            Err(e) => return Err(e),
        };
        
        let name = match pe.buffer.get_slice_ref::<WChar>(Offset(offset.0 + (mem::size_of::<u16>() as u32)), *length as usize) {
            Ok(n) => n,
            Err(e) => return Err(e),
        };

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
    pub fn parse(pe: &'data mut PE, rva: RVA) -> Result<Self, Error> {
        let mut offset = match pe.translate(PETranslation::Memory(rva)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        unsafe {
            let mut ptr = match pe.buffer.offset_to_mut_ptr(offset) {
                Ok(p) => p,
                Err(e) => return Err(e),
            };

            let length = &mut *(ptr as *mut u16);
            let u16_size = mem::size_of::<u16>();

            ptr = ptr.add(u16_size);

            if !pe.buffer.validate_ptr(ptr) {
                return Err(Error::BadPointer);
            }

            offset.0 += u16_size as u32;
            
            let name = slice::from_raw_parts_mut(ptr as *mut WChar, *length as usize);

            Ok(Self { length, name })
        }
    }
}

#[repr(packed)]
pub struct ImageResourceDataEntry {
    pub offset_to_data: RVA,
    pub size: u32,
    pub code_page: u32,
    pub reserved: u32,
}
impl ImageResourceDataEntry {
    /// Read the data pointed to by this data entry.
    pub fn read<'data>(&self, pe: &'data PE) -> Result<&'data [u8], Error> {
        if self.offset_to_data.0 == 0 || !pe.validate_rva(self.offset_to_data) {
            return Err(Error::InvalidRVA);
        }

        let offset = match pe.translate(PETranslation::Memory(self.offset_to_data)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        pe.buffer.read(offset, self.size as usize)
    }
    /// Read mutable data pointed to by this directory entry.
    pub fn read_mut<'data>(&self, pe: &'data mut PE) -> Result<&'data mut [u8], Error> {
        if self.offset_to_data.0 == 0 || !pe.validate_rva(self.offset_to_data) {
            return Err(Error::InvalidRVA);
        }

        let offset = match pe.translate(PETranslation::Memory(self.offset_to_data)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        pe.buffer.read_mut(offset, self.size as usize)
    }
    /// Write data to the directory entry. Returns [`Error::BufferTooSmall`](Error::BufferTooSmall) if the data
    /// overflows the buffer provided by the directory entry.
    pub fn write(&self, pe: &mut PE, data: &[u8]) -> Result<(), Error> {
        if self.offset_to_data.0 == 0 || !pe.validate_rva(self.offset_to_data) {
            return Err(Error::InvalidRVA);
        }

        let offset = match pe.translate(PETranslation::Memory(self.offset_to_data)) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        if (data.len() as u32) > self.size {
            return Err(Error::BufferTooSmall);
        }

        pe.buffer.write(offset, data)
    }
}
