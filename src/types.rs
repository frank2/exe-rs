use bitflags::bitflags;

use chrono::offset::{Offset as ChronoOffset};
use chrono::offset::TimeZone;
use chrono::{Local as LocalTime};

use std::collections::HashMap;
use std::default::Default;
use std::mem;

use widestring::U16Str;

use crate::{PE, Error};

pub const DOS_SIGNATURE: u16    = 0x5A4D;
pub const OS2_SIGNATURE: u16    = 0x454E;
pub const OS2_SIGNATURE_LE: u16 = 0x454C;
pub const VXD_SIGNATURE: u16    = 0x454C;
pub const NT_SIGNATURE: u32     = 0x00004550;

pub const HDR32_MAGIC: u16 = 0x010B;
pub const HDR64_MAGIC: u16 = 0x020B;
pub const ROM_MAGIC: u16   = 0x0107;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Arch {
    X86,
    X64,
}

#[repr(packed)]
#[derive(Copy, Clone, Default, Eq, PartialEq, Debug)]
pub struct CChar(pub u8);

/* borrowed from pe-rs */
pub trait CCharString {
    fn zero_terminated(&self) -> Option<&Self>;
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

#[repr(packed)]
#[derive(Copy, Clone, Default, Eq, PartialEq, Debug)]
pub struct WChar(pub u16);

pub trait WCharString {
    fn zero_terminated(&self) -> Option<&Self>;
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

pub trait Address {
    fn as_offset(&self, pe: &PE) -> Result<Offset, Error>;
    fn as_rva(&self, pe: &PE) -> Result<RVA, Error>;
    fn as_va(&self, pe: &PE) -> Result<VA, Error>;
}

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

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Machine {
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
    fn default_x86() -> Self {
        ImageFileHeader::default()
    }
    fn default_x64() -> Self {
        Self {
            machine: Machine::AMD64 as u16,
            number_of_sections: 0,
            time_date_stamp: LocalTime.timestamp(0, 0).timestamp() as u32,
            pointer_to_symbol_table: Offset(0),
            number_of_symbols: 0,
            size_of_optional_header: mem::size_of::<ImageOptionalHeader32>() as u16,
            characteristics: FileCharacteristics::EXECUTABLE_IMAGE | FileCharacteristics::MACHINE_32BIT,
        }
    }
}
impl Default for ImageFileHeader {
    fn default() -> Self {
        Self {
            machine: Machine::I386 as u16,
            number_of_sections: 0,
            time_date_stamp: LocalTime.timestamp(0, 0).timestamp() as u32,
            pointer_to_symbol_table: Offset(0),
            number_of_symbols: 0,
            size_of_optional_header: mem::size_of::<ImageOptionalHeader32>() as u16,
            characteristics: FileCharacteristics::EXECUTABLE_IMAGE | FileCharacteristics::MACHINE_32BIT,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Subsystem {
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
    pub data_directory: [ImageDataDirectory; 16],
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
            subsystem: Subsystem::WindowsGUI as u16,
            dll_characteristics: DLLCharacteristics::DYNAMIC_BASE | DLLCharacteristics::NX_COMPAT | DLLCharacteristics::TERMINAL_SERVER_AWARE,
            size_of_stack_reserve: 0x40000,
            size_of_stack_commit: 0x2000,
            size_of_heap_reserve: 0x100000,
            size_of_heap_commit: 0x1000,
            loader_flags: 0,
            number_of_rva_and_sizes: 0x10,
            /* I really don't want to give ImageDataDirectory the copy trait,
               so this is ugly copypasta */
            data_directory: [
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
            ],
        }
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
    pub data_directory: [ImageDataDirectory; 16],
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
            subsystem: Subsystem::WindowsGUI as u16,
            dll_characteristics: DLLCharacteristics::DYNAMIC_BASE | DLLCharacteristics::NX_COMPAT | DLLCharacteristics::TERMINAL_SERVER_AWARE,
            size_of_stack_reserve: 0x100000,
            size_of_stack_commit: 0x1000,
            size_of_heap_reserve: 0x100000,
            size_of_heap_commit: 0x1000,
            loader_flags: 0,
            number_of_rva_and_sizes: 0x10,
            data_directory: [
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
                ImageDataDirectory { virtual_address: RVA(0), size: 0 },
            ],
        }
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

pub enum NTHeaders<'data> {
    NTHeaders32(&'data ImageNTHeaders32),
    NTHeaders64(&'data ImageNTHeaders64),
}

pub enum NTHeadersMut<'data> {
    NTHeaders32(&'data mut ImageNTHeaders32),
    NTHeaders64(&'data mut ImageNTHeaders64),
}

bitflags! {
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

#[repr(packed)]
#[derive(Default)]
pub struct ImageDataDirectory {
    pub virtual_address: RVA,
    pub size: u32,
}
impl ImageDataDirectory {
    pub fn resolve<'data>(&self, pe: &'data PE, entry: ImageDirectoryEntry) -> Result<DataDirectory<'data>, Error> {
        if self.virtual_address.0 == 0 {
            return Err(Error::InvalidRVA);
        }
        
        let address = match self.virtual_address.as_offset(pe) {
            Ok(a) => a,
            Err(e) => return Err(e),
        };

        /* we use an if/else statement instead of a match block for readability */
        if entry == ImageDirectoryEntry::Export {
            match pe.buffer.get_ref::<ImageExportDirectory>(address) {
                Ok(d) => Ok(DataDirectory::Export(d)),
                Err(e) => Err(e),
            }
        }
        else {
            Err(Error::UnsupportedDirectory)
        }
    }
    pub fn resolve_mut<'data>(&self, pe: &'data mut PE, entry: ImageDirectoryEntry) -> Result<DataDirectoryMut<'data>, Error> {
        if self.virtual_address.0 == 0 {
            return Err(Error::InvalidRVA);
        }
        
        let address = match self.virtual_address.as_offset(pe) {
            Ok(a) => a,
            Err(e) => return Err(e),
        };

        /* we use an if/else statement instead of a match block for readability */
        if entry == ImageDirectoryEntry::Export {
            match pe.buffer.get_mut_ref::<ImageExportDirectory>(address) {
                Ok(d) => Ok(DataDirectoryMut::Export(d)),
                Err(e) => Err(e),
            }
        }
        else {
            Err(Error::UnsupportedDirectory)
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

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ThunkData {
    Ordinal(u32),
    Function(RVA),
    ForwarderString(RVA),
}

pub trait Thunk {
    fn is_ordinal(&self) -> bool;
    fn parse(&self, start: Option<RVA>, end: Option<RVA>) -> ThunkData;
}

#[repr(packed)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Thunk32(pub u32);
impl Thunk for Thunk32 {
    fn is_ordinal(&self) -> bool {
        (self.0 & 0x80000000) != 0
    }
    fn parse(&self, start: Option<RVA>, end: Option<RVA>) -> ThunkData {
        if self.is_ordinal() {
            ThunkData::Ordinal((self.0 & 0xFFFF) as u32)
        }
        else if start.is_none() || end.is_none() {
            ThunkData::Function(RVA(self.0 as u32))
        }
        else {
            let rva_start = start.unwrap();
            let rva_end = end.unwrap();
            let value = self.0 as u32;

            if rva_start.0 <= value && value < rva_end.0 {
                ThunkData::ForwarderString(RVA(value))
            }
            else {
                ThunkData::Function(RVA(value))
            }
        }
    }
}

#[repr(packed)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Thunk64(pub u64);
impl Thunk for Thunk64 {
    fn is_ordinal(&self) -> bool {
        (self.0 & 0x8000000000000000) != 0
    }
    fn parse(&self, start: Option<RVA>, end: Option<RVA>) -> ThunkData {
        if self.is_ordinal() {
            ThunkData::Ordinal((self.0 & 0xFFFFFFFF) as u32)
        }
        else if start.is_none() || end.is_none() {
            ThunkData::Function(RVA(self.0 as u32))
        }
        else {
            let rva_start = start.unwrap();
            let rva_end = end.unwrap();
            let value = self.0;

            if (rva_start.0 as u64) <= value && value < (rva_end.0 as u64) {
                ThunkData::ForwarderString(RVA(value as u32))
            }
            else {
                ThunkData::Function(RVA(value as u32))
            }
        }
    }
}

#[repr(packed)]
pub struct ImageExportDirectory {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    name: RVA,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: RVA, // [RVA; number_of_functions]
    address_of_names: RVA, // [RVA; number_of_names]
    address_of_name_ordinals: RVA, // [RVA; number_of_names]
}
impl ImageExportDirectory {
    pub fn get_name<'data>(&self, pe: &'data PE) -> Result<&'data [CChar], Error> {
        if self.name.0 == 0 {
            return Err(Error::InvalidRVA);
        }
        
        match self.name.as_offset(pe) {
            Err(e) => return Err(e),
            Ok(a) => pe.buffer.get_cstring(a, false, None),
        }
    }
    pub fn get_mut_name<'data>(&self, pe: &'data mut PE) -> Result<&'data mut [CChar], Error> {
        if self.name.0 == 0 {
            return Err(Error::InvalidRVA);
        }

        match self.name.as_offset(pe) {
            Err(e) => return Err(e),
            Ok(a) => pe.buffer.get_mut_cstring(a, false, None),
        }
    }
    pub fn get_functions<'data>(&self, pe: &'data PE) -> Result<&'data [Thunk32], Error> {
        if self.address_of_functions.0 == 0 {
            return Err(Error::InvalidRVA);
        }

        match self.address_of_functions.as_offset(pe) {
            Err(e) => return Err(e),
            Ok(a) => pe.buffer.get_slice_ref::<Thunk32>(a, self.number_of_functions as usize),
        }
    }
    pub fn get_mut_functions<'data>(&self, pe: &'data mut PE) -> Result<&'data mut [Thunk32], Error> {
        if self.address_of_functions.0 == 0 {
            return Err(Error::InvalidRVA);
        }

        match self.address_of_functions.as_offset(pe) {
            Err(e) => return Err(e),
            Ok(a) => pe.buffer.get_mut_slice_ref::<Thunk32>(a, self.number_of_functions as usize),
        }
    }
    pub fn get_names<'data>(&self, pe: &'data PE) -> Result<&'data [RVA], Error> {
        if self.address_of_names.0 == 0 {
            return Err(Error::InvalidRVA);
        }

        match self.address_of_names.as_offset(pe) {
            Err(e) => return Err(e),
            Ok(a) => pe.buffer.get_slice_ref::<RVA>(a, self.number_of_names as usize),
        }
    }
    pub fn get_mut_names<'data>(&self, pe: &'data mut PE) -> Result<&'data mut [RVA], Error> {
        if self.address_of_names.0 == 0 {
            return Err(Error::InvalidRVA);
        }

        match self.address_of_names.as_offset(pe) {
            Err(e) => return Err(e),
            Ok(a) => pe.buffer.get_mut_slice_ref::<RVA>(a, self.number_of_names as usize),
        }
    }
    pub fn get_name_ordinals<'data>(&self, pe: &'data PE) -> Result<&'data [u16], Error> {
        if self.address_of_name_ordinals.0 == 0 {
            return Err(Error::InvalidRVA);
        }

        match self.address_of_name_ordinals.as_offset(pe) {
            Err(e) => return Err(e),
            Ok(a) => pe.buffer.get_slice_ref::<u16>(a, self.number_of_names as usize),
        }
    }
    pub fn get_mut_name_ordinals<'data>(&self, pe: &'data mut PE) -> Result<&'data mut [u16], Error> {
        if self.address_of_name_ordinals.0 == 0 {
            return Err(Error::InvalidRVA);
        }

        match self.address_of_name_ordinals.as_offset(pe) {
            Err(e) => return Err(e),
            Ok(a) => pe.buffer.get_mut_slice_ref::<u16>(a, self.number_of_names as usize),
        }
    }
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

            let name_offset = match name_rva.as_offset(pe) {
                Ok(o) => o,
                Err(_) => continue, /* we continue instead of returning the error to be greedy with parsing */
            };

            let name = match pe.buffer.get_cstring(name_offset, false, None) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let ordinal = ordinals[index as usize];
            let function = functions[ordinal as usize].parse(Some(start), Some(end));

            result.insert(name.as_str(), function);
        }

        Ok(result)
    }
}

pub enum DataDirectory<'data> {
    Export(&'data ImageExportDirectory),
    Unsupported,
}

pub enum DataDirectoryMut<'data> {
    Export(&'data mut ImageExportDirectory),
    Unsupported,
}
