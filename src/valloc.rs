//! For Windows only. This module contains everything needed to interact with [`VirtualAlloc`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)
//! and related functions.
use pkbuffer::{Buffer, PtrBuffer};
use bitflags::bitflags;

use winapi::shared::minwindef::LPVOID;
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree, VirtualQuery, VirtualProtect};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::winnt::MEMORY_BASIC_INFORMATION;

use crate::{align, Error};
use crate::headers::*;
use crate::pe::*;
use crate::types::*;

bitflags! {
    /// Only available for Windows. Represents the bitflags for `flAllocationType` in [`VirtualAlloc`](VirtualAlloc).
    pub struct AllocationType: u32 {
        const MEM_COMMIT = 0x1000;
        const MEM_RESERVE = 0x2000;
        const MEM_RESET = 0x80000;
        const MEM_RESET_UNDO = 0x1000000;
        const MEM_LARGE_PAGES = 0x20000000;
        const MEM_PHYSICAL = 0x00400000;
        const MEM_TOP_DOWN = 0x00100000;
        const MEM_WRITE_WATCH = 0x00200000;
    }
}

bitflags! {
    /// Only available for Windows. Represents the enum for `flProtect` in [`VirtualAlloc`](VirtualAlloc).
    pub struct Protect: u32 {
        const PAGE_EXECUTE = 0x10;
        const PAGE_EXECUTE_READ = 0x20;
        const PAGE_EXECUTE_READWRITE = 0x40;
        const PAGE_EXECUTE_WRITECOPY = 0x80;
        const PAGE_NOACCESS = 0x01;
        const PAGE_READONLY = 0x02;
        const PAGE_READWRITE = 0x04;
        const PAGE_WRITECOPY = 0x08;
        const PAGE_TARGETS_INVALID = 0x40000000;
        const PAGE_GUARD = 0x100;
        const PAGE_NOCACHE = 0x200;
        const PAGE_WRITECOMBINE = 0x400;
    }
}

/// Only for Windows. Represents a buffer backed by the `VirtualAlloc` function on Windows.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct VallocBuffer {
    buffer: PtrBuffer,
    allocation: AllocationType,
    protection: Protect,
    owned: bool,
}
impl VallocBuffer {
    /// Use the [`VirtualAlloc`](VirtualAlloc) function directly to allocate a new `VallocBuffer` object.
    ///
    /// This calls `VirtualAlloc` and attempts to allocate the space with the given base address.
    /// To allocate on an address chosen by the system, pass [`std::ptr::null`](std::ptr::null).
    /// On allocation error, this will return a [`Error::Win32Error`](Error::Win32Error).
    pub fn new(address: *const u8, size: usize, allocation: AllocationType, protection: Protect) -> Result<Self, Error> {
        let buffer = unsafe { VirtualAlloc(address as LPVOID, size, allocation.bits(), protection.bits()) };

        if buffer == std::ptr::null_mut() { return Err(Error::Win32Error(unsafe { GetLastError() })); }

        Ok(Self {
            buffer: PtrBuffer::new(buffer as *const u8, size),
            allocation,
            protection,
            owned: true,
        })
    }
    fn query_internal(address: *const u8) -> Result<MEMORY_BASIC_INFORMATION, Error> {
        let mut info = MEMORY_BASIC_INFORMATION::default();

        if unsafe { VirtualQuery(address as LPVOID, &mut info as *mut MEMORY_BASIC_INFORMATION, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) } == 0 {
            Err(Error::Win32Error(unsafe { GetLastError() }))
        }
        else {
            Ok(info)
        }
    }
    /// Query memory for the given address, then return the `VallocBuffer` representation of the page it's from.
    ///
    /// This essentially calls [`VirtualQuery`](VirtualQuery) to query the given address for the page it represents,
    /// then returns that page. If no address was found, return nothing. If an error occurs, return a
    /// [`Win32Error`](Error::Win32Error).
    pub fn from_query(address: *const u8) -> Result<Option<Self>, Error> {
        let info = Self::query_internal(address)?;

        if info.BaseAddress == std::ptr::null_mut() || ((address as usize) < (info.BaseAddress as usize) || (address as usize) > (info.BaseAddress as usize + info.RegionSize)) {
            Ok(None)
        }
        else {
            Ok(Some(Self {
                buffer: PtrBuffer::new(info.BaseAddress as *const u8, info.RegionSize),
                allocation: AllocationType::from_bits_truncate(info.State),
                protection: Protect::from_bits_truncate(info.Protect),
                owned: false,
            }))
        }
    }
    /// Check if a region of memory still exists.
    ///
    /// Returns a [`Win32Error`](Error::Win32Error) if the query of the page failed.
    pub fn is_available(&self) -> Result<bool, Error> {
        let address = self.as_ptr();
        let info = Self::query_internal(address)?;
        
        if info.BaseAddress == std::ptr::null_mut() || ((address as usize) < (info.BaseAddress as usize) || (address as usize) > (info.BaseAddress as usize + info.RegionSize)) {
            Ok(false)
        }
        else {
            Ok(true)
        }
    }
    /// Get the default allocation type of this buffer.
    pub fn get_default_allocation(&self) -> AllocationType {
        self.allocation
    }
    /// Get the current allocation type of this buffer.
    ///
    /// If the buffer is not available, returns a [`BufferNotAvailable`](Error::BufferNotAvailable) error.
    /// On error querying the buffer, returns a [`Win32Error`](Error::Win32Error).
    pub fn get_allocation(&self) -> Result<AllocationType, Error> {
        let available = self.is_available()?;

        if !available { return Err(Error::BufferNotAvailable) }

        let info = Self::query_internal(self.as_ptr())?;

        Ok(AllocationType::from_bits_truncate(info.State))
    }
    /// Get the default protection for this buffer.
    pub fn get_default_protection(&self) -> Protect {
        self.protection
    }
    /// Get the current protection for this buffer.
    ///
    /// On error querying the buffer, returns a [`Win32Error`](Error::Win32Error).
    pub fn get_protection(&self) -> Result<Protect, Error> {
        let available = self.is_available()?;

        if !available { return Err(Error::BufferNotAvailable) }

        let info = Self::query_internal(self.as_ptr())?;

        Ok(Protect::from_bits_truncate(info.Protect))
    }
    /// Check if the buffer is readable.
    pub fn is_readable(&self) -> Result<bool, Error> {
        let protect = self.get_protection()?;

        Ok(protect.contains(Protect::PAGE_READONLY)
           || protect.contains(Protect::PAGE_READWRITE)
           || protect.contains(Protect::PAGE_EXECUTE_READ)
           || protect.contains(Protect::PAGE_EXECUTE_READWRITE))
    }
    /// Check if the buffer is writable.
    pub fn is_writable(&self) -> Result<bool, Error> {
        let protect = self.get_protection()?;

        Ok(protect.contains(Protect::PAGE_READWRITE)
           || protect.contains(Protect::PAGE_EXECUTE_READWRITE))
    }
    /// Check if the buffer is executable.
    pub fn is_executable(&self) -> Result<bool, Error> {
        let protect = self.get_protection()?;

        Ok(protect.contains(Protect::PAGE_EXECUTE)
           || protect.contains(Protect::PAGE_EXECUTE_READ)
           || protect.contains(Protect::PAGE_EXECUTE_READWRITE))
    }
    /// Call `VirtualProtect` on the allocated buffer.
    ///
    /// Returns the old protection of the buffer. If [`None`](Option::None) is passed, attempt to set it with the default
    /// protection the buffer was initialized with. On failure, this function returns a [`Win32Error`](Error::Win32Error).
    pub fn protect(&mut self, protect: Option<Protect>) -> Result<Protect, Error> {
        let new_protect;

        if protect.is_none() { new_protect = self.protection; }
        else { new_protect = protect.unwrap(); }

        let mut old_protect = new_protect.bits();
        
        if unsafe { VirtualProtect(self.as_ptr() as LPVOID, self.len(), new_protect.bits(), &mut old_protect as *mut u32) } == 0 {
            Err(Error::Win32Error(unsafe { GetLastError() }))
        }
        else {
            Ok(Protect::from_bits_truncate(old_protect))
        }
    }
}
impl Buffer for VallocBuffer {
    fn len(&self) -> usize { self.buffer.len() }
    fn as_ptr(&self) -> *const u8 { self.buffer.as_ptr() }
    fn as_mut_ptr(&mut self) -> *mut u8 { self.buffer.as_mut_ptr() }
    fn as_slice(&self) -> &[u8] { self.buffer.as_slice() }
    fn as_mut_slice(&mut self) -> &mut [u8] { self.buffer.as_mut_slice() }
}
impl<Idx: std::slice::SliceIndex<[u8]>> std::ops::Index<Idx> for VallocBuffer {
    type Output = Idx::Output;
        
    fn index(&self, index: Idx) -> &Self::Output {
        self.as_slice().index(index)
    }
}
impl<Idx: std::slice::SliceIndex<[u8]>> std::ops::IndexMut<Idx> for VallocBuffer {
    fn index_mut(&mut self, index: Idx) -> &mut Self::Output {
        self.as_mut_slice().index_mut(index)
    }
}
impl Drop for VallocBuffer {
    fn drop(&mut self) {
        if self.owned {
            if let Ok(result) = self.is_available() {
                if result {
                    unsafe { VirtualFree(self.as_mut_ptr() as LPVOID, self.len(), 0x8000) };
                }
            }
        }
    }
}

/// Only for Windows. Represents a [`PE`](PE) buffer allocated with `VirtualAlloc`.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct VallocPE {
    sum: PtrPE,
    sections: Vec<(ImageSectionHeader, VallocBuffer)>,
    reservation: Option<VallocBuffer>,
}
impl VallocPE {
    /// Create a new `VallocPE` object with the given base address and size.
    ///
    /// This essentially creates a single section within the PE object backed by a [`VallocBuffer`](VallocBuffer),
    /// see [`VallocBuffer::new`](VallocBuffer::new) for more info.
    pub fn new(address: *const u8, size: usize, allocation: AllocationType, protect: Protect) -> Result<Self, Error> {
        let buffer = VallocBuffer::new(
            address,
            size,
            allocation,
            protect,
        )?;
        
        Ok(Self::from_valloc_buffer(buffer))
    }

    /// Create a new `VallocPE` object with only the given buffer as its section.
    pub fn from_valloc_buffer(buffer: VallocBuffer) -> Self {
        let sum = PtrPE::new_memory(buffer.as_ptr(), buffer.len());
        let sections = vec![(ImageSectionHeader::default(), buffer)];

        Self { sum, sections, reservation: None }
    }
    /// Create a new `VallocPE` object from another [`PE`](PE) object.
    ///
    /// This essentially enumerates the section table of the [`PE`](PE) object and allocates
    /// the individual sections with the proper initialized protections.
    pub fn from_pe<P: PE + Buffer>(pe: &P) -> Result<Self, Error> {
        let headers = pe.get_valid_nt_headers()?;
        let pe_size = pe.calculate_memory_size()?;
        let (image_base, section_alignment) = match headers {
            NTHeaders::NTHeaders32(h32) => (h32.optional_header.image_base as usize, h32.optional_header.section_alignment),
            NTHeaders::NTHeaders64(h64) => (h64.optional_header.image_base as usize, h64.optional_header.section_alignment),
        };

        let aslr = match headers {
            NTHeaders::NTHeaders32(h32) => !(h32.optional_header.dll_characteristics & DLLCharacteristics::DYNAMIC_BASE).is_empty(),
            NTHeaders::NTHeaders64(h64) => !(h64.optional_header.dll_characteristics & DLLCharacteristics::DYNAMIC_BASE).is_empty(),
        };

        let mut alloc_address;
        
        if aslr {
            alloc_address = std::ptr::null() as *const u8;
        }
        else {
            alloc_address = image_base as *const u8;
        }

        let reservation = VallocBuffer::new(
            alloc_address,
            pe_size,
            AllocationType::MEM_RESERVE,
            Protect::PAGE_READWRITE,
        )?;

        alloc_address = reservation.as_ptr();
        let alloc_base = alloc_address;

        let section_table = pe.get_section_table()?;
        let mut section_table = section_table.to_vec();
        section_table.sort_by(|a,b| a.virtual_address.0.cmp(&b.virtual_address.0));

        let mut sections = Vec::<(ImageSectionHeader, VallocBuffer)>::new();

        let header_size = pe.calculate_header_size()?;
        let header_data = pe.read(0, header_size)?;
        let first_section = &section_table[0];
        let mut section_size = align(first_section.virtual_address.0 as usize, section_alignment as usize);
        let mut previous_size = section_size;
        let mut total_size = section_size;
        
        let mut header_buffer = VallocBuffer::new(
            alloc_address,
            section_size,
            AllocationType::MEM_COMMIT,
            Protect::PAGE_READWRITE,
        )?;

        header_buffer.write(0, header_data)?;
        header_buffer.protect(Some(Protect::PAGE_READONLY))?;
        sections.push((ImageSectionHeader::default(), header_buffer));

        for scn_header in section_table {
            let checked_address = unsafe { alloc_base.add(align(scn_header.virtual_address.into(), section_alignment) as usize) };
            alloc_address = unsafe { alloc_address.add(previous_size) };

            if alloc_address != checked_address {
                return Err(Error::SectionsNotContiguous);
            }

            section_size = align(scn_header.virtual_size as usize, section_alignment as usize);
            previous_size = section_size;
            total_size += section_size;

            let protect;

            if scn_header.characteristics.contains(SectionCharacteristics::MEM_READ)
                && scn_header.characteristics.contains(SectionCharacteristics::MEM_WRITE)
                && scn_header.characteristics.contains(SectionCharacteristics::MEM_EXECUTE) {
                    protect = Protect::PAGE_EXECUTE_READWRITE;
                }
            else if scn_header.characteristics.contains(SectionCharacteristics::MEM_READ)
                && scn_header.characteristics.contains(SectionCharacteristics::MEM_WRITE) {
                    protect = Protect::PAGE_READWRITE;
                }
            else if scn_header.characteristics.contains(SectionCharacteristics::MEM_READ)
                && scn_header.characteristics.contains(SectionCharacteristics::MEM_EXECUTE) {
                    protect = Protect::PAGE_EXECUTE_READ;
                }
            else if scn_header.characteristics.contains(SectionCharacteristics::MEM_READ) {
                protect = Protect::PAGE_READONLY;
            }
            else if scn_header.characteristics.contains(SectionCharacteristics::MEM_EXECUTE) {
                protect = Protect::PAGE_EXECUTE;
            }
            else {
                protect = Protect::PAGE_NOACCESS;
            }

            let section_data = scn_header.read(pe)?;
            let mut section_buffer = VallocBuffer::new(
                alloc_address,
                section_size,
                AllocationType::MEM_COMMIT,
                Protect::PAGE_READWRITE,
            )?;
            section_buffer.write(0, section_data)?;
            section_buffer.protect(Some(protect))?;

            sections.push((scn_header.clone(), section_buffer));
        }

        let sum = PtrPE::new_memory(reservation.as_ptr(), total_size);

        Ok(Self { sum, sections, reservation: Some(reservation) })
    }
    
    /// Attempts to load the image into memory similar to the Windows loader.
    ///
    /// This is not a 100% accurate representation of the Windows loader, it's rather a rudimentary version to get a binary
    /// off the ground and be executable. Note that this is not a safe function, in the sense that arbitrary code may be
    /// executed due to the TLS directory.
    ///
    /// **Note**: You should probably not run this function on suspected malware in an unsandboxed environment. In a sandboxed
    /// environment, though, this function comes in handy for executing code which is known to be benign.
    pub fn load_image(&mut self) -> Result<(), Error> {
        match self.get_arch() {
            Ok(a) => match a {
                Arch::X86 => { if std::mem::size_of::<usize>() == 8 { return Err(Error::ArchMismatch(Arch::X86, a)); } },
                Arch::X64 => { if std::mem::size_of::<usize>() == 4 { return Err(Error::ArchMismatch(Arch::X64, a)); } },
            },
            Err(e) => return Err(e),
        }

        self.mark_read_write()?;
        let self_ro = PtrPE::new_memory(self.as_ptr(), self.len());

        if self_ro.has_data_directory(ImageDirectoryEntry::BaseReloc) {
            let reloc_dir = match RelocationDirectory::parse(&self_ro) {
                Ok(r) => r,
                Err(e) => return Err(e),
            };

            reloc_dir.relocate(self, self_ro.as_ptr() as u64)?;
        }

        if self_ro.has_data_directory(ImageDirectoryEntry::Import) {
            let import_dir = ImportDirectory::parse(&self_ro)?;

            match import_dir.resolve_iat(self) {
                Ok(()) => (),
                Err(e) => return Err(e),
            }
        }

        self.protect()?;

        if self_ro.has_data_directory(ImageDirectoryEntry::TLS) {
            let tls_dir = match TLSDirectory::parse(&self_ro) {
                Ok(t) => t,
                Err(e) => return Err(e),
            };

            let mut resolved_callbacks = Vec::<*const u8>::new();

            match tls_dir {
                TLSDirectory::TLS32(tls32) => {
                    let callbacks = match tls32.get_callbacks(unsafe { &*(self as *mut VallocPE as *const VallocPE) }) {
                        Ok(c) => c,
                        Err(e) => return Err(e),
                    };
                    
                    for callback in callbacks {
                        match callback.as_ptr(self) {
                            Ok(p) => resolved_callbacks.push(p),
                            Err(e) => return Err(e),
                        }
                    }
                },
                TLSDirectory::TLS64(tls64) => {
                    let callbacks = match tls64.get_callbacks(unsafe { &*(self as *mut VallocPE as *const VallocPE) }) {
                        Ok(c) => c,
                        Err(e) => return Err(e),
                    };
                    
                    for callback in callbacks {
                        match callback.as_ptr(self) {
                            Ok(p) => resolved_callbacks.push(p),
                            Err(e) => return Err(e),
                        }
                    }
                },
            }
        
            for callback in resolved_callbacks {
                type TLSCallback = unsafe extern "system" fn(*const u8, u32, *const u8);
                let callback_fn = unsafe { std::mem::transmute::<*const u8, TLSCallback>(callback) };
            
                unsafe { callback_fn(self.as_ptr(), 1, std::ptr::null()) };
            }
        }
    
        Ok(())
    }

    /// Get the header section of the allocated [`PE`](PE) file.
    pub fn get_header(&self) -> &VallocBuffer {
        &self.sections[0].1
    }
    pub fn get_mut_header(&mut self) -> &mut VallocBuffer {
        &mut self.sections[0].1
    }
    pub fn get_section(&self, index: usize) -> Result<&VallocBuffer, Error> {
        let sections = &self.sections[1..];

        if index > sections.len() { return Err(Error::OutOfBounds(sections.len(), index)); }

        Ok(&sections[index].1)
    }
    pub fn get_mut_section(&mut self, index: usize) -> Result<&mut VallocBuffer, Error> {
        let sections = &mut self.sections[1..];

        if index > sections.len() { return Err(Error::OutOfBounds(sections.len(), index)); }

        Ok(&mut sections[index].1)
    }
    pub fn get_section_by_name<S: AsRef<str>>(&self, name: S) -> Result<&VallocBuffer, Error> {
        let sections = &self.sections[1..];
        let name = name.as_ref();

        for (header, section) in sections {
            let s = header.name.as_str()?;
            if name == s { return Ok(section); }
        }

        Err(Error::SectionNotFound)
    }
    pub fn get_mut_section_by_name<S: AsRef<str>>(&mut self, name: S) -> Result<&mut VallocBuffer, Error> {
        let sections = &mut self.sections[1..];
        let name = name.as_ref();

        for (header, scn) in sections.iter_mut() {
            let s = header.name.as_str()?;
            if name == s { return Ok(scn); }
        }

        Err(Error::SectionNotFound)
    }
    pub fn mark_read_write(&mut self) -> Result<(), Error> {
        for (_, scn) in &mut self.sections[1..] {
            scn.protect(Some(Protect::PAGE_READWRITE))?;
        }

        Ok(())
    }
    pub fn protect(&mut self) -> Result<(), Error> {
        for (header, scn) in &mut self.sections[1..] {
            let protect;

            if header.characteristics.contains(SectionCharacteristics::MEM_READ)
                && header.characteristics.contains(SectionCharacteristics::MEM_WRITE)
                && header.characteristics.contains(SectionCharacteristics::MEM_EXECUTE) {
                    protect = Protect::PAGE_EXECUTE_READWRITE;
                }
            else if header.characteristics.contains(SectionCharacteristics::MEM_READ)
                && header.characteristics.contains(SectionCharacteristics::MEM_WRITE) {
                    protect = Protect::PAGE_READWRITE;
                }
            else if header.characteristics.contains(SectionCharacteristics::MEM_READ)
                && header.characteristics.contains(SectionCharacteristics::MEM_EXECUTE) {
                    protect = Protect::PAGE_EXECUTE_READ;
                }
            else if header.characteristics.contains(SectionCharacteristics::MEM_READ) {
                protect = Protect::PAGE_READONLY;
            }
            else if header.characteristics.contains(SectionCharacteristics::MEM_EXECUTE) {
                protect = Protect::PAGE_EXECUTE;
            }
            else {
                protect = Protect::PAGE_NOACCESS;
            }
            
            scn.protect(Some(protect))?;
        }

        Ok(())
    }
}
impl PE for VallocPE {
    fn get_type(&self) -> PEType { PEType::Memory }
    fn is_allocated(&self) -> bool { true }
}
impl Buffer for VallocPE {
    fn len(&self) -> usize { self.sum.len() }
    fn as_ptr(&self) -> *const u8 { self.sum.as_ptr() }
    fn as_mut_ptr(&mut self) -> *mut u8 { self.sum.as_mut_ptr() }
    fn as_slice(&self) -> &[u8] { self.sum.as_slice() }
    fn as_mut_slice(&mut self) -> &mut [u8] { self.sum.as_mut_slice() }
}
impl<Idx: std::slice::SliceIndex<[u8]>> std::ops::Index<Idx> for VallocPE {
    type Output = Idx::Output;
        
    fn index(&self, index: Idx) -> &Self::Output {
        self.as_slice().index(index)
    }
}
impl<Idx: std::slice::SliceIndex<[u8]>> std::ops::IndexMut<Idx> for VallocPE {
    fn index_mut(&mut self, index: Idx) -> &mut Self::Output {
        self.as_mut_slice().index_mut(index)
    }
}
