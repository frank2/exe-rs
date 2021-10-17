//! This module contains everything needed for representing a PE buffer. The buffer contains
//! raw functionality necessary to cast objects from the data vector, as well as helper functions
//! to perform calculations such as hashes and entropy.

use bitflags::bitflags;

use byteorder::{LittleEndian, ReadBytesExt};

use md5::{Md5, Digest};

use sha1::Sha1;

use sha2::Sha256;

use std::clone::Clone;
use std::collections::HashMap;
use std::convert::AsRef;
use std::fs;
use std::io::{Error as IoError, Cursor};
use std::mem;
use std::ops::{Index, IndexMut};
#[cfg(windows)] use std::ops::Drop;
use std::path::Path;
use std::ptr;
use std::slice;

#[cfg(windows)] use winapi::shared::minwindef::LPVOID;
#[cfg(windows)] use winapi::um::memoryapi::{VirtualAlloc, VirtualFree};
#[cfg(windows)] use winapi::um::errhandlingapi::GetLastError;

use crate::Error;
use crate::types::{Offset, CChar, WChar};

/// Aligns a given `value` to the boundary specified by `boundary`.
pub fn align(value: usize, boundary: usize) -> usize {
    if value % boundary == 0 {
        value
    }
    else {
        value + (boundary - (value % boundary))
    }
}

/// Get a slice of ```u8``` that represents the underlying data of the object. Useful when combined with
/// the [`HashData`](HashData) or [`Entropy`](Entropy) traits.
pub fn ref_to_bytes<T>(data: &T) -> &[u8] {
    let ptr = data as *const T as *const u8;
    let size = mem::size_of::<T>();

    unsafe {
        slice::from_raw_parts(ptr, size)
    }
}

/// Get a slice of `u8` that represents the underlying data of the given slice.
pub fn slice_ref_to_bytes<T>(data: &[T]) -> &[u8] {
    let ptr = &data[0] as *const T as *const u8;
    let size = mem::size_of::<T>() * data.len();

    unsafe {
        slice::from_raw_parts(ptr, size)
    }
}

/// Get a mutable slice of ```u8``` that represents the underlying data of the object.
pub fn ref_to_mut_bytes<T>(data: &mut T) -> &mut [u8] {
    let ptr = data as *mut T as *mut u8;
    let size = mem::size_of::<T>();

    unsafe {
        slice::from_raw_parts_mut(ptr, size)
    }
}

/// Get a mutable slice of `u8` that represents the underlying data of the given slice.
pub fn slice_ref_to_mut_bytes<T>(data: &[T]) -> &mut [u8] {
    let ptr = &data[0] as *const T as *mut T as *mut u8;
    let size = mem::size_of::<T>() * data.len();

    unsafe {
        slice::from_raw_parts_mut(ptr, size)
    }
}

/// Syntactic sugar for producing various hashes of data. Typically applied to ```[u8]``` slices.
///
/// ```rust
/// use hex;
///
/// use exe::PE;
/// use exe::buffer::HashData;
/// use exe::types::CCharString;
///
/// let buffer = std::fs::read("test/compiled.exe").unwrap();
/// let pefile = PE::new_disk(buffer.as_slice());
/// let section_table = pefile.get_section_table().unwrap();
///
/// println!("=Section Hashes=");
///
/// for section in section_table {
///    println!("[{}]", section.name.as_str());
///
///    let section_data = section.read(&pefile).unwrap();
///
///    println!("MD5:    {}", hex::encode(section_data.md5()));
///    println!("SHA1:   {}", hex::encode(section_data.sha1()));
///    println!("SHA256: {}\n", hex::encode(section_data.sha256()));
/// }
pub trait HashData {
    /// Produce an MD5 hash.
    fn md5(&self) -> Vec<u8>;
    /// Produce a SHA1 hash.
    fn sha1(&self) -> Vec<u8>;
    /// Produce a SHA256 hash.
    fn sha256(&self) -> Vec<u8>;
}
impl HashData for [u8] {
    fn md5(&self) -> Vec<u8> {
        let mut hash = Md5::new();
        hash.update(self);
        hash.finalize()
            .as_slice()
            .iter()
            .cloned()
            .collect()
    }
    fn sha1(&self) -> Vec<u8> {
        let mut hash = Sha1::new();
        hash.update(self);
        hash.finalize()
            .as_slice()
            .iter()
            .cloned()
            .collect()
    }
    fn sha256(&self) -> Vec<u8> {
        let mut hash = Sha256::new();
        hash.update(self);
        hash.finalize()
            .as_slice()
            .iter()
            .cloned()
            .collect()
    }
}

/// Syntactic sugar to calculate entropy on a given object.
pub trait Entropy {
    /// Calculates the entropy of a given object. Returns a value between 0.0 (low entropy) and 8.0 (high entropy).
    fn entropy(&self) -> f64;
}
impl Entropy for [u8] {
    // algorithm once again borrowed from Ero Carrera's legacy-leaving pefile
    fn entropy(&self) -> f64 {
        if self.len() == 0 { return 0.0_f64; }
        
        let mut occurences: HashMap<u8, usize> = (0..=255).map(|x| (x, 0)).collect();
        for c in self { occurences.insert(*c, occurences.get(c).unwrap()+1); }

        let mut entropy = 0.0_f64;

        for (_, weight) in occurences {
            let p_x = (weight as f64) / (self.len() as f64);

            if p_x == 0.0 { continue; }
            
            entropy -= p_x * p_x.log2();
        }

        entropy.abs()
    }
}

#[cfg(windows)]
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

/// Only available for Windows. Represents the enum for `flProtect` in [`VirtualAlloc`](VirtualAlloc).
#[cfg(windows)]
pub enum Protect {
    Execute = 0x10,
    ExecuteRead = 0x20,
    ExecuteReadWrite = 0x40,
    ExecuteWriteCopy = 0x80,
    NoAccess = 0x01,
    ReadOnly = 0x02,
    ReadWrite = 0x04,
    WriteCopy = 0x08,
    TargetsInvalidNoUpdate = 0x40000000,
    Guard = 0x100,
    NoCache = 0x200,
    WriteCombine = 0x400,
}
    
/// A buffer representing the PE image.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Buffer {
    data: *const u8,
    length: usize,
    #[cfg(windows)]
    allocated: bool,
}
impl Buffer {
    /// Creates a new buffer from a slice of memory. The `memory` argument must outlive the `Buffer` object.
    pub fn new(memory: &[u8]) -> Self {
        Self {
            data: memory.as_ptr(),
            length: memory.len(),
            #[cfg(windows)]
            allocated: false,
        }
    }
    /// Creates a new mutable buffer from a mutable slice of memory. The `memory` argument must outlive the `Buffer` object.
    pub fn new_mut(memory: &mut [u8]) -> Self {
        Self {
            data: memory.as_ptr(), // we can always make it mutable later
            length: memory.len(),
            #[cfg(windows)]
            allocated: false,
        }
    }
    /// Creates a new buffer from a pointer and a length argument.
    pub fn from_raw_parts(ptr: *const u8, size: usize) -> Self {
        Self {
            data: ptr,
            length: size,
            #[cfg(windows)]
            allocated: false,
        }
    }
    /// Creates a new buffer from a mutable pointer and a length argument.
    pub fn from_raw_parts_mut(ptr: *mut u8, size: usize) -> Self {
        Self {
            data: ptr as *const u8,
            length: size,
            #[cfg(windows)]
            allocated: false,
        }
    }
    /// Only available for Windows. Use the [`VirtualAlloc`](VirtualAlloc) function to allocate a new `Buffer` object. On failure, this
    /// function returns a [`Win32Error`](Error::Win32Error).
    #[cfg(windows)]
    pub fn virtual_alloc(address: *const u8, size: usize, allocation: AllocationType, protect: Protect) -> Result<Buffer, Error> {
        let buffer = unsafe { VirtualAlloc(address as LPVOID, size, allocation.bits(), protect as u32) };

        if buffer == std::ptr::null_mut() { return Err(Error::Win32Error(unsafe { GetLastError() })); }

        Ok(Buffer {
            data: buffer as *const u8,
            length: size,
            allocated: true,
        })
    }

    /// Only available for Windows. Check if this `Buffer` object has been allocated.
    #[cfg(windows)]
    pub fn is_allocated(&self) -> bool {
        self.allocated
    }

    /// Get the length of the buffer.
    pub fn len(&self) -> usize {
        self.length
    }
    /// Get the buffer as a slice.
    pub fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.data, self.length) }
    }
    
    /// Get the buffer as a mutable slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.data as *mut u8, self.length) }
    }
    /// Get the buffer as a pointer.
    pub fn as_ptr(&self) -> *const u8 {
        self.data
    }
    /// Get the buffer as a mutable pointer.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data as *mut u8
    }
    /// Check if the PE file is empty.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
    /// Convert this buffer into a [`Vec`](std::vec::Vec)<[`u8`](u8)> object.
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }

    /// Save the buffer to disk with the given filename.
    pub fn save<P: AsRef<Path>>(&self, filename: P) -> Result<(), IoError> {
        fs::write(filename, self.as_slice())
    }

    /// Convert the given offset value to a pointer in the buffer. The function is marked as
    /// unsafe because the offset isn't validated.
    pub unsafe fn offset_to_ptr(&self, offset: Offset) -> *const u8 {
        self.as_ptr().add(offset.0 as usize)
    }
    /// Convert the given offset value to a mutable pointer in the buffer. The function is marked as
    /// unsafe because the offset isn't validated.
    pub unsafe fn offset_to_mut_ptr(&mut self, offset: Offset) -> *mut u8 {
        self.as_mut_ptr().add(offset.0 as usize)
    }
    /// Get the pointer to the end of the file. This pointer is unsafe because it points at the end
    /// of the buffer, which doesn't contain data.
    pub unsafe fn eof(&self) -> *const u8 {
        self.as_ptr().add(self.len())
    }

    /// Verifies that the given pointer is a valid pointer into this buffer.
    pub fn validate_ptr(&self, ptr: *const u8) -> bool {
        let start = self.as_ptr() as usize;
        let end = unsafe { self.eof() as usize };
        let pos = ptr as usize;

        start <= pos && pos < end
    }

    /// Convert a pointer to an offset. This returns [`Error::BadPointer`](Error::BadPointer) if the pointer
    /// isn't in the buffer range.
    pub fn ptr_to_offset(&self, ptr: *const u8) -> Result<Offset, Error> {
        if !self.validate_ptr(ptr) {
            return Err(Error::BadPointer(ptr));
        }
        
        let delta = (ptr as usize) - (self.as_ptr() as usize);

        /* executables greater than 4GB are unsupported */
        if delta > (u32::MAX as usize) {
            Err(Error::BadPointer(ptr))
        }
        else {
            Ok(Offset(delta as u32))
        }
    }
    /// Converts a reference to an offset. Returns a [`Error::BadPointer`](Error::BadPointer) error if the reference
    /// isn't from the buffer.
    pub fn ref_to_offset<T>(&self, data: &T) -> Result<Offset, Error> {
        self.ptr_to_offset(data as *const T as *const u8)
    }
    
    /// Produces an MD5 hash of this buffer.
    pub fn md5(&self) -> Vec<u8> {
        self.as_slice().md5()
    }
    /// Produces a SHA1 hash of this buffer.
    pub fn sha1(&self) -> Vec<u8> {
        self.as_slice().sha1()
    }
    /// Produces a SHA256 hash of this buffer.
    pub fn sha256(&self) -> Vec<u8> {
        self.as_slice().sha256()
    }
    /// Produces the entropy of the buffer.
    pub fn entropy(&self) -> f64 {
        self.as_slice().entropy()
    }
    /// Gets a reference to an object in the buffer data. This is ultimately how PE objects are created from the buffer.
    ///
    /// ```rust
    /// use exe::buffer::Buffer;
    /// use exe::headers::{ImageDOSHeader, ImageNTHeaders32, NT_SIGNATURE};
    /// use exe::types::Offset;
    ///
    /// let file_data = std::fs::read("test/compiled.exe").unwrap();
    /// let buffer = Buffer::new(file_data.as_slice());
    /// 
    /// let dos_header = buffer.get_ref::<ImageDOSHeader>(Offset(0)).unwrap();
    /// let nt_header = buffer.get_ref::<ImageNTHeaders32>(dos_header.e_lfanew).unwrap();
    /// 
    /// assert_eq!(nt_header.signature, NT_SIGNATURE);
    /// ```
    pub fn get_ref<T>(&self, offset: Offset) -> Result<&T, Error> {
        let t_size = mem::size_of::<T>();
        let end = t_size+offset.0 as usize;

        if end > self.len() {
            return Err(Error::BufferTooSmall(self.len(), end));
        }

        unsafe {
            let ptr = self.offset_to_ptr(offset) as *const T;
            Ok(&*ptr)
        }
    }
    /// Gets a mutable reference to an object in the buffer data.
    pub fn get_mut_ref<T>(&mut self, offset: Offset) -> Result<&mut T, Error> {
        let t_size = mem::size_of::<T>();
        let end = t_size+offset.0 as usize;

        if end > self.len() {
            return Err(Error::BufferTooSmall(self.len(), end));
        }

        unsafe {
            let ptr = self.offset_to_mut_ptr(offset);
            Ok(&mut *(ptr as *const T as *mut T))
        }
    }
    /// Converts a reference of type `T` into a mutable reference.
    pub fn make_mut_ref<T>(&mut self, data: &T) -> Result<&mut T, Error> {
        let offset = match self.ref_to_offset(data) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        self.get_mut_ref(offset)
    }
    /// Gets a slice reference of data in the buffer. This is how to get arrays from the buffer.
    ///
    /// ```rust
    /// use exe::buffer::Buffer;
    /// use exe::types::Offset;
    ///
    /// let file_data = std::fs::read("test/compiled.exe").unwrap();
    /// let buffer = Buffer::new(file_data.as_slice());
    /// let mz = buffer.get_slice_ref::<u8>(Offset(0), 2).unwrap();
    /// 
    /// assert_eq!(mz, [0x4D, 0x5A]);
    /// ```
    pub fn get_slice_ref<T>(&self, offset: Offset, count: usize) -> Result<&[T], Error> {
        let t_size = mem::size_of::<T>() * count;
        let end = t_size+offset.0 as usize;

        if end > self.len() {
            return Err(Error::BufferTooSmall(self.len(), end));
        }

        unsafe {
            let ptr = self.offset_to_ptr(offset) as *const T;
            Ok(slice::from_raw_parts(ptr, count))
        }
    }
    /// Gets a mutable slice reference of data in the buffer.
    pub fn get_mut_slice_ref<T>(&mut self, offset: Offset, count: usize) -> Result<&mut [T], Error> {
        let t_size = mem::size_of::<T>() * count;
        let end = t_size+offset.0 as usize;

        if end > self.len() {
            return Err(Error::BufferTooSmall(self.len(), end));
        }

        unsafe {
            let ptr = self.offset_to_mut_ptr(offset);
            Ok(slice::from_raw_parts_mut(ptr as *const T as *mut T, count))
        }
    }
    /// Converts a slice reference of type `T` into a mutable slice reference.
    pub fn make_mut_slice_ref<T>(&mut self, data: &[T]) -> Result<&mut [T], Error> {
        let offset = match self.ptr_to_offset(data.as_ptr() as *const u8) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };

        self.get_mut_slice_ref::<T>(offset, data.len())
    }
    /// Get the size of a zero-terminated C-string in the data.
    pub fn get_cstring_size(&self, offset: Offset, thunk: bool, max_size: Option<usize>) -> Result<usize, Error> {
        let end = match max_size {
            None => self.len(),
            Some(s) => (offset.0 as usize) + s,
        };

        if end > self.len() {
            return Err(Error::BufferTooSmall(self.len(), end));
        }

        let mut cursor = Cursor::new(self.as_slice());
        let mut index = offset.0 as usize;

        for i in index..end {
            cursor.set_position(i as u64);

            let val = cursor.read_u8();

            match val {
                Err(_) => return Err(Error::BufferTooSmall(self.len(), i as usize)),
                Ok(v) => match v {
                    0 => { index = i; break; },
                    _ => ()
                }
            }
        }

        index += 1; // include null byte
        let mut size = index - (offset.0 as usize);

        if thunk {
            size += size % 2;
        }

        Ok(size)
    }
    /// Gets the size of a zero-terminated UTF16 string in the data.
    pub fn get_widestring_size(&self, offset: Offset, max_size: Option<usize>) -> Result<usize, Error> {
        let end = match max_size {
            None => self.len(),
            Some(s) => (offset.0 as usize) + (s * 2),
        };

        if end > self.len() {
            return Err(Error::BufferTooSmall(self.len(), end));
        }

        let mut cursor = Cursor::new(self.as_slice());
        let mut index = offset.0 as usize;

        for i in (index..end).step_by(2) {
            cursor.set_position(i as u64);

            let val = cursor.read_u16::<LittleEndian>();

            match val {
                Err(_) => return Err(Error::BufferTooSmall(self.len(), i as usize)),
                Ok(v) => match v {
                    0 => { index = i; break; },
                    _ => ()
                }
            }
        }

        Ok( ( (index+2) - (offset.0 as usize) ) / 2 )
    }
    /// Get a zero-terminated C-string from the data. The thunk option is there to handle imports by name, whose null
    /// terminated value size is dependent on how long the string is (i.e., if it's an odd length, an extra zero is
    /// appended).
    ///
    /// ```rust
    /// use exe::buffer::Buffer;
    /// use exe::types::{Offset, CCharString};
    ///
    /// let file_data = std::fs::read("test/dll.dll").unwrap();
    /// let buffer = Buffer::new(file_data.as_slice());
    /// let dll_name = buffer.get_cstring(Offset(0x328), false, None).unwrap();
    ///
    /// assert_eq!(dll_name.as_str(), "dll.dll");
    /// ```
    pub fn get_cstring(&self, offset: Offset, thunk: bool, max_size: Option<usize>) -> Result<&[CChar], Error> {
        let found_size = match self.get_cstring_size(offset, thunk, max_size) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        self.get_slice_ref::<CChar>(offset, found_size)
    }
    /// Get a mutable zero-terminated C-string from the data.
    pub fn get_mut_cstring(&mut self, offset: Offset, thunk: bool, max_size: Option<usize>) -> Result<&mut [CChar], Error> {
        let found_size = match self.get_cstring_size(offset, thunk, max_size) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        self.get_mut_slice_ref::<CChar>(offset, found_size)
    }
    /// Get a zero-terminated UTF16 string from the data.
    pub fn get_widestring(&self, offset: Offset, max_size: Option<usize>) -> Result<&[WChar], Error> {
        let found_size = match self.get_widestring_size(offset, max_size) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        self.get_slice_ref::<WChar>(offset, found_size)
    }
    /// Get a mutable zero-terminated UTF16 string from the data.
    pub fn get_mut_widestring(&mut self, offset: Offset, max_size: Option<usize>) -> Result<&mut [WChar], Error> {
        let found_size = match self.get_widestring_size(offset, max_size) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        self.get_mut_slice_ref::<WChar>(offset, found_size)
    }
    /// Read arbitrary data from the buffer.
    pub fn read(&self, offset: Offset, size: usize) -> Result<&[u8], Error> {
        self.get_slice_ref::<u8>(offset, size)
    }
    /// Read mutable arbitrary data from the buffer.
    pub fn read_mut(&mut self, offset: Offset, size: usize) -> Result<&mut [u8], Error> {
        self.get_mut_slice_ref::<u8>(offset, size)
    }
    /// Write arbitrary data to the buffer.
    pub fn write(&mut self, offset: Offset, data: &[u8]) -> Result<(), Error> {
        let size = data.len();
        let end = size+offset.0 as usize;

        if end > self.len() {
            return Err(Error::BufferTooSmall(self.len(), end));
        }

        let from_ptr = data.as_ptr();
            
        unsafe {
            let to_ptr = self.offset_to_mut_ptr(offset);
            ptr::copy(from_ptr, to_ptr, size);
            
            Ok(())
        }
    }
    /// Write an object reference to the buffer.
    pub fn write_ref<T>(&mut self, offset: Offset, data: &T) -> Result<(), Error> {
        self.write(offset, ref_to_bytes::<T>(data))
    }
    /// Write a slice reference to the buffer.
    pub fn write_slice_ref<T>(&mut self, offset: Offset, data: &[T]) -> Result<(), Error> {
        self.write(offset, slice_ref_to_bytes::<T>(data))
    }

    /// Search for a slice of data in the buffer. Returns an empty vector if nothing is found.
    pub fn search_slice(&self, search: &[u8]) -> Result<Vec<Offset>, Error> {
        if search.len() > self.len() {
            return Err(Error::BufferTooSmall(self.len(), search.len()));
        }

        let buffer_data = self.as_slice();
        let mut offsets = Vec::<Offset>::new();

        for i in 0..(self.len() - search.len()) {
            if buffer_data[i] == search[0] {
                offsets.push(Offset(i as u32));
            }
        }

        let mut results = Vec::<Offset>::new();
        
        for offset in &offsets {
            let found_slice = match self.read(*offset, search.len()) {
                Ok(s) => s,
                Err(e) => return Err(e),
            };

            if found_slice == search {
                results.push(*offset);
            }
        }

        Ok(results)
    }

    /// Search for an object reference within the buffer. Returns an empty vector if nothing is found.
    pub fn search_ref<T>(&self, search: &T) -> Result<Vec<Offset>, Error> {
        self.search_slice(ref_to_bytes::<T>(search))
    }
}
impl<Idx: slice::SliceIndex<[u8]>> Index<Idx> for Buffer {
    type Output = Idx::Output;

    fn index(&self, index: Idx) -> &Self::Output {
        self.as_slice().index(index)
    }
}
impl<Idx: slice::SliceIndex<[u8]>> IndexMut<Idx> for Buffer {
    fn index_mut(&mut self, index: Idx) -> &mut Self::Output {
        self.as_mut_slice().index_mut(index)
    }
}
#[cfg(windows)]
impl Drop for Buffer {
    fn drop(&mut self) {
        if self.allocated { unsafe { VirtualFree(self.data as LPVOID, self.length, 0x8000) }; }
    }
}
