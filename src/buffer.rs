//! This module contains everything needed for representing a PE buffer. The buffer contains
//! raw functionality necessary to cast objects from the data vector.

use byteorder::{LittleEndian, ReadBytesExt};

use std::convert::AsRef;
use std::fs;
use std::io::{Error as IoError, Cursor};
use std::mem;
use std::path::Path;
use std::ptr;
use std::slice;

use crate::types::{Offset, CChar, WChar, ImageImportByName};
use crate::Error;

#[derive(Clone, Eq, PartialEq, Debug)]
/// A buffer representing the PE file.
pub struct Buffer {
    data: Vec<u8>
}
impl Buffer {
    /// Creates a new buffer with an optional size.
    pub fn new(size: Option<usize>) -> Self {
        if size.is_some() {
            Self { data: vec![0u8; size.unwrap()] }
        }
        else {
            Self { data: Vec::<u8>::new() }
        }
    }
    /// Creates a new buffer from a slice of data.
    pub fn from_data(data: &[u8]) -> Self {
        Self {
            data: data.iter().cloned().collect()
        }
    }
    /// Creates a new buffer from disk data.
    pub fn from_file<P: AsRef<Path>>(filename: P) -> Result<Self, IoError> {
        match fs::read(filename) {
            Ok(contents) => Ok(Self { data: contents }),
            Err(e) => Err(e),
        }
    }
    /// Get the length of the buffer.
    pub fn len(&self) -> usize {
        self.data.len()
    }
    /// Resize the buffer.
    pub fn resize(&mut self, size: usize) {
        self.data.resize(size, 0);
    }
    /// Get the buffer as a slice.
    pub fn as_slice(&self) -> &[u8] {
        self.data.as_slice()
    }
    /// Get the buffer as a mutable slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.data.as_mut_slice()
    }
    /// Get the buffer as a pointer.
    pub fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }
    /// Get the buffer as a mutable pointer.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }
    /// Append a vector of data to the buffer.
    pub fn append(&mut self, other: &mut Vec<u8>) {
        self.data.append(other)
    }
    /// Check if the PE file is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
    /// Extend the buffer with a data slice.
    pub fn extend_from_slice(&mut self, other: &[u8]) {
        self.data.extend_from_slice(other)
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
    /// Convert a pointer to an offset. This returns ```Error::BadPointer``` if the pointer
    /// isn't in the buffer range.
    pub fn ptr_to_offset(&self, ptr: *const u8) -> Result<Offset, Error> {
        let start = self.as_ptr() as usize;
        let end = unsafe { self.eof() as usize };
        let pos = ptr as usize;

        if start <= pos && pos < end {
            let delta = pos - start;

            /* executables greater than 4GB are unsupported */
            if delta > (u32::MAX as usize) {
                Err(Error::BadPointer)
            }
            else {
                Ok(Offset(delta as u32))
            }
        }
        else {
            Err(Error::BadPointer)
        }
    }
    /// Converts a reference to an offset. Returns a ```Error::BadPointer``` error if the reference
    /// isn't from the buffer.
    pub fn ref_to_offset<T>(&self, data: &T) -> Result<Offset, Error> {
        self.ptr_to_offset(data as *const T as *const u8)
    }
    /// Gets a reference to an object in the buffer data. This is ultimately how PE objects are created from the buffer.
    ///
    /// ```rust
    /// use exe::buffer::Buffer;
    /// use exe::types::{Offset, ImageDOSHeader, ImageNTHeaders32, NT_SIGNATURE};
    ///
    /// let buffer = Buffer::from_file("test/compiled.exe").unwrap();
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
            return Err(Error::BufferTooSmall);
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
            return Err(Error::BufferTooSmall);
        }

        unsafe {
            let ptr = self.offset_to_mut_ptr(offset) as *mut T;
            Ok(&mut *ptr)
        }
    }
    /// Gets a slice reference of data in the buffer. This is how to get arrays in the buffer.
    ///
    /// ```rust
    /// use exe::buffer::Buffer;
    /// use exe::types::Offset;
    ///
    /// let buffer = Buffer::from_file("test/compiled.exe").unwrap();
    /// let mz = buffer.get_slice_ref::<u8>(Offset(0), 2).unwrap();
    /// 
    /// assert_eq!(mz, [0x4D, 0x5A]);
    /// ```
    pub fn get_slice_ref<T>(&self, offset: Offset, count: usize) -> Result<&[T], Error> {
        let t_size = mem::size_of::<T>() * count;
        let end = t_size+offset.0 as usize;

        if end > self.len() {
            return Err(Error::BufferTooSmall);
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
            return Err(Error::BufferTooSmall);
        }

        unsafe {
            let ptr = self.offset_to_mut_ptr(offset) as *mut T;
            Ok(slice::from_raw_parts_mut(ptr, count))
        }
    }
    /// Get the size of a zero-terminated C-string in the data.
    pub fn get_cstring_size(&self, offset: Offset, thunk: bool, max_size: Option<usize>) -> Result<usize, Error> {
        let end = match max_size {
            None => self.len(),
            Some(s) => (offset.0 as usize) + s,
        };

        if end > self.len() {
            return Err(Error::BufferTooSmall);
        }

        let mut cursor = Cursor::new(self.as_slice());
        let mut index = offset.0 as usize;

        for i in index..end {
            cursor.set_position(i as u64);

            let val = cursor.read_u8();

            match val {
                Err(_) => return Err(Error::BufferTooSmall),
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
            return Err(Error::BufferTooSmall);
        }

        let mut cursor = Cursor::new(self.as_slice());
        let mut index = offset.0 as usize;

        for i in (index..end).step_by(2) {
            cursor.set_position(i as u64);

            let val = cursor.read_u16::<LittleEndian>();

            match val {
                Err(_) => return Err(Error::BufferTooSmall),
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
    /// let buffer = Buffer::from_file("test/dll.dll").unwrap();
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
    /// Get an ```ImageImportByName``` object at the given offset. See the documentation of ```ImageImportByName```
    /// for an explanation of why this is needed.
    pub fn get_import_by_name(&self, offset: Offset) -> Result<ImageImportByName, Error> {
        let hint = match self.get_ref::<u16>(offset) {
            Ok(h) => h,
            Err(e) => return Err(e),
        };
        let name = match self.get_cstring(Offset(offset.0 + (mem::size_of::<u16>() as u32)), true, None) {
            Ok(n) => n,
            Err(e) => return Err(e),
        };

        Ok(ImageImportByName { hint, name })
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
    pub fn write(&mut self, offset: Offset, data: &[u8]) -> Result<usize, Error> {
        let size = data.len();
        let end = size+offset.0 as usize;

        if end > self.len() {
            return Err(Error::BufferTooSmall);
        }

        let from_ptr = data.as_ptr();
            
        unsafe {
            let to_ptr = self.offset_to_mut_ptr(offset);
            ptr::copy(from_ptr, to_ptr, size);
            
            Ok(size)
        }
    }
    /// Write a referenced object to the buffer.
    pub fn write_ref<T>(&mut self, offset: Offset, data: &T) -> Result<usize, Error> {
        let ptr = data as *const T as *const u8;
        let size = mem::size_of::<T>();
        
        unsafe {
            let data_slice = slice::from_raw_parts(ptr, size);
            self.write(offset, data_slice)
        }
    }
}
