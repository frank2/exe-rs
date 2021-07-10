use byteorder::{LittleEndian, ReadBytesExt};

use std::convert::AsRef;
use std::fs;
use std::io::{Error as IoError, Cursor};
use std::mem;
use std::path::Path;
use std::ptr;
use std::slice;

use crate::types::{Offset, CChar, WChar};
use crate::Error;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Buffer {
    data: Vec<u8>
}
impl Buffer {
    pub fn new() -> Self {
        Self {
            data: Vec::<u8>::new()
        }
    }
    pub fn from_data(data: &[u8]) -> Self {
        Self {
            data: data.iter().cloned().collect()
        }
    }
    pub fn from_file<P: AsRef<Path>>(filename: P) -> Result<Self, IoError> {
        match fs::read(filename) {
            Ok(contents) => Ok(Self { data: contents }),
            Err(e) => Err(e),
        }
    }
    pub fn len(&self) -> usize {
        self.data.len()
    }
    pub fn resize(&mut self, size: usize) {
        self.data.resize(size, 0);
    }
    pub fn as_slice(&self) -> &[u8] {
        self.data.as_slice()
    }
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.data.as_mut_slice()
    }
    pub fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }
    pub fn append(&mut self, other: &mut Vec<u8>) {
        self.data.append(other)
    }
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
    pub fn extend_from_slice(&mut self, other: &[u8]) {
        self.data.extend_from_slice(other)
    }
    pub unsafe fn offset_to_ptr(&self, offset: Offset) -> *const u8 {
        self.as_ptr().offset(offset.0 as isize)
    }
    pub unsafe fn offset_to_mut_ptr(&mut self, offset: Offset) -> *mut u8 {
        self.as_mut_ptr().offset(offset.0 as isize)
    }
    pub unsafe fn eof(&self) -> *const u8 {
        self.as_ptr().offset(self.len() as isize)
    }
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
    pub fn ref_to_offset<T>(&self, data: &T) -> Result<Offset, Error> {
        self.ptr_to_offset(data as *const T as *const u8)
    }
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

        println!("[DEBUG] index ended at {:?}", index);

        if thunk {
            let delta = index - (offset.0 as usize);

            if delta % 2 != 0 {
                index += 1;
            }
        }

        Ok((index+1) - (offset.0 as usize))
    }
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
            cursor.set_position(index as u64);

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
    pub fn get_cstring(&self, offset: Offset, thunk: bool, max_size: Option<usize>) -> Result<&[CChar], Error> {
        let found_size = match self.get_cstring_size(offset, thunk, max_size) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        self.get_slice_ref::<CChar>(offset, found_size)
    }
    pub fn get_mut_cstring(&mut self, offset: Offset, thunk: bool, max_size: Option<usize>) -> Result<&mut [CChar], Error> {
        let found_size = match self.get_cstring_size(offset, thunk, max_size) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        self.get_mut_slice_ref::<CChar>(offset, found_size)
    }
    pub fn get_widestring(&self, offset: Offset, max_size: Option<usize>) -> Result<&[WChar], Error> {
        let found_size = match self.get_widestring_size(offset, max_size) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        self.get_slice_ref::<WChar>(offset, found_size)
    }
    pub fn get_mut_widestring(&mut self, offset: Offset, max_size: Option<usize>) -> Result<&mut [WChar], Error> {
        let found_size = match self.get_widestring_size(offset, max_size) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        self.get_mut_slice_ref::<WChar>(offset, found_size)
    }
    pub fn read(&self, offset: Offset, size: usize) -> Result<&[u8], Error> {
        self.get_slice_ref::<u8>(offset, size)
    }
    pub fn read_mut(&mut self, offset: Offset, size: usize) -> Result<&mut [u8], Error> {
        self.get_mut_slice_ref::<u8>(offset, size)
    }
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
    pub fn write_ref<T>(&mut self, offset: Offset, data: &T) -> Result<usize, Error> {
        let ptr = data as *const T as *const u8;
        let size = mem::size_of::<T>();
        
        unsafe {
            let data_slice = slice::from_raw_parts(ptr, size);
            self.write(offset, data_slice)
        }
    }
}
