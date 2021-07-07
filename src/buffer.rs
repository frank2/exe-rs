use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::fs;
use std::mem;
use std::ptr;
use std::slice;

use crate::types::Offset;

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
    pub fn from_file(filename: &str) -> Result<Self, IoError> {
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
    pub fn get_ref<T>(&self, offset: Offset) -> Result<&T, IoError> {
        let t_size = mem::size_of::<T>();
        let end = t_size+offset.0 as usize;

        if end > self.len() {
            return Err(IoError::new(IoErrorKind::UnexpectedEof,"reached end of file before cast"));
        }

        unsafe {
            let ptr = self.offset_to_ptr(offset) as *const T;
            Ok(&*ptr)
        }
    }
    pub fn get_mut_ref<T>(&mut self, offset: Offset) -> Result<&mut T, IoError> {
        let t_size = mem::size_of::<T>();
        let end = t_size+offset.0 as usize;

        if end > self.len() {
            return Err(IoError::new(IoErrorKind::UnexpectedEof,"reached end of file before cast"));
        }

        unsafe {
            let ptr = self.offset_to_mut_ptr(offset) as *mut T;
            Ok(&mut *ptr)
        }
    }
    pub fn get_slice_ref<T>(&self, offset: Offset, count: usize) -> Result<&[T], IoError> {
        let t_size = mem::size_of::<T>() * count;
        let end = t_size+offset.0 as usize;

        if end > self.len() {
            return Err(IoError::new(IoErrorKind::UnexpectedEof,"reached end of file before cast"));
        }

        unsafe {
            let ptr = self.offset_to_ptr(offset) as *const T;
            Ok(slice::from_raw_parts(ptr, count))
        }
    }
    pub fn get_mut_slice_ref<T>(&mut self, offset: Offset, count: usize) -> Result<&mut [T], IoError> {
        let t_size = mem::size_of::<T>() * count;
        let end = t_size+offset.0 as usize;

        if end > self.len() {
            return Err(IoError::new(IoErrorKind::UnexpectedEof,"reached end of file before cast"));
        }

        unsafe {
            let ptr = self.offset_to_mut_ptr(offset) as *mut T;
            Ok(slice::from_raw_parts_mut(ptr, count))
        }
    }
    pub fn read(&self, offset: Offset, size: usize) -> Result<&[u8], IoError> {
        self.get_slice_ref::<u8>(offset, size)
    }
    pub fn read_mut(&mut self, offset: Offset, size: usize) -> Result<&mut [u8], IoError> {
        self.get_mut_slice_ref::<u8>(offset, size)
    }
    pub fn write(&mut self, offset: Offset, data: &[u8]) -> Result<usize, IoError> {
        let size = data.len();
        let end = size+offset.0 as usize;

        if end > self.len() {
            return Err(IoError::new(IoErrorKind::UnexpectedEof,"write goes out of bounds"));
        }

        let from_ptr = data.as_ptr();
            
        unsafe {
            let to_ptr = self.offset_to_mut_ptr(offset);
            ptr::copy(from_ptr, to_ptr, size);
            
            Ok(size)
        }
    }
}
