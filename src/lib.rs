//! [exe-rs](https://github.com/frank2/exe-rs) is a library for handling PE files, whether it be building them or analyzing them!
//!
//! Getting started is easy:
//! ```rust
//! use exe::pe::{PE, VecPE};
//! use exe::types::{ImportDirectory, ImportData, CCharString};
//!
//! let image = VecPE::from_disk_file("test/compiled.exe").unwrap();
//! let import_directory = ImportDirectory::parse(&image).unwrap();
//!
//! for descriptor in import_directory.descriptors {
//!    println!("Module: {}", descriptor.get_name(&image).unwrap().as_str().unwrap());
//!    println!("Imports:");
//!
//!    for import in descriptor.get_imports(&image).unwrap() {
//!       match import {
//!          ImportData::Ordinal(x) => println!("   #{}", x),
//!          ImportData::ImportByName(s) => println!("   {}", s)
//!       }
//!    }
//! }
//! ```
//!
//! Standard PE headers and other types can be found in the [headers](headers/) module, while
//! helper types can be found in the [types](types/) module. Low-level functionality for handling
//! PE data, such as collecting pointers and managing pointers as well as pulling out data, is
//! handled by the [pkbuffer](pkbuffer) module and the [`Buffer`](pkbuffer::Buffer) trait.
//! Further usage examples can be found in the [test file](https://github.com/frank2/exe-rs/blob/main/src/tests.rs).

pub mod headers;
pub mod imphash;
pub mod pe;
pub mod types;

#[cfg(feature="win32")]
pub mod valloc;

pub use crate::headers::*;
pub use crate::imphash::*;
pub use crate::pe::*;
pub use crate::types::*;

#[cfg(feature="win32")]
pub use crate::valloc::*;

#[cfg(test)]
mod tests;

use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;

use num_traits;

use pkbuffer::Error as PKError;

use std::collections::HashMap;
use std::io::Error as IoError;
use std::str::Utf8Error;
use widestring::error::Utf16Error;

/// Aligns a given `value` to the boundary specified by `boundary`.
///
/// `value` and `boundary` must be an unsigned integer type.
///
/// # Example
///
/// ```rust
/// use exe::align;
///
/// let value = 0x1200usize;
/// let alignment = 0x1000usize;
///
/// assert_eq!(0x2000, align(value, alignment));
/// ```
pub fn align<V: num_traits::Num + num_traits::Unsigned + num_traits::Zero + core::ops::Rem + Copy>(value: V, boundary: V) -> V {
    if value % boundary == (num_traits::zero::<V>()) {
        value
    }
    else {
        value + (boundary - (value % boundary))
    }
}

/// Find all embedded images within the given [`PE`](PE) file, rendering them as the given [`PEType`](PEType).
pub fn find_embedded_images<P: PE>(pe: &P, pe_type: PEType) -> Result<Option<Vec<PtrPE>>, Error> {
    let mut results = Vec::<PtrPE>::new();
    let mut index = 2usize; // skip the initial MZ header

    while index < pe.len() {
        if index > (u32::MAX as usize) { break; }

        let mz = match pe.get_ref::<u16>(index) {
            Ok(u) => u,
            Err(_) => { index += 1; continue; },
        };
        if *mz != DOS_SIGNATURE { index += 1; continue; }

        let dos_header = match pe.get_ref::<ImageDOSHeader>(index) {
            Ok(h) => h,
            Err(_) => { index += 1; continue; },
        };

        let e_lfanew: usize = index + dos_header.e_lfanew.0 as usize;

        let nt_signature = match pe.get_ref::<u32>(e_lfanew) {
            Ok(s) => s,
            Err(_) => { index += 1; continue; },
        };

        if *nt_signature != NT_SIGNATURE { index += 1; continue; }

        // we now have some kind of PE image. whether it's a valid PE image
        // is yet to be determined. so read to the end of the buffer as a
        // temporary image to start parsing out the proper image.
        let eof = pe.len() - index;
        let pe_ptr = match pe.offset_to_ptr(index) {
            Ok(p) => p,
            Err(_) => { index += 1; continue; },
        };
        let temp_pe = PtrPE::new(pe_type, pe_ptr, eof);

        let image_size = match pe_type {
            PEType::Disk => match temp_pe.calculate_disk_size() {
                Ok(s) => s,
                Err(_) => { index += 1; continue; },
            },
            PEType::Memory => match temp_pe.calculate_memory_size() {
                Ok(s) => s,
                Err(_) => { index += 1; continue; },
            },
        };

        let validate_size = index + image_size;
        if validate_size > pe.len() { index += 1; continue; }

        let real_pe = PtrPE::new(pe_type, pe_ptr, image_size);

        results.push(real_pe);
        index += image_size;
    }

    if results.len() == 0 { Ok(None) }
    else { Ok(Some(results)) }
}

/// Errors produced by the library.
#[derive(Debug)]
pub enum Error {
    /// The error originated in `std::io`.
    IoError(IoError),
    /// The error was a UTF8 error.
    Utf8Error(Utf8Error),
    /// The error was a UTF16 error.
    Utf16Error(Utf16Error),
    /// The error originated in the [pkbuffer](pkbuffer) library.
    PKBufferError(PKError),
    /// The error occurred while parsing a number.
    ParseIntError(std::num::ParseIntError),
    /// The operation went out of bounds of something in the PE file.
    ///
    /// Arg0 is the expected boundary, arg1 is the offending boundary.
    OutOfBounds(usize,usize),
    /// The PE file has an invalid DOS signature.
    ///
    /// Arg0 is the offending signature.
    InvalidDOSSignature(u16),
    /// The header is not aligned correctly.
    BadAlignment,
    /// The PE file has an invalid PE signature.
    ///
    /// Arg0 is the offending signature.
    InvalidPESignature(u32),
    /// The PE file has an invalid NT signature.
    ///
    /// Arg0 is the offending signature.
    InvalidNTSignature(u16),
    /// The offset provided or generated resulted in an invalid offset value.
    ///
    /// Arg0 is the offending offset.
    InvalidOffset(Offset),
    /// The RVA provided or generated resulted in an invalid RVA value.
    ///
    /// Arg0 is the offending RVA.
    InvalidRVA(RVA),
    /// The VA provided or generated resulted in an invalid VA value.
    ///
    /// Arg0 is the offending VA.
    InvalidVA(VA),
    /// The PE section was not found given the search criteria (e.g., an RVA value)
    SectionNotFound,
    /// The pointer provided or generated did not fit in the range of the buffer.
    ///
    /// Arg0 is the offending pointer.
    BadPointer(*const u8),
    /// The data directory requested is currently unsupported.
    ///
    /// Arg0 is the unsupported directory entry.
    UnsupportedDirectory(ImageDirectoryEntry),
    /// The relocation entry is invalid.
    InvalidRelocation,
    /// The provided directory is not available.
    ///
    /// Arg0 is the unavailable directory entry.
    BadDirectory(ImageDirectoryEntry),
    /// The data directory is corrupt and cannot be parsed.
    CorruptDataDirectory,
    /// The architecture of the Rust binary and the given PE file do not match.
    ///
    /// Arg0 represents the expected arch, arg1 represents the offending arch.
    ArchMismatch(Arch, Arch),
    /// The resource was not found with the given arguments.
    ResourceNotFound,
    /// Only available on Windows. The function returned a Win32 error.
    ///
    /// Arg0 represents the Win32 error.
    #[cfg(feature="win32")]
    Win32Error(u32),
    /// Only shows up on Windows. The section table was found to be not contiguous.
    #[cfg(feature="win32")]
    SectionsNotContiguous,
    /// Only shows up on Windows. The section characteristics were bad. This is because there was a bad combination
    /// of read, write and execute characteristics in the section.
    #[cfg(feature="win32")]
    BadSectionCharacteristics(SectionCharacteristics),
    /// Only shows up on Windows. The memory region pointed to by the [`VallocBuffer`](VallocBuffer) is no longer available.
    #[cfg(feature="win32")]
    BufferNotAvailable,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Error::IoError(ref io_error) =>
                write!(f, "i/o error: {}", io_error.to_string()),
            Error::Utf8Error(ref utf8_error) =>
                write!(f, "UTF8 error: {}", utf8_error.to_string()),
            Error::Utf16Error(ref utf16_error) =>
                write!(f, "UTF16 error: {}", utf16_error.to_string()),
            Error::PKBufferError(ref pk_error) =>
                write!(f, "PKBuffer error: {}", pk_error.to_string()),
            Error::ParseIntError(ref int_error) =>
                write!(f, "Int parsing error: {}", int_error.to_string()),
            Error::OutOfBounds(expected, got) =>
                write!(f, "The PE buffer was too small to complete the operation. Buffer length is {}, got {}.", expected, got),
            Error::InvalidDOSSignature(sig) =>
                write!(f, "The PE file has an invalid DOS signature: {:#x}", sig),
            Error::BadAlignment =>
                write!(f, "The header is not aligned correctly."),
            Error::InvalidPESignature(sig) =>
                write!(f, "The PE file has an invalid PE signature: {:#x}", sig),
            Error::InvalidNTSignature(sig) =>
                write!(f, "The PE file has an invalid NT signature: {:#x}", sig),
            Error::InvalidOffset(offset) =>
                write!(f, "The offset provided or generated resulted in an invalid offset value: {:#x}", offset.0),
            Error::InvalidRVA(rva) =>
                write!(f, "The RVA provided or generated resulted in an invalid RVA value: {:#x}", rva.0),
            Error::InvalidVA(va) => {
                let va_value = match va {
                    VA::VA32(va32) => va32.0 as u64,
                    VA::VA64(va64) => va64.0,
                };

                write!(f, "The VA provided or generated resulted in an invalid VA value: {:#x}", va_value)
            },
            Error::SectionNotFound =>
                write!(f, "The PE section was not found given the search criteria."),
            Error::BadPointer(ptr) =>
                write!(f, "The pointer provided or generated did not fit in the range of the buffer: {:p}", ptr),
            Error::UnsupportedDirectory(data_dir) =>
                write!(f, "The data directory requested is currently unsupported: {:?}", data_dir),
            Error::InvalidRelocation =>
                write!(f, "The relocation entry is invalid."),
            Error::BadDirectory(data_dir) =>
                write!(f, "The provided directory is not available in the PE: {:?}", data_dir),
            Error::CorruptDataDirectory =>
                write!(f, "The data directory is corrupt and cannot be parsed."),
            Error::ArchMismatch(expected, got) =>
                write!(f, "The architecture of the Rust binary and the given PE file do not match: expected {:?}, got {:?}", expected, got),
            Error::ResourceNotFound =>
                write!(f, "The resource was not found by the provided parameters."),
            #[cfg(feature="win32")]
            Error::Win32Error(err) => write!(f, "The function returned a Win32 error: {:#x}", err),
            #[cfg(feature="win32")]
            Error::SectionsNotContiguous => write!(f, "The sections in the PE file were not contiguous"),
            #[cfg(feature="win32")]
            Error::BadSectionCharacteristics(chars) => write!(f, "Bad section characteristics: {:#x}", chars.bits()),
            #[cfg(feature="win32")]
            Error::BufferNotAvailable => write!(f, "The buffer is no longer available"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoError(ref e) => Some(e),
            Self::PKBufferError(ref e) => Some(e),
            _ => None,
        }
    }
}
impl std::convert::From<IoError> for Error {
    fn from(io_error: IoError) -> Self {
        Self::IoError(io_error)
    }
}
impl std::convert::From<Utf8Error> for Error {
    fn from(utf8_error: Utf8Error) -> Self {
        Self::Utf8Error(utf8_error)
    }
}
impl std::convert::From<Utf16Error> for Error {
    fn from(utf16_error: Utf16Error) -> Self {
        Self::Utf16Error(utf16_error)
    }
}
impl std::convert::From<PKError> for Error {
    fn from(pk_error: PKError) -> Self {
        Self::PKBufferError(pk_error)
    }
}
impl std::convert::From<std::num::ParseIntError> for Error {
    fn from(int_error: std::num::ParseIntError) -> Self {
        Self::ParseIntError(int_error)
    }
}
unsafe impl Send for Error {}
unsafe impl Sync for Error {}

/// Syntactic sugar for producing various hashes of data. Typically applied to ```[u8]``` slices.
///
/// # Example
///
/// ```rust
/// use hex;
///
/// use exe::{HashData, PE, VecPE};
/// use exe::types::CCharString;
///
/// let pefile = VecPE::from_disk_file("test/compiled.exe").unwrap();
/// let section_table = pefile.get_section_table().unwrap();
///
/// println!("=Section Hashes=");
///
/// for section in section_table {
///    println!("[{}]", section.name.as_str().unwrap());
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
        Md5::digest(self).to_vec()
    }
    fn sha1(&self) -> Vec<u8> {
        Sha1::digest(self).to_vec()
    }
    fn sha256(&self) -> Vec<u8> {
        Sha256::digest(self).to_vec()
    }
}
impl<T> HashData for T
where
    T: PE
{
    fn md5(&self) -> Vec<u8> { self.as_slice().md5() }
    fn sha1(&self) -> Vec<u8> { self.as_slice().sha1() }
    fn sha256(&self) -> Vec<u8> { self.as_slice().sha256() }
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
impl<T> Entropy for T
where
    T: PE
{
    fn entropy(&self) -> f64 { self.as_slice().entropy() }
}

