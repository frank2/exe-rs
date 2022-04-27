# Changelog

## 0.5.4
## Bugfixes
* I really wish docs.rs had a way to test their documentation generation...

## 0.5.3
### Bugfixes
* Fixed an issue with docs.rs not compiling the documentation properly due to misconfigured features.

## 0.5.2
### Features
* `pkbuffer` upgraded to 0.4.1, which features dynamic searching of buffer spaces.
* A new object was created, `VallocBuffer`, and `VallocPE` was refactored to accomodate.
* `VallocPE` now has a loader function, `from_pe`. This uses `VirtualAlloc` to reserve and contiguously load the PE's sections in as similar way to the kernel as possible. 
    * as a result of this, `load_image` has been moved to `VallocPE`

### Bugfixes
* Windows features are now behind the Cargo feature `win32`. This is mostly so that the Windows features show up in documentation.
* moved `VallocPE`, `VallocBuffer` and the `PE` trait into their own libraries, `exe::valloc` and `exe::pe` respectively.
* `Protect` now matches more closely with the MSDN docs.

## 0.5.1
### Features
* `Offset` and other address types can now be converted into/from their base types via the `From` trait

### Bugfixes
* Update to `pkbuffer` 0.4.0
    * this update brings some type and casting safety to the library
    * this requires knowledge of the `Castable` trait for getting objects from PE files, see the `pkbuffer` documentation for more details.

## 0.5.0
**This update makes major code-breaking changes!** Notably, the buffer module has been moved into its own library called [pkbuffer](https://github.com/frank2/pkbuffer). This caused the whole library to need to be refactored, and ultimately changed the way the structures interact with the data! As a result, though, PE structure objects can retain buffer functionality without having to rely on interacting with a member of a struct (i.e., the pattern of "pefile.pe.buffer" is no longer necessary). The interface for buffer objects changed, though-- instead of requiring an explicit `Offset` object, they now take a `usize` as an offset. To make things simpler, `RVA` and `Offset` can now be explicitly converted into `usize` with the `Into` trait.

This refactor has caused the main `PE` module to become a trait! This means you can now flexibly create your own `PE` object by implementing this trait as well as the `Buffer` trait on an object.

### Features
* library refactored to use [pkbuffer](https://github.com/frank2/pkbuffer)
    * there are three main PE types now: `PtrPE` (for pointer-based PE data), `VecPE` (for owned PE data) and `VallocPE` for Windows (for data allocated with `VirtualAlloc`).
    * `PEImage` has been renamed to `VecPE`
    * `align` has been moved into the main module.
    * `HashData` and `Entropy` traits have been moved into the main module.
    * `PE` derived objects can now be used like `Buffer` objects.
    * `BufferTooSmall` error has been renamed to `OutOfBounds` to match pkbuffer.
    * `from_ptr` has been moved to `PtrPE` and renamed to `from_memory`
    * `to_image` has been moved to `PtrPE` and renamed to `to_vecpe`
    * the following PE functions are now their own functions:
        * `find_embedded_images`
        * `load_image`
* `RVA` and `Offset` can now be converted into a `usize` via the `Into` trait.
* `align` now takes generic unsigned integer types instead of just a `usize`, read the docs for more info.

### Bugfixes
* now using `AsRef`/`AsMut` in instances where `[u8]` is being used.
* question mark operator used throughout the code instead of explicit match/return cases.
* `Error` now implements `Send` and `Sync`, thanks to @[__the_sylph__](https://twitter.com/__the_sylph__/) for reporting this!

## 0.4.6
### Features
* PE images can now be created from a `&[u8]` of assembly data. This is useful for quickly turning raw assembly into an executable! See `PEImage::from_assembly`.
* Export names can now be acquired by hash algorithm, see `ExportDirectory::get_export_name_by_hash`.

## 0.4.5
### Features
* Errors now feature more context! For example, `InvalidRVA` now contains the offending RVA. See the docs for more details!
### Bugfixes
* `Error` now implements the `std::error::Error` trait and `std::fmt::Display` trait, thanks to p0lloloco for reporting!

## 0.4.4
### Features
* Only available for Windows: `Buffer` objects can now be allocated directly with the `Buffer::virtual_alloc` function, see the docs for more.
* Only available for Windows: `ImageImportDescriptor` objects can now have their import address table resolved, see `ImageImportDescriptor::resolve_iat`.
* Only available for Windows: `PE` images can now be loaded and prepared for execution, see `PE::load_image`.
### Bugfixes
* `PE` address conversion functions (e.g., `PE::offset_to_rva`) now validate their input addresses before recalculating.
* fixed a bug in `Address::as_ptr` where addresses were not being translated between `PEType` images.

## 0.4.3
### Features
* added ability to turn a slice of type `T` into an array of bytes, see `Buffer::slice_ref_to_bytes`.
* added the ability to add arbitrary relocations to a relocation table, see `RelocationDirectory::add_relocation`.
* `ImageSectionHeader` now implements the Default trait.
* added the ability to add and append sections to the PE's section table, see `PE::add_section` and `PE::append_section`.
* added the ability to convert objects with the `Address` trait (e.g., `Offset`, `RVA`, `VA`, etc.) to pointers, see `Address::as_ptr`.
* added the `PEImage` object, a wrapper for `PE` objects which contains owned data in a backing vector, see the docs for more.
* `Buffer` objects now implement the `Index` trait.
* [`VS_VERSIONINFO`](https://docs.microsoft.com/en-us/windows/win32/menurc/vs-versioninfo) has been implemented, see `types::VSVersionInfo` and similarly named structures.
* added an alignment function, see `buffer::align`.
* added the ability to convert a reference to mutable, see `Buffer::make_mut_ref` and `Buffer::make_mut_slice_ref`.
### Bugfixes
* renamed `ref_to_slice` to `ref_to_bytes` to be more clear
* marked objects still marked with `#[repr(packed)]` with `#[repr(C)]`
* tracked down TLS directory characteristics and made a bitflag structure, see `headers::TLSCharacteristics`
* `Buffer` objects now operate on pointers, which solves a lot of underlying code

## 0.4.2
### Features
* implemented the [imphash algorithm](https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html), see `PE::calculate_imphash`.
* buffers and `PE` objects can now be cloned!
* added `ImportDirectory::get_import_map`, which calls `get_imports` on all the descriptors and maps them to their DLL name.
* added ability to convert an image from a disk image to a memory image and vice versa, see `PE::recreate_image`.
* added ability to search for byte strings in buffer, see `Buffer::search_slice` and `Buffer::search_ref`.
* implemented the Debug directory, see `headers::ImageDebugDirectory`.
* implemented the TLS directory, see `types::TLSDirectory`, `headers::ImageTLSDirectory32` and `headers::ImageTLSDirectory64`.
### Bugfixes
* changed how `ImageImportDescriptor::get_imports` resolves ordinals, thanks to the `ImportData` enum it now resolves in a more sane manner.
* forgot to make a function public, oops! `RelocationDirectory::relocate` is now visible and callable.
* alignments have no need to be validated, validation checks removed from alignment functions.
* headers are now `#[repr(C)]` instead of `#[repr(packed)]`, allowing for deriving of traits such as Debug, Eq and Clone.

## 0.4.1
### Features
* **buffers now operate on `u8` slice references!** this has affected how PE files are initialized, see [the docs](https://docs.rs/exe) for more details.
* added functionality to align offsets and RVAs to the file alignment and section alignment of the headers, see ```PE::align_to_file``` and ```ImageSectionHeader::is_aligned_to_file``` for details.
* added functionality to pull the DOS stub out of the image, see ```PE::get_dos_stub```.
* added a great example of dumping section hashes from a PE file, see ```PE::buffer::HashData``` in the docs.
* added syntactic sugar for `Offset` objects, buffer operations requiring offsets can now be accessed directly from them with a supplied `PE` object.
* `PE` image can now calculate disk sizes and memory sizes, see `PE::calculate_disk_size` and `PE::calculate_memory_size`.
* PE images embedded in a given executable can now be extracted! see `PE::find_embedded_images`. this does not have a corresponding test because it was tested on malware.
* added ability to calculate and validate PE checksums of an image, see `PE::validate_checksum` and `PE::calculate_checksum`.
### Bugfixes
* fixed a bug in default ```ImageFileHeader``` generation where the ```size_of_optional_header``` value was calculated incorrectly.
* fixed a bug where pointers weren't being calculated correctly into offsets.

## 0.4
### Features
* added support for resource directories
* refactored data directories to be initialized in a new fashion, see [the docs](https://docs.rs/exe) for more details and [the test file](https://github.com/frank2/exe-rs/blob/main/src/tests.rs) for examples.
* PE images can now be parsed from pointers, see ```PE::from_ptr``` and [the test file](https://github.com/frank2/exe-rs/blob/main/src/tests.rs) for example usage.

## 0.3.1
### Features
* PE object can now parse memory dumps properly, testing against [compiled_dumped.bin](https://github.com/frank2/exe-rs/blob/main/test/compiled_dumped.bin).
* data directory is now parsed correctly, testing against [no_dd.exe](https://github.com/corkami/pocs/blob/master/PE/bin/no_dd.exe)
* buffer now has support for arbitrary hashing of ```u8``` slices, see the HashData trait in the buffer module.
* buffer now also supports arbitrary calculation of entropy on ```u8``` slices, see the Entropy trait in the buffer module.
* buffers can now be dumped to disk (novel!) see ```Buffer::save```.
* add functionality to ```ImageSectionHeader``` such as reading data and calculating proper offsets to data.
* all headers in the headers module now implement clone!
### Bugfixes
* fixed a bug where ```RVA```s got translated incorrectly if they had no ```Offset``` equivalent

## 0.3
### Features
* added support for relocation directories
* moved PE headers into the headers module to differentiate them from Rust types
* added alignment validation for NT headers
* allow for mutable ImageImportByName structure
### Bugfixes
* fixed a bug where import thunks weren't properly parsed, now tested against [imports_nothunk.exe](https://github.com/corkami/pocs/blob/master/PE/bin/imports_nothunk.exe)
* fixed a bug in the default file headers for x64 architectures

## 0.2
### Features
* crate is published!
* add support for import and export directories
