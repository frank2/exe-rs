# exe-rs
```exe-rs``` is a Portable Executable (PE) parsing library tested on multiple kinds of malformed PE executables, including [the Corkami corpus](https://github.com/corkami/pocs/tree/master/PE) and various forms of malware! It's a library built with creation in mind as well as parsing, attempting to make tasks related to PE files as smooth and flawless as possible.

You can read the documentation [here](https://docs.rs/exe/), and see various use examples in [the test file](https://github.com/frank2/exe-rs/blob/main/src/tests.rs).

# Changelog

## 0.5
### Features
* implemented the [imphash algorithm](https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html), see `PE::calculate_imphash`.
* buffers and `PE` objects can now be cloned!
* added `ImportDirectory::get_import_map`, which calls `get_imports` on all the descriptors and maps them to their DLL name.
* added ability to convert an image from a disk image to a memory image and vice versa, see `PE::recreate_image`.
* added ability to search for byte strings in buffer, see `Buffer::search_slice` and `Buffer::search_ref`.
* implemented the Debug directory, see `headers::ImageDebugDirectory`.
### Bugfixes
* changed how `ImageImportDescriptor::get_imports` resolves ordinals, thanks to the `ImportData` enum it now resolves in a more sane manner.
* forgot to make a function public, oops! `RelocationDirectory::relocate` is now visible and callable.
* alignments have no need to be validated, validation checks removed from alignment functions.

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
