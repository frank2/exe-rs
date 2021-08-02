# exe-rs
```exe-rs``` is a Portable Executable (PE) parsing library tested on multiple kinds of malformed PE executables, including [the Corkami corpus](https://github.com/corkami/pocs/tree/master/PE) and various forms of malware! It's a library built with creation in mind as well as parsing, attempting to make tasks related to PE files as smooth and flawless as possible.

You can read the documentation [here](https://docs.rs/exe/), and see various use examples in [the test file](https://github.com/frank2/exe-rs/blob/main/src/tests.rs).

# Changelog

## 0.4.1
* buffers now operate on `u8` slice references! this has affected how PE files are initialized, see [the docs](https://docs.rs/exe) for more details.
* fixed a bug in default ```ImageFileHeader``` generation where the ```size_of_optional_header``` value was calculated incorrectly.
* added functionality to align offsets and RVAs to the file alignment and section alignment of the headers, see ```PE::align_to_file``` and ```ImageSectionHeader::is_aligned_to_file``` for details.
* added functionality to pull the DOS stub out of the image, see ```PE::get_dos_stub```.
* added a great example of dumping section hashes from a PE file, see ```PE::buffer::HashData``` in the docs.
* added syntactic sugar for `Offset` objects, buffer operations requiring offsets can now be accessed directly from them with a supplied `PE` object.
* `PE` image can now calculate disk sizes and memory sizes, see `PE::calculate_disk_size` and `PE::calculate_memory_size`.

## 0.4
* added support for resource directories
* refactored data directories to be initialized in a new fashion, see [the docs](https://docs.rs/exe) for more details and [the test file](https://github.com/frank2/exe-rs/blob/main/src/tests.rs) for examples.
* PE images can now be parsed from pointers, see ```PE::from_ptr``` and [the test file](https://github.com/frank2/exe-rs/blob/main/src/tests.rs) for example usage.

## 0.3.1
* PE object can now parse memory dumps properly, testing against [compiled_dumped.bin](https://github.com/frank2/exe-rs/blob/main/test/compiled_dumped.bin).
* data directory is now parsed correctly, testing against [no_dd.exe](https://github.com/corkami/pocs/blob/master/PE/bin/no_dd.exe)
* buffer now has support for arbitrary hashing of ```u8``` slices, see the HashData trait in the buffer module.
* buffer now also supports arbitrary calculation of entropy on ```u8``` slices, see the Entropy trait in the buffer module.
* buffers can now be dumped to disk (novel!) see ```Buffer::save```.
* add functionality to ```ImageSectionHeader``` such as reading data and calculating proper offsets to data.
* all headers in the headers module now implement clone!
* fixed a bug where ```RVA```s got translated incorrectly if they had no ```Offset``` equivalent

## 0.3
* added support for relocation directories
* moved PE headers into the headers module to differentiate them from Rust types
* added alignment validation for NT headers
* allow for mutable ImageImportByName structure
* fixed a bug where import thunks weren't properly parsed, now tested against [imports_nothunk.exe](https://github.com/corkami/pocs/blob/master/PE/bin/imports_nothunk.exe)
* fixed a bug in the default file headers for x64 architectures

## 0.2
* crate is published!
* add support for import and export directories
