# exe-rs
The PE Executable Library, but for Rust!

This library is tested on the [Corkami corpus](https://github.com/corkami/pocs/tree/master/PE)!

Read the documentation [here](https://docs.rs/exe/)!

# Changelog

## 0.4
* added support for resource directories
* refactored data directories to initialize them in a new fashion, see [the docs](https://docs.rs/exe) for more details and [the test file](https://github.com/frank2/exe-rs/blob/main/src/tests.rs) for examples.

## 0.3.1
* PE object can now parse memory dumps properly, testing against [compiled_dumped.bin](https://github.com/frank2/exe-rs/blob/main/test/compiled_dumped.bin).
* data directory is now parsed correctly, testing against [no_dd.exe](https://github.com/corkami/pocs/blob/master/PE/bin/no_dd.exe)
* buffer now has support for arbitrary hashing of ```u8``` slices, see the HashData trait in the buffer module.
* buffer now also supports arbitrary calculation of entropy on ```u8``` slices, see the Entropy trait in the buffer module.
* buffers can now be dumped to disk (novel!) see Buffer::save.
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
