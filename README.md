# exe-rs
The PE Executable Library, but for Rust!

This library is tested on the [Corkami corpus](https://github.com/corkami/pocs/tree/master/PE)!

Read the documentation [here](https://docs.rs/exe/)!

# Changelog

## 0.4
* PE object can now parse memory dumps properly, testing against [compiled_dumped.bin](https://github.com/frank2/exe-rs/blob/main/test/compiled_dumped.bin).
* data directory is now parsed correctly, testing against [no_dd.exe](https://github.com/corkami/pocs/blob/master/PE/bin/no_dd.exe)
* buffer now has support for arbitrary hashing of data, see the HashData trait in the buffer module.

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
