# exe-rs
The PE Executable Library, but for Rust!

This library is tested on the [Corkami corpus](https://github.com/corkami/pocs/tree/master/PE)!

Read the documentation [here](https://docs.rs/exe/)!

# Changelog

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
