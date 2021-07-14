# exe-rs
The PE Executable Library, but for Rust!

This library is tested on the [Corkami corpus](https://github.com/corkami/pocs/tree/master/PE)!

Read the documentation [here](https://docs.rs/exe/)!

# Changelog

## 0.2.1
* fixed a bug where import thunks weren't properly parsed, now tested against [imports_nothunk.exe](https://github.com/corkami/pocs/blob/master/PE/bin/imports_nothunk.exe)
* added alignment validation for NT headers

## 0.2
* crate is published!
* add support for import and export directories
