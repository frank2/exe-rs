# exe-rs
```exe-rs``` is a Portable Executable (PE) parsing library tested on multiple kinds of malformed PE executables, including [the Corkami corpus](https://github.com/corkami/pocs/tree/master/PE) and various forms of malware! It's a library built with creation in mind as well as parsing, attempting to make tasks related to PE files as smooth and flawless as possible.

You can read the documentation [here](https://docs.rs/exe/), and see various use examples in [the test file](https://github.com/frank2/exe-rs/blob/main/src/tests.rs). The changelog between various versions is available [here](https://github.com/frank2/exe-rs/blob/main/CHANGELOG.md).

Windows-specific features (such as loading a given PE file for execution) can be configured by enabling the `win32` feature of the crate.
