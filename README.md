# exe-rs
```exe-rs``` is a Portable Executable (PE) parsing library tested on multiple kinds of malformed PE executables, including [the Corkami corpus](https://github.com/corkami/pocs/tree/master/PE) and various forms of malware! It's a library built with creation in mind as well as parsing, attempting to make tasks related to PE files as smooth and flawless as possible.

You can read the documentation [here](https://docs.rs/exe/), and see various use examples in [the test file](https://github.com/frank2/exe-rs/blob/main/src/tests.rs). The changelog between various versions is available [here](https://github.com/frank2/exe-rs/blob/main/CHANGELOG.md).

Windows-specific features (such as loading a given PE file for execution) can be configured by enabling the `win32` feature of the crate.

## Quick Start

```rust
use exe::pe::{PE, VecPE};
use exe::types::{ImportDirectory, ImportData, CCharString};

let image = VecPE::from_disk_file("test/compiled.exe").unwrap();
let import_directory = ImportDirectory::parse(&image).unwrap();

for descriptor in import_directory.descriptors {
   println!("Module: {}", descriptor.get_name(&image).unwrap().as_str().unwrap());
   println!("Imports:");

   for import in descriptor.get_imports(&image).unwrap() {
      match import {
         ImportData::Ordinal(x) => println!("   #{}", x),
         ImportData::ImportByName(s) => println!("   {}", s)
      }
   }
}
```

## Direct Header References (0.5.7+)

Access PE headers directly via references for efficient in-place modification:

```rust
use exe::pe::{PE, VecPE};
use exe::headers::{DOS_SIGNATURE, ImageDOSHeader};

let mut pefile = VecPE::from_disk_file("test.exe").unwrap();

// Get a reference to the DOS header
let dos: &ImageDOSHeader = pefile.get_dos_header_ref().unwrap();
assert_eq!(dos.e_magic, DOS_SIGNATURE);

// Get a mutable reference for in-place modification
let dos: &mut ImageDOSHeader = pefile.get_mut_dos_header_ref().unwrap();
dos.e_csum = 0xDEADBEEF;  // writes directly to buffer

// NT headers work the same way
let nt: &ImageNTHeaders32 = pefile.get_nt_headers_32_ref().unwrap();
```

This enables editing PE headers without copy-out-and-reload overhead.
