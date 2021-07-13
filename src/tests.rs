use std::collections::HashMap;

use super::*;
use super::types::*;
use super::buffer::*;

#[test]
fn test_docs_lib_01() {
    let pefile = PE::from_file("test/compiled.exe").unwrap();
    let import_directory = pefile.resolve_data_directory(ImageDirectoryEntry::Import).unwrap();

    if let DataDirectory::Import(import_table) = import_directory {
        for import in import_table {
            println!("Module: {}", import.get_name(&pefile).unwrap().as_str());
            println!("Imports: {:?}", import.get_imports(&pefile).unwrap());
        }
    }
}

#[test]
fn test_docs_lib_02() {
    let pefile = PE::from_file("test/normal64.exe").unwrap();
    let headers = pefile.get_valid_nt_headers().unwrap();
    
    match headers {
        NTHeaders::NTHeaders32(_) => panic!("this won't print..."),
        NTHeaders::NTHeaders64(_) => println!("...but this will!"),
    }
}

#[test]
fn test_docs_lib_03() {
    let pefile = PE::from_file("test/compiled.exe").unwrap();
    let data_directory = pefile.resolve_data_directory(ImageDirectoryEntry::Import).unwrap();

    if let DataDirectory::Import(import_table) = data_directory {
        println!("Got the import table!");
    }
    else {
        panic!("Bad import table!");
    }
}

#[test]
fn test_docs_buffer_01() {
    let buffer = Buffer::from_file("test/compiled.exe").unwrap();
    
    let dos_header = buffer.get_ref::<ImageDOSHeader>(Offset(0)).unwrap();
    let nt_header = buffer.get_ref::<ImageNTHeaders32>(dos_header.e_lfanew).unwrap();

    assert_eq!(nt_header.signature, NT_SIGNATURE);
}

#[test]
fn test_docs_buffer_02() {
    let buffer = Buffer::from_file("test/compiled.exe").unwrap();
    let mz = buffer.get_slice_ref::<u8>(Offset(0), 2).unwrap();

    assert_eq!(mz, [0x4D, 0x5A]);
}

#[test]
fn test_docs_buffer_03() {
    let buffer = Buffer::from_file("test/dll.dll").unwrap();
    let dll_name = buffer.get_cstring(Offset(0x328), false, None).unwrap();

    assert_eq!(dll_name.as_str(), "dll.dll");
}

#[test]
fn test_compiled() {
    let compiled = PE::from_file("test/compiled.exe");
    assert!(compiled.is_ok());

    let pefile = compiled.unwrap();

    let arch = pefile.get_arch();
    assert!(arch.is_ok());
    assert_eq!(arch.unwrap(), Arch::X86);

    let bad_header = pefile.get_valid_nt_headers_64();
    assert!(bad_header.is_err());

    let get_headers = pefile.get_valid_nt_headers_32();
    assert!(get_headers.is_ok());

    let headers = get_headers.unwrap();
    
    let get_section_table = pefile.get_section_table();
    assert!(get_section_table.is_ok());

    let section_table = get_section_table.unwrap();
    assert_eq!(section_table.len(), headers.file_header.number_of_sections as usize);
    assert_eq!(section_table[0].name.as_str(), ".text");
    assert_eq!(section_table[1].name.as_str(), ".rdata");
    assert_eq!(section_table[2].name.as_str(), ".data");

    let data_directory = pefile.resolve_data_directory(ImageDirectoryEntry::Import);
    assert!(data_directory.is_ok());

    if let DataDirectory::Import(import_table) = data_directory.unwrap() {
        assert_eq!(import_table.len(), 2);
        assert_eq!(import_table[0].original_first_thunk, RVA(0x2040));
        assert_eq!(import_table[0].name, RVA(0x20A0));
        assert_eq!(import_table[0].first_thunk, RVA(0x2080));

        let name_0 = import_table[0].get_name(&pefile);
        assert!(name_0.is_ok());
        assert_eq!(name_0.unwrap().as_str(), "kernel32.dll");

        let kernel32_thunks_result = import_table[0].get_original_first_thunk(&pefile);
        assert!(kernel32_thunks_result.is_ok());

        let kernel32_thunks = kernel32_thunks_result.unwrap();
        if let Thunk::Thunk32(kernel32_thunk) = kernel32_thunks[0] {
            assert_eq!(*kernel32_thunk, Thunk32(0x2060));
        }
        else {
            panic!("bad thunk");
        }
        
        let kernel32_imports = import_table[0].get_imports(&pefile);
        let kernel32_expected = vec!["ExitProcess".to_string()];
        assert!(kernel32_imports.is_ok());
        assert_eq!(kernel32_imports.unwrap(), kernel32_expected);

        let name_1 = import_table[1].get_name(&pefile);
        assert!(name_1.is_ok());
        assert_eq!(name_1.unwrap().as_str(), "msvcrt.dll");

        let msvcrt_imports = import_table[1].get_imports(&pefile);
        let msvcrt_expected = vec!["printf".to_string()];
        assert!(msvcrt_imports.is_ok());
        assert_eq!(msvcrt_imports.unwrap(), msvcrt_expected);
    }
    else
    {
        panic!("couldn't get import table");
    }
}

#[test]
fn test_dll() {
    let dll = PE::from_file("test/dll.dll");
    assert!(dll.is_ok());

    let pefile = dll.unwrap();

    let directory = pefile.resolve_data_directory(ImageDirectoryEntry::Export);
    assert!(directory.is_ok());

    if let DataDirectory::Export(export_table) = directory.unwrap() {
        let name = export_table.get_name(&pefile);
        assert!(name.is_ok());
        assert_eq!(name.unwrap().as_str(), "dll.dll");

        let exports = export_table.get_export_map(&pefile);
        let expected: HashMap<&str, ThunkData> = [("export", ThunkData::Function(RVA(0x1024)))].iter().map(|&x| x).collect();

        assert!(exports.is_ok());
        assert_eq!(exports.unwrap(), expected);
    }
    else {
        panic!("couldn't get export directory");
    }
}

#[test]
fn test_dll_fw() {
    let dll_fw = PE::from_file("test/dllfw.dll");
    assert!(dll_fw.is_ok());

    let pefile = dll_fw.unwrap();

    let directory = pefile.resolve_data_directory(ImageDirectoryEntry::Export);
    assert!(directory.is_ok());

    if let DataDirectory::Export(export_table) = directory.unwrap() {
        let exports = export_table.get_export_map(&pefile);
        let expected: HashMap<&str, ThunkData> = [("ExitProcess", ThunkData::ForwarderString(RVA(0x1060)))].iter().map(|&x| x).collect();

        assert!(exports.is_ok());

        let export_map = exports.unwrap();
        assert_eq!(export_map, expected);

        if let ThunkData::ForwarderString(forwarder_rva) = export_map["ExitProcess"] {
            let forwarder_offset = forwarder_rva.as_offset(&pefile);
            assert!(forwarder_offset.is_ok());

            let offset = forwarder_offset.unwrap();
            let string_data = pefile.buffer.get_cstring(offset, false, None);
            assert!(string_data.is_ok());
            assert_eq!(string_data.unwrap().as_str(), "msvcrt.printf");
        }
        else {
            panic!("couldn't get forwarder string");
        }
    }
    else {
        panic!("couldn't get export directory");
    }
}
