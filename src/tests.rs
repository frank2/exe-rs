use std::collections::HashMap;

use super::*;
use super::headers::*;
use super::types::*;

#[test]
fn test_compiled() {
    let compiled = PE::from_file("test/compiled.exe");
    assert!(compiled.is_ok());

    let pefile = compiled.unwrap();

    let md5 = pefile.buffer.md5();
    assert_eq!(md5, vec![0x42,0x40,0xAF,0xEB,0x03,0xE0,0xFC,0x11,0xB7,0x2F,0xDB,0xA7,0xFF,0x30,0xDC,0x4F]);

    let sha1 = pefile.buffer.sha1();
    assert_eq!(sha1, vec![0xBE,0x63,0xA8,0x93,0x13,0xA2,0xD7,0xDB,0xF5,0x24,0xAA,0x43,0x33,0xF8,0x96,0xA2,0x87,0xF4,0x1A,0x20]);

    let sha256 = pefile.buffer.sha256();
    assert_eq!(sha256, vec![0x56,0x20,0x2f,0xe9,0x6d,0x34,0x93,0xd0,0x3e,0x77,0x21,0x0d,0x75,0x1f,0x8e,0x2a,
                            0x16,0xee,0x7e,0xe9,0x62,0xb0,0xec,0x1f,0x6f,0x83,0x0c,0xce,0x6c,0x89,0x45,0x40]);

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

    let data_directory_offset = pefile.get_data_directory_offset();
    assert!(data_directory_offset.is_ok());
    assert_eq!(data_directory_offset.unwrap(), Offset(0x128));

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
fn test_compiled_dumped() {
    let compiled = PE::from_memory_dump("test/compiled_dumped.bin");
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

    let relocation_directory = pefile.resolve_data_directory(ImageDirectoryEntry::BaseReloc);
    assert!(relocation_directory.is_ok());

    if let DataDirectory::BaseReloc(relocation_table) = relocation_directory.unwrap() {
        assert_eq!(relocation_table.len(), 1);

        let relocation_data = relocation_table.relocations(&pefile, 0x02000000);
        let expected: Vec<(RVA, RelocationValue)> = [
            (RVA(0x1008), RelocationValue::Relocation32(0x02001059)),
            (RVA(0x100F), RelocationValue::Relocation32(0x02001034)),
            (RVA(0x1017), RelocationValue::Relocation32(0x020010D0)),
            (RVA(0x1025), RelocationValue::Relocation32(0x0200107E)),
            (RVA(0x102B), RelocationValue::Relocation32(0x020010D0)),
        ].iter().cloned().collect();
             
        assert!(relocation_data.is_ok());
        assert_eq!(relocation_data.unwrap(), expected);
    }
    else {
        panic!("couldn't get relocation directory");
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

#[test]
fn test_imports_nothunk() {
    let imports_nothunk = PE::from_file("test/imports_nothunk.exe");
    assert!(imports_nothunk.is_ok());

    let pefile = imports_nothunk.unwrap();
    let data_directory = pefile.resolve_data_directory(ImageDirectoryEntry::Import);
    assert!(data_directory.is_ok());

    if let DataDirectory::Import(import_table) = data_directory.unwrap() {
        assert_eq!(import_table.len(), 3);

        let kernel32_imports = import_table[0].get_imports(&pefile);
        assert!(kernel32_imports.is_ok());
        assert_eq!(kernel32_imports.unwrap(), [String::from("ExitProcess")]);

        let blank_imports = import_table[1].get_imports(&pefile);
        assert!(blank_imports.is_ok());
        assert!(blank_imports.unwrap().is_empty());

        let msvcrt_imports = import_table[2].get_imports(&pefile);
        assert!(msvcrt_imports.is_ok());
        assert_eq!(msvcrt_imports.unwrap(), [String::from("printf")]);
    }
    else {
        panic!("couldn't get import table");
    }
}

#[test]
fn test_no_dd() {
    let no_dd = PE::from_file("test/no_dd.exe");
    assert!(no_dd.is_ok());

    let pefile = no_dd.unwrap();

    let data_directory = pefile.get_data_directory_table();
    assert!(data_directory.is_ok());
    assert!(data_directory.unwrap().is_empty());
}

#[test]
fn test_hello_world_packed() {
    let hello_world_packed = PE::from_file("test/hello_world_packed.exe");
    assert!(hello_world_packed.is_ok());

    let pefile = hello_world_packed.unwrap();

    let entropy = pefile.buffer.entropy();
    assert!(entropy > 7.0);
}
