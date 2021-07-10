use std::collections::HashMap;

use super::*;
use super::types::*;
use super::buffer::*;

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
        assert_eq!(exports.unwrap(), expected);
    }
    else {
        panic!("couldn't get export directory");
    }
}
