use super::*;
use super::types::*;
use super::buffer::*;

#[test]
fn test_compiled() {
    let compiled = PE::from_file("test/compiled.exe");
    assert_eq!(compiled.is_ok(), true);

    let pefile = compiled.unwrap();

    let arch = pefile.get_arch();
    assert_eq!(arch.is_ok(), true);
    assert_eq!(arch.unwrap(), Arch::X86);

    let bad_header = pefile.get_valid_nt_headers_64();
    assert_eq!(bad_header.is_err(), true);

    let get_headers = pefile.get_valid_nt_headers_32();
    assert_eq!(get_headers.is_ok(), true);

    let headers = get_headers.unwrap();
    
    let get_section_table = pefile.get_section_table();
    assert_eq!(get_section_table.is_ok(), true);

    let section_table = get_section_table.unwrap();
    assert_eq!(section_table.len(), headers.file_header.number_of_sections as usize);
    assert_eq!(section_table[0].name.as_os_str(), ".text");
    assert_eq!(section_table[1].name.as_os_str(), ".rdata");
    assert_eq!(section_table[2].name.as_os_str(), ".data");
}
