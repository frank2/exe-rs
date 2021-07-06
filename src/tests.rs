use super::*;
use super::types::*;
use super::buffer::*;

#[test]
fn test_compiled() {
    let compiled = PEFile::from_file("test/compiled.exe");

    assert_eq!(compiled.is_ok(), true);

    let pefile = compiled.unwrap();
    let arch = pefile.get_arch();
    
    assert_eq!(arch.is_ok(), true);
    assert_eq!(arch.unwrap(), Arch::X86);
}
