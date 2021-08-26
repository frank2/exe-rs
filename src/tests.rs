use hex;

use std::collections::HashMap;

#[cfg(windows)] use winapi::um::libloaderapi::GetModuleHandleA;

use super::*;

#[test]
fn test_compiled() {
    let pefile = PEImage::from_disk_file("test/compiled.exe").unwrap();

    assert_eq!(pefile.len(), pefile.pe.calculate_disk_size().unwrap());

    let md5 = pefile.pe.buffer.md5();
    assert_eq!(md5, hex::decode("4240afeb03e0fc11b72fdba7ff30dc4f").unwrap());

    let sha1 = pefile.pe.buffer.sha1();
    assert_eq!(sha1, hex::decode("be63a89313a2d7dbf524aa4333f896a287f41a20").unwrap());

    let sha256 = pefile.pe.buffer.sha256();
    assert_eq!(sha256, hex::decode("56202fe96d3493d03e77210d751f8e2a16ee7ee962b0ec1f6f830cce6c894540").unwrap());

    let dos_magic = &pefile[0..2];
    assert_eq!(dos_magic, &[0x4d, 0x5a]);

    let dos_magic_buffer = &pefile.pe.buffer[0..2];
    assert_eq!(dos_magic_buffer, &[0x4d, 0x5a]);

    let dos_stub = pefile.pe.get_dos_stub();
    assert!(dos_stub.is_ok());
    assert_eq!(dos_stub.unwrap(), hex::decode("0E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A24000000000000005D5C6DC1193D0392193D0392193D0392972210921E3D0392E51D1192183D039252696368193D03920000000000000000").unwrap());
    
    let arch = pefile.pe.get_arch();
    assert!(arch.is_ok());
    assert_eq!(arch.unwrap(), Arch::X86);

    let bad_header = pefile.pe.get_valid_nt_headers_64();
    assert!(bad_header.is_err());

    let mz_check = Offset(0).as_ptr(&pefile.pe);
    assert!(mz_check.is_ok());
    assert_eq!(unsafe { *(mz_check.unwrap() as *const u16) }, DOS_SIGNATURE);

    let e_lfanew_check = pefile.pe.e_lfanew();
    assert!(e_lfanew_check.is_ok());

    let e_lfanew = e_lfanew_check.unwrap();

    let search = pefile.pe.buffer.search_ref(&NT_SIGNATURE);
    assert!(search.is_ok());
    assert_eq!(search.unwrap(), vec![e_lfanew]);

    let get_headers = pefile.pe.get_valid_nt_headers_32();
    assert!(get_headers.is_ok());

    let headers = get_headers.unwrap();
    
    let get_section_table = pefile.pe.get_section_table();
    assert!(get_section_table.is_ok());

    let section_table = get_section_table.unwrap();
    assert_eq!(section_table.len(), headers.file_header.number_of_sections as usize);
    assert_eq!(section_table[0].name.as_str(), ".text");
    assert_eq!(section_table[1].name.as_str(), ".rdata");
    assert_eq!(section_table[2].name.as_str(), ".data");

    let data_directory_offset = pefile.pe.get_data_directory_offset();
    assert!(data_directory_offset.is_ok());
    assert_eq!(data_directory_offset.unwrap(), Offset(0x128));

    assert!(pefile.pe.has_data_directory(ImageDirectoryEntry::Import));
    assert!(!pefile.pe.has_data_directory(ImageDirectoryEntry::Export));
    
    let import_directory_result = ImportDirectory::parse(&pefile.pe);
    assert!(import_directory_result.is_ok());

    let import_directory = import_directory_result.unwrap();
    assert_eq!(import_directory.descriptors.len(), 2);
    assert_eq!(import_directory.descriptors[0].original_first_thunk, RVA(0x2040));
    assert_eq!(import_directory.descriptors[0].name, RVA(0x20A0));
    assert_eq!(import_directory.descriptors[0].first_thunk, RVA(0x2080));

    let name_0 = import_directory.descriptors[0].get_name(&pefile.pe);
    assert!(name_0.is_ok());
    assert_eq!(name_0.unwrap().as_str(), "kernel32.dll");

    let kernel32_thunks_result = import_directory.descriptors[0].get_original_first_thunk(&pefile.pe);
    assert!(kernel32_thunks_result.is_ok());

    let kernel32_thunks = kernel32_thunks_result.unwrap();
    if let Thunk::Thunk32(kernel32_thunk) = kernel32_thunks[0] {
        assert_eq!(*kernel32_thunk, Thunk32(0x2060));
    }
    else {
        panic!("bad thunk");
    }
        
    let kernel32_imports = import_directory.descriptors[0].get_imports(&pefile.pe);
    let kernel32_expected = vec![ImportData::ImportByName("ExitProcess")];
    assert!(kernel32_imports.is_ok());
    assert_eq!(kernel32_imports.unwrap(), kernel32_expected);

    let name_1 = import_directory.descriptors[1].get_name(&pefile.pe);
    assert!(name_1.is_ok());
    assert_eq!(name_1.unwrap().as_str(), "msvcrt.dll");

    let msvcrt_imports = import_directory.descriptors[1].get_imports(&pefile.pe);
    let msvcrt_expected = vec![ImportData::ImportByName("printf")];
    assert!(msvcrt_imports.is_ok());
    assert_eq!(msvcrt_imports.unwrap(), msvcrt_expected);

    let known_mem_image = std::fs::read("test/compiled_dumped.bin").unwrap();
    let recreated_image = pefile.pe.recreate_image(PEType::Memory);
    assert!(recreated_image.is_ok());
    
    // due to the IAT, the images are not equal by a few bytes, so we instead
    // compare the length of the two images, which should be equal if it properly
    // recreated the image.
    assert_eq!(known_mem_image.len(), recreated_image.unwrap().len());
}

#[test]
fn test_compiled_dumped() {
    let pefile = PEImage::from_memory_file("test/compiled_dumped.bin").unwrap();

    assert_eq!(pefile.len(), pefile.pe.calculate_memory_size().unwrap());

    let dos_stub = pefile.pe.get_dos_stub();
    assert!(dos_stub.is_ok());
    assert_eq!(dos_stub.unwrap(), hex::decode("0E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A24000000000000005D5C6DC1193D0392193D0392193D0392972210921E3D0392E51D1192183D039252696368193D03920000000000000000").unwrap());

    let arch = pefile.pe.get_arch();
    assert!(arch.is_ok());
    assert_eq!(arch.unwrap(), Arch::X86);

    let bad_header = pefile.pe.get_valid_nt_headers_64();
    assert!(bad_header.is_err());

    let get_headers = pefile.pe.get_valid_nt_headers_32();
    assert!(get_headers.is_ok());

    let headers = get_headers.unwrap();
    
    let get_section_table = pefile.pe.get_section_table();
    assert!(get_section_table.is_ok());

    let section_table = get_section_table.unwrap();
    assert_eq!(section_table.len(), headers.file_header.number_of_sections as usize);
    assert_eq!(section_table[0].name.as_str(), ".text");
    assert_eq!(section_table[1].name.as_str(), ".rdata");
    assert_eq!(section_table[2].name.as_str(), ".data");

    assert!(pefile.pe.has_data_directory(ImageDirectoryEntry::Import));
    assert!(!pefile.pe.has_data_directory(ImageDirectoryEntry::Export));

    let import_directory_result = ImportDirectory::parse(&pefile.pe);
    assert!(import_directory_result.is_ok());

    let import_directory = import_directory_result.unwrap();
    assert_eq!(import_directory.descriptors.len(), 2);
    assert_eq!(import_directory.descriptors[0].original_first_thunk, RVA(0x2040));
    assert_eq!(import_directory.descriptors[0].name, RVA(0x20A0));
    assert_eq!(import_directory.descriptors[0].first_thunk, RVA(0x2080));

    let name_0 = import_directory.descriptors[0].get_name(&pefile.pe);
    assert!(name_0.is_ok());
    assert_eq!(name_0.unwrap().as_str(), "kernel32.dll");

    let kernel32_thunks_result = import_directory.descriptors[0].get_original_first_thunk(&pefile.pe);
    assert!(kernel32_thunks_result.is_ok());

    let kernel32_thunks = kernel32_thunks_result.unwrap();
    if let Thunk::Thunk32(kernel32_thunk) = kernel32_thunks[0] {
        assert_eq!(*kernel32_thunk, Thunk32(0x2060));
    }
    else {
        panic!("bad thunk");
    }
        
    let kernel32_imports = import_directory.descriptors[0].get_imports(&pefile.pe);
    let kernel32_expected = vec![ImportData::ImportByName("ExitProcess")];
    assert!(kernel32_imports.is_ok());
    assert_eq!(kernel32_imports.unwrap(), kernel32_expected);

    let name_1 = import_directory.descriptors[1].get_name(&pefile.pe);
    assert!(name_1.is_ok());
    assert_eq!(name_1.unwrap().as_str(), "msvcrt.dll");

    let msvcrt_imports = import_directory.descriptors[1].get_imports(&pefile.pe);
    let msvcrt_expected = vec![ImportData::ImportByName("printf")];
    assert!(msvcrt_imports.is_ok());
    assert_eq!(msvcrt_imports.unwrap(), msvcrt_expected);

    let known_disk_image = std::fs::read("test/compiled.exe").unwrap();
    let recreated_image = pefile.pe.recreate_image(PEType::Disk);
    assert!(recreated_image.is_ok());
    assert_eq!(known_disk_image.len(), recreated_image.unwrap().len());
}

#[test]
fn test_dll() {
    let pefile = PEImage::from_disk_file("test/dll.dll").unwrap();

    assert!(pefile.pe.has_data_directory(ImageDirectoryEntry::Export));

    let directory = ExportDirectory::parse(&pefile.pe);
    assert!(directory.is_ok());

    let export_table = directory.unwrap();
    let name = export_table.get_name(&pefile.pe);
    assert!(name.is_ok());
    assert_eq!(name.unwrap().as_str(), "dll.dll");

    let exports = export_table.get_export_map(&pefile.pe);
    let expected: HashMap<&str, ThunkData> = [("export", ThunkData::Function(RVA(0x1024)))].iter().map(|&x| x).collect();

    assert!(exports.is_ok());
    assert_eq!(exports.unwrap(), expected);
    assert!(pefile.pe.has_data_directory(ImageDirectoryEntry::BaseReloc));

    let relocation_directory_result = RelocationDirectory::parse(&pefile.pe);
    assert!(relocation_directory_result.is_ok());

    let relocation_table = relocation_directory_result.unwrap();
    assert_eq!(relocation_table.entries.len(), 1);

    let relocation_data = relocation_table.relocations(&pefile.pe, 0x02000000);
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

#[test]
fn test_dll_fw() {
    let pefile = PEImage::from_disk_file("test/dllfw.dll").unwrap();

    assert!(pefile.pe.has_data_directory(ImageDirectoryEntry::Export));

    let directory = ExportDirectory::parse(&pefile.pe);
    assert!(directory.is_ok());

    let export_table = directory.unwrap();
    let exports = export_table.get_export_map(&pefile.pe);
    let expected: HashMap<&str, ThunkData> = [("ExitProcess", ThunkData::ForwarderString(RVA(0x1060)))].iter().map(|&x| x).collect();
    assert!(exports.is_ok());

    let export_map = exports.unwrap();
    assert_eq!(export_map, expected);

    if let ThunkData::ForwarderString(forwarder_rva) = export_map["ExitProcess"] {
        let forwarder_offset = forwarder_rva.as_offset(&pefile.pe);
        assert!(forwarder_offset.is_ok());

        let offset = forwarder_offset.unwrap();
        let string_data = pefile.pe.buffer.get_cstring(offset, false, None);
        assert!(string_data.is_ok());
        assert_eq!(string_data.unwrap().as_str(), "msvcrt.printf");
    }
    else {
        panic!("couldn't get forwarder string");
    }
}

#[test]
fn test_imports_nothunk() {
    let pefile = PEImage::from_disk_file("test/imports_nothunk.exe").unwrap();

    assert!(pefile.pe.has_data_directory(ImageDirectoryEntry::Import));

    let data_directory = ImportDirectory::parse(&pefile.pe);
    assert!(data_directory.is_ok());

    let import_table = data_directory.unwrap();
    assert_eq!(import_table.descriptors.len(), 3);

    let kernel32_imports = import_table.descriptors[0].get_imports(&pefile.pe);
    assert!(kernel32_imports.is_ok());
    assert_eq!(kernel32_imports.unwrap(), [ImportData::ImportByName("ExitProcess")]);

    let blank_imports = import_table.descriptors[1].get_imports(&pefile.pe);
    assert!(blank_imports.is_ok());
    assert!(blank_imports.unwrap().is_empty());

    let msvcrt_imports = import_table.descriptors[2].get_imports(&pefile.pe);
    assert!(msvcrt_imports.is_ok());
    assert_eq!(msvcrt_imports.unwrap(), [ImportData::ImportByName("printf")]);
}

#[test]
fn test_no_dd() {
    let pefile = PEImage::from_disk_file("test/no_dd.exe").unwrap();

    let data_directory = pefile.pe.get_data_directory_table();
    assert!(data_directory.is_ok());
    assert!(data_directory.unwrap().is_empty());
}

#[test]
fn test_hello_world() {
    let pefile = PEImage::from_disk_file("test/hello_world.exe").unwrap();

    let debug_directory_check = DebugDirectory::parse(&pefile.pe);
    assert!(debug_directory_check.is_ok());

    let debug_directory = debug_directory_check.unwrap();
    assert_eq!(ImageDebugType::from_u32(debug_directory.type_), ImageDebugType::CodeView);
}

#[test]
fn test_hello_world_packed() {
    let pefile = PEImage::from_disk_file("test/hello_world_packed.exe").unwrap();

    let entropy = pefile.pe.buffer.entropy();
    assert!(entropy > 7.0);
    assert!(pefile.pe.has_data_directory(ImageDirectoryEntry::Resource));

    let data_directory = ResourceDirectory::parse(&pefile.pe);
    assert!(data_directory.is_ok());

    let resource_table = data_directory.unwrap();
    assert_eq!(resource_table.resources.len(), 1);

    let rsrc = resource_table.resources[0];

    assert_eq!(rsrc.type_id, ResourceDirectoryID::ID(24));
    assert_eq!(rsrc.rsrc_id, ResourceDirectoryID::ID(1));
    assert_eq!(rsrc.lang_id, ResourceDirectoryID::ID(1033));
    assert_eq!(rsrc.data, ResourceOffset(0x48));
}

#[test]
fn test_hello_world_rust() {
    let pefile = PEImage::from_disk_file("test/hello_world_rust.exe").unwrap();

    let tls_directory_check = TLSDirectory::parse(&pefile.pe);
    assert!(tls_directory_check.is_ok());

    if let TLSDirectory::TLS64(tls_directory) = tls_directory_check.unwrap() {
        let raw_data = tls_directory.read(&pefile.pe);
        assert!(raw_data.is_ok());
        assert_eq!(raw_data.unwrap(), vec![0u8; tls_directory.get_raw_data_size()].as_slice());

        let callbacks = tls_directory.get_callbacks(&pefile.pe);
        assert!(callbacks.is_ok());
        assert_eq!(callbacks.unwrap(), &[VA64(0x14000cf00)]);
    }
    else {
        panic!("couldn't get TLS directory");
    }
}

#[test]
fn test_cff_explorer() {
    let pefile = PEImage::from_disk_file("test/cff_explorer.exe").unwrap();

    let checksum = pefile.pe.validate_checksum();
    assert!(checksum.is_ok());
    assert!(checksum.unwrap());

    let imphash = pefile.pe.calculate_imphash();
    assert!(imphash.is_ok());
    assert_eq!(imphash.unwrap(), hex::decode("29307ef77ea94259e99f987498998a8f").unwrap());

    assert!(pefile.pe.has_data_directory(ImageDirectoryEntry::Resource));

    let data_directory = ResourceDirectory::parse(&pefile.pe);
    assert!(data_directory.is_ok());

    let resource_table = data_directory.unwrap();
    let cursors = resource_table.filter_by_type(ResourceID::Cursor);
    assert_eq!(cursors.len(), 17);

    let bitmaps = resource_table.filter_by_type(ResourceID::Bitmap);
    assert_eq!(bitmaps.len(), 30);

    let icons = resource_table.filter_by_type(ResourceID::Icon);
    assert_eq!(icons.len(), 43);

    let fonts = resource_table.filter_by_type(ResourceID::Font);
    assert_eq!(fonts.len(), 0);
}

#[test]
fn test_creation() {
    let mut created_file = PEImage::new_disk(0x4000);

    let dos_result = created_file.write_ref(Offset(0), &ImageDOSHeader::default());
    assert!(dos_result.is_ok());

    let e_lfanew = created_file.pe.e_lfanew();
    assert!(e_lfanew.is_ok());
    assert_eq!(e_lfanew.unwrap(), Offset(0xE0));

    let nt_result = created_file.write_ref(created_file.pe.e_lfanew().unwrap(), &ImageNTHeaders64::default());
    assert!(nt_result.is_ok());

    let nt_headers_mut = created_file.pe.get_valid_mut_nt_headers();
    assert!(nt_headers_mut.is_ok());

    if let NTHeadersMut::NTHeaders64(nt_headers_64) = nt_headers_mut.unwrap() {
        assert_eq!(nt_headers_64.file_header.number_of_sections, 0);
        nt_headers_64.optional_header.size_of_image = 0x4000;
    }
    else {
        panic!("couldn't get mutable NT headers");
    }

    let mut new_section = ImageSectionHeader::default();
    
    new_section.set_name(Some(".text"));
    assert_eq!(new_section.name.as_str(), ".text");

    let created_section_check = created_file.pe.append_section(&new_section);
    assert!(created_section_check.is_ok());

    let created_section = created_section_check.unwrap();
    assert_eq!(created_section.pointer_to_raw_data, Offset(0x400));
    assert_eq!(created_section.virtual_address, RVA(0x1000));

    let data: &[u8] = &[0x48, 0x31, 0xC0, 0xC3]; // xor rax,rax / ret
    
    created_section.virtual_size = 0x1000;
    created_section.size_of_raw_data = data.len() as u32;
    created_section.characteristics = SectionCharacteristics::MEM_EXECUTE
        | SectionCharacteristics::MEM_READ
        | SectionCharacteristics::CNT_CODE;

    // clone the section to stop mutable borrowing of created_file
    let cloned_section = created_section.clone();
    assert!(cloned_section.is_aligned_to_file(&created_file.pe));
    assert!(cloned_section.is_aligned_to_section(&created_file.pe));
    
    let nt_headers = created_file.pe.get_valid_nt_headers();
    assert!(nt_headers.is_ok());

    if let NTHeaders::NTHeaders64(nt_headers_64) = nt_headers.unwrap() {
        assert_eq!(nt_headers_64.file_header.number_of_sections, 1);
    }
    else {
        panic!("couldn't get NT headers");
    }

    let section_table = created_file.pe.get_section_table();
    assert!(section_table.is_ok());
    assert_eq!(section_table.unwrap()[0], cloned_section);

    let section_offset = cloned_section.data_offset(created_file.pe.pe_type);
    assert_eq!(section_offset, Offset(0x400));

    let write_result = cloned_section.write(&mut created_file.pe, data);
    assert!(write_result.is_ok());

    let read_result = cloned_section.read(&created_file.pe);
    assert!(read_result.is_ok());
    assert_eq!(read_result.unwrap(), data);

    let alt_read_result = created_file.read(section_offset, data.len());
    assert!(alt_read_result.is_ok());
    assert_eq!(alt_read_result.unwrap(), data);
}

#[cfg(windows)]
#[test]
fn test_pointer() {
    let hmodule = unsafe { GetModuleHandleA(std::ptr::null()) };
    let memory_module = unsafe { PE::from_ptr(hmodule as *const u8) };
    assert!(memory_module.is_ok());
}

#[test]
fn test_add_relocation() {
    let pefile_ro = PEImage::from_disk_file("test/dll.dll").unwrap();
    let mut pefile = pefile_ro.clone();

    let mut relocation_directory = RelocationDirectory::parse(&pefile_ro.pe).unwrap();
    let add_result = relocation_directory.add_relocation(&mut pefile.pe, RVA(0x11C0));
    assert!(add_result.is_ok());

    let reparsed = RelocationDirectory::parse(&pefile.pe).unwrap();
    let relocations = reparsed.relocations(&pefile.pe, 0x02000000).unwrap();
    assert_eq!(relocations[relocations.len()-1], (RVA(0x11C0), RelocationValue::Relocation32(0x01000000)));
}
