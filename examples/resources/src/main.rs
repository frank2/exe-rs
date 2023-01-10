use exe::*;

fn main() {
    let pe = VecPE::from_disk_file("../../test/cff_explorer.exe").unwrap();
    let rsrc = ResourceDirectory::parse(&pe).unwrap();
    let icons = rsrc.icon_groups(&pe).unwrap();

    for (id, dir) in &icons {
        let filename = match id {
            ResolvedDirectoryID::ID(val) => format!("{}.ico", val),
            ResolvedDirectoryID::Name(name) => format!("{}.ico", name),
        };

        println!("Writing {}", filename);

        let icon_file = dir.to_icon_buffer(&pe).unwrap();
        icon_file.save(filename).unwrap();
    }

    println!("Icons dumped from executable");
}
