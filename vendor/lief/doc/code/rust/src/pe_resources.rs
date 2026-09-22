use lief::pe::resources::{Node, NodeBase};

pub fn access_root(some_pe: &lief::pe::Binary) {
    // lief-doc: access-root-start
    let pe: &lief::pe::Binary = some_pe;

    let rsrc = pe.resources().unwrap();

    println!("{}", &rsrc as &dyn NodeBase);
    // lief-doc: access-root-end
}

pub fn add_child(some_pe: &mut lief::pe::Binary) {
    // lief-doc: add-child-start
    let pe: &mut lief::pe::Binary = some_pe;

    let mut root = pe.resources().unwrap();

    let mut dir_node = lief::pe::resources::Directory::with_id(100);
    let data_node = lief::pe::resources::Data::with_buffer(&[1, 2, 3]);

    dir_node.add_child(&Node::Data(data_node));
    root.add_child(&Node::Directory(dir_node));

    pe.write("new.exe");
    // lief-doc: add-child-end
}

pub fn set_manifest(some_pe: &mut lief::pe::Binary) {
    // lief-doc: manifest-start
    let pe: &mut lief::pe::Binary = some_pe;

    let mut manager = pe.resources_manager().unwrap();

    manager.set_manifest(
        r#"
    <?xml version="1.0" standalone="yes"?>
    <assembly xmlns="urn:schemas-microsoft-com:asm.v1"
              manifestVersion="1.0">
      <trustInfo>
        <security>
          <requestedPrivileges>
             <requestedExecutionLevel level='asInvoker' uiAccess='false'/>
          </requestedPrivileges>
        </security>
      </trustInfo>
    </assembly>
    "#,
    );

    pe.write("new.exe");
    // lief-doc: manifest-end
}

pub fn transfer_resources(from_pe: &lief::pe::Binary, to_pe: &mut lief::pe::Binary) {
    // lief-doc: transfer-start
    to_pe.set_resources(&from_pe.resources().unwrap());
    // lief-doc: transfer-end
}
