#include <algorithm>
#include <codecvt>
#include <locale>
#include <memory>

#include <LIEF/LIEF.hpp>

#include "./postject.hpp"

postject::ExecutableFormat postject::get_executable_format(
    const std::vector<uint8_t>& executable) {
  if (LIEF::ELF::is_elf(executable)) {
    return ExecutableFormat::kELF;
  } else if (LIEF::MachO::is_macho(executable)) {
    return ExecutableFormat::kMachO;
  } else if (LIEF::PE::is_pe(executable)) {
    return ExecutableFormat::kPE;
  }

  return ExecutableFormat::kUnknown;
}

postject::InjectResult postject::inject_into_elf(
    const std::vector<uint8_t>& executable,
    const std::string& note_name,
    const std::vector<uint8_t>& data,
    bool overwrite) {
  InjectResult result;
  std::unique_ptr<LIEF::ELF::Binary> binary =
      LIEF::ELF::Parser::parse(executable);

  if (!binary) {
    result.type = InjectResultType::kError;
    return result;
  }

  LIEF::ELF::Note* existing_note = nullptr;

  for (LIEF::ELF::Note& note : binary->notes()) {
    if (note.name() == note_name) {
      existing_note = &note;
    }
  }

  if (existing_note) {
    if (!overwrite) {
      result.type = InjectResultType::kAlreadyExists;
      return result;
    } else {
      binary->remove(*existing_note);
    }
  }

  LIEF::ELF::Note note;
  note.name(note_name);
  note.description(data);
  binary->add(note);

  result.type = InjectResultType::kSuccess;
  result.output = binary->raw();
  return result;
}

postject::InjectResult postject::inject_into_macho(
    const std::vector<uint8_t>& executable,
    const std::string& segment_name,
    const std::string& section_name,
    const std::vector<uint8_t>& data,
    bool overwrite) {
  InjectResult result;
  std::unique_ptr<LIEF::MachO::FatBinary> fat_binary =
      LIEF::MachO::Parser::parse(executable);

  if (!fat_binary) {
    result.type = InjectResultType::kError;
    return result;
  }

  // Inject into all Mach-O binaries if there's more than one in a fat binary
  for (LIEF::MachO::Binary& binary : *fat_binary) {
    LIEF::MachO::Section* existing_section =
        binary.get_section(segment_name, section_name);

    if (existing_section) {
      if (!overwrite) {
        result.type = InjectResultType::kAlreadyExists;
        return result;
      }

      binary.remove_section(segment_name, section_name, true);
    }

    LIEF::MachO::SegmentCommand* segment = binary.get_segment(segment_name);
    LIEF::MachO::Section section(section_name, data);

    if (!segment) {
      // Create the segment and mark it read-only
      LIEF::MachO::SegmentCommand new_segment(segment_name);
      new_segment.max_protection(
          static_cast<uint32_t>(LIEF::MachO::VM_PROTECTIONS::VM_PROT_READ));
      new_segment.init_protection(
          static_cast<uint32_t>(LIEF::MachO::VM_PROTECTIONS::VM_PROT_READ));
      new_segment.add_section(section);
      binary.add(new_segment);
    } else {
      binary.add_section(*segment, section);
    }

    // It will need to be signed again anyway, so remove the signature
    if (binary.has_code_signature()) {
      binary.remove_signature();
    }
  }

  result.type = InjectResultType::kSuccess;
  result.output = fat_binary->raw();
  return result;
}

postject::InjectResult postject::inject_into_pe(
    const std::vector<uint8_t>& executable,
    const std::string& resource_name,
    const std::vector<uint8_t>& data,
    bool overwrite) {
  InjectResult result;

  std::unique_ptr<LIEF::PE::Binary> binary =
      LIEF::PE::Parser::parse(executable);

  if (!binary) {
    result.type = InjectResultType::kError;
    return result;
  }

  // TODO - lief.PE.ResourcesManager doesn't support RCDATA it seems, add
  // support so this is simpler?

  if (!binary->has_resources()) {
    // TODO - Handle this edge case by creating the resource tree
    result.type = InjectResultType::kError;
    return result;
  }

  LIEF::PE::ResourceNode* resources = binary->resources();

  LIEF::PE::ResourceNode* rcdata_node = nullptr;
  LIEF::PE::ResourceNode* id_node = nullptr;

  // First level => Type (ResourceDirectory node)
  auto rcdata_node_iter = std::find_if(
      std::begin(resources->childs()), std::end(resources->childs()),
      [](const LIEF::PE::ResourceNode& node) {
        return node.id() ==
               static_cast<uint32_t>(LIEF::PE::RESOURCE_TYPES::RCDATA);
      });

  if (rcdata_node_iter != std::end(resources->childs())) {
    rcdata_node = &*rcdata_node_iter;
  } else {
    LIEF::PE::ResourceDirectory new_rcdata_node;
    new_rcdata_node.id(static_cast<uint32_t>(LIEF::PE::RESOURCE_TYPES::RCDATA));
    rcdata_node = &resources->add_child(new_rcdata_node);
  }

  // Second level => ID (ResourceDirectory node)
  auto id_node_iter = std::find_if(
      std::begin(rcdata_node->childs()), std::end(rcdata_node->childs()),
      [resource_name](const LIEF::PE::ResourceNode& node) {
        return node.name() ==
               std::wstring_convert<std::codecvt_utf8_utf16<char16_t>,
                                    char16_t>{}
                   .from_bytes(resource_name);
      });

  if (id_node_iter != std::end(rcdata_node->childs())) {
    id_node = &*id_node_iter;
  } else {
    LIEF::PE::ResourceDirectory new_id_node;
    new_id_node.name(resource_name);
    // TODO - This isn't documented, but if this isn't set then LIEF won't save
    //        the name. Seems like LIEF should be able to automatically handle
    //        this if you've set the node's name
    new_id_node.id(0x80000000);
    id_node = &rcdata_node->add_child(new_id_node);
  }

  // Third level => Lang (ResourceData node)
  if (id_node->childs() != std::end(id_node->childs())) {
    if (!overwrite) {
      result.type = InjectResultType::kAlreadyExists;
      return result;
    }

    id_node->delete_child(*id_node->childs());
  }

  LIEF::PE::ResourceData lang_node;
  lang_node.content(data);
  id_node->add_child(lang_node);

  binary->remove_section(".rsrc", true);

  // Write out the binary, only modifying the resources
  LIEF::PE::Builder builder(*binary);
  builder.build_dos_stub(true);
  builder.build_imports(false);
  builder.build_overlay(false);
  builder.build_relocations(false);
  builder.build_resources(true);
  builder.build_tls(false);
  builder.build();

  // TODO - Why doesn't LIEF just replace the .rsrc section?
  //        Can we at least change build_resources to take a section name?

  // Re-parse the output so the .l2 section is available
  binary = LIEF::PE::Parser::parse(builder.get_build());

  // Rename the rebuilt resource section
  LIEF::PE::Section* section = binary->get_section(".l2");
  section->name(".rsrc");

  LIEF::PE::Builder builder2(*binary);
  builder2.build_dos_stub(true);
  builder2.build_imports(false);
  builder2.build_overlay(false);
  builder2.build_relocations(false);
  builder2.build_resources(false);
  builder2.build_tls(false);
  builder2.build();

  result.type = InjectResultType::kSuccess;
  result.output = builder2.get_build();
  return result;
}
