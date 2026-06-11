#include <algorithm>
#include <codecvt>
#include <locale>
#include <memory>
#include <string>
#include <vector>

#include <emscripten/bind.h>
#include <emscripten/val.h>

#include <LIEF/LIEF.hpp>

enum class ExecutableFormat { kELF, kMachO, kPE, kUnknown };

enum class InjectResult { kAlreadyExists, kError, kSuccess };

std::vector<uint8_t> vec_from_val(const emscripten::val& value) {
  // We are using `convertJSArrayToNumberVector()` instead of `vecFromJSArray()`
  // because it is faster. It is okay if we use it without additional type
  // checking because this function is only called on Node.js Buffer instances
  // which is expected to contain elements that are safe to pass to the JS
  // function, `Number()`.
  return emscripten::convertJSArrayToNumberVector<uint8_t>(value);
}

static emscripten::val to_uint8array(const std::vector<uint8_t>& output) {
  emscripten::val view{
      emscripten::typed_memory_view(output.size(), output.data())};
  auto output_data = emscripten::val::global("Uint8Array").new_(output.size());
  output_data.call<void>("set", view);
  return output_data;
}

ExecutableFormat get_executable_format(const emscripten::val& executable) {
  std::vector<uint8_t> buffer = vec_from_val(executable);

  if (LIEF::ELF::is_elf(buffer)) {
    return ExecutableFormat::kELF;
  } else if (LIEF::MachO::is_macho(buffer)) {
    return ExecutableFormat::kMachO;
  } else if (LIEF::PE::is_pe(buffer)) {
    return ExecutableFormat::kPE;
  }

  return ExecutableFormat::kUnknown;
}

emscripten::val inject_into_elf(const emscripten::val& executable,
                                const std::string& note_name,
                                const emscripten::val& data,
                                bool overwrite = false) {
  emscripten::val object = emscripten::val::object();
  object.set("data", emscripten::val::undefined());

  std::unique_ptr<LIEF::ELF::Binary> binary =
      LIEF::ELF::Parser::parse(vec_from_val(executable));

  if (!binary) {
    object.set("result", emscripten::val(InjectResult::kError));
    return object;
  }

  // LIEF can return a length longer than it actually is, so use compare here.
  LIEF::ELF::Note* existing_note = nullptr;

  for (LIEF::ELF::Note& note : binary->notes()) {
    if (note.name().compare(0, note_name.size(), note_name) == 0) {
      existing_note = &note;
    }
  }

  if (existing_note) {
    if (!overwrite) {
      object.set("result", emscripten::val(InjectResult::kAlreadyExists));
      return object;
    } else {
      binary->remove(*existing_note);
    }
  }

  constexpr uint32_t kNoteType = 0;
  std::unique_ptr<LIEF::ELF::Note> note = LIEF::ELF::Note::create(
      note_name, kNoteType, vec_from_val(data), note_name);

  if (!note) {
    object.set("result", emscripten::val(InjectResult::kError));
    return object;
  }

  binary->add(*note);

  LIEF::ELF::Builder::config_t cfg;
  cfg.notes = true;
  cfg.dynamic_section = true;
  LIEF::ELF::Builder builder(*binary, cfg);
  builder.build();

  const std::vector<uint8_t>& output = builder.get_build();
  if (output.empty()) {
    object.set("result", emscripten::val(InjectResult::kError));
    return object;
  }

  object.set("data", to_uint8array(output));
  object.set("result", emscripten::val(InjectResult::kSuccess));
  return object;
}

emscripten::val inject_into_macho(const emscripten::val& executable,
                                  const std::string& segment_name,
                                  const std::string& section_name,
                                  const emscripten::val& data,
                                  bool overwrite = false) {
  emscripten::val object = emscripten::val::object();
  object.set("data", emscripten::val::undefined());

  std::unique_ptr<LIEF::MachO::FatBinary> fat_binary =
      LIEF::MachO::Parser::parse(vec_from_val(executable));

  if (!fat_binary) {
    object.set("result", emscripten::val(InjectResult::kError));
    return object;
  }

  std::vector<uint8_t> payload = vec_from_val(data);

  // Inject into all Mach-O binaries if there's more than one in a fat binary
  for (LIEF::MachO::Binary& binary : *fat_binary) {
    LIEF::MachO::SegmentCommand* segment = binary.get_segment(segment_name);

    if (!segment) {
      // Create the segment and mark it read-only
      LIEF::MachO::SegmentCommand new_segment(segment_name);
      new_segment.max_protection(static_cast<uint32_t>(
          LIEF::MachO::SegmentCommand::VM_PROTECTIONS::READ));
      new_segment.init_protection(static_cast<uint32_t>(
          LIEF::MachO::SegmentCommand::VM_PROTECTIONS::READ));
      LIEF::MachO::Section section(section_name, payload);
      new_segment.add_section(section);
      binary.add(new_segment);
    } else {
      LIEF::MachO::Section* existing_section =
          segment->get_section(section_name);
      if (existing_section) {
        if (!overwrite) {
          object.set("result", emscripten::val(InjectResult::kAlreadyExists));
          return object;
        }
        binary.remove_section(segment_name, section_name, true);
        segment = binary.get_segment(segment_name);
      }
      LIEF::MachO::Section section(section_name, payload);
      binary.add_section(*segment, section);
    }

    // It will need to be signed again anyway, so remove the signature
    if (binary.has_code_signature()) {
      binary.remove_signature();
    }
  }

  // Construct a new Uint8Array in JS
  std::vector<uint8_t> output = fat_binary->raw();
  object.set("data", to_uint8array(output));
  object.set("result", emscripten::val(InjectResult::kSuccess));

  return object;
}

emscripten::val inject_into_pe(const emscripten::val& executable,
                               const std::string& resource_name,
                               const emscripten::val& data,
                               bool overwrite = false) {
  emscripten::val object = emscripten::val::object();
  object.set("data", emscripten::val::undefined());

  std::unique_ptr<LIEF::PE::Binary> binary =
      LIEF::PE::Parser::parse(vec_from_val(executable));

  if (!binary) {
    object.set("result", emscripten::val(InjectResult::kError));
    return object;
  }

  // TODO - lief.PE.ResourcesManager doesn't support RCDATA it seems, add
  // support so this is simpler?

  if (!binary->has_resources()) {
    // TODO - Handle this edge case by creating the resource tree
    object.set("result", emscripten::val(InjectResult::kError));
    return object;
  }

  LIEF::PE::ResourceNode* resources = binary->resources();

  LIEF::PE::ResourceNode* rcdata_node = nullptr;
  LIEF::PE::ResourceNode* id_node = nullptr;

  // First level => Type (ResourceDirectory node)
  constexpr uint32_t kRcdataId =
      static_cast<uint32_t>(LIEF::PE::ResourcesManager::TYPE::RCDATA);
  auto rcdata_node_iter = std::find_if(std::begin(resources->childs()),
                                       std::end(resources->childs()),
                                       [](const LIEF::PE::ResourceNode& node) {
                                         return node.id() == kRcdataId;
                                       });

  if (rcdata_node_iter != std::end(resources->childs())) {
    rcdata_node = &*rcdata_node_iter;
  } else {
    LIEF::PE::ResourceDirectory new_rcdata_node;
    new_rcdata_node.id(kRcdataId);
    rcdata_node = &resources->add_child(new_rcdata_node);
  }

  // Second level => ID (ResourceDirectory node).
  std::u16string resource_name_u16(resource_name.begin(), resource_name.end());
  auto id_node_iter = std::find_if(
      std::begin(rcdata_node->childs()), std::end(rcdata_node->childs()),
      [&resource_name_u16](const LIEF::PE::ResourceNode& node) {
        return node.name() == resource_name_u16;
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
      object.set("result", emscripten::val(InjectResult::kAlreadyExists));
      return object;
    }

    id_node->delete_child(*id_node->childs());
  }

  LIEF::PE::ResourceData lang_node(vec_from_val(data));
  id_node->add_child(lang_node);

  // Rebuild only the resources, keeping the section named .rsrc.
  LIEF::PE::Builder::config_t cfg;
  cfg.resources = true;
  cfg.rsrc_section = ".rsrc";
  LIEF::PE::Builder builder(*binary, cfg);
  if (!builder.build()) {
    object.set("result", emscripten::val(InjectResult::kError));
    return object;
  }

  const std::vector<uint8_t>& output = builder.get_build();
  object.set("data", to_uint8array(output));
  object.set("result", emscripten::val(InjectResult::kSuccess));

  return object;
}

EMSCRIPTEN_BINDINGS(postject) {
  emscripten::enum_<ExecutableFormat>("ExecutableFormat")
      .value("kELF", ExecutableFormat::kELF)
      .value("kMachO", ExecutableFormat::kMachO)
      .value("kPE", ExecutableFormat::kPE)
      .value("kUnknown", ExecutableFormat::kUnknown);
  emscripten::enum_<InjectResult>("InjectResult")
      .value("kAlreadyExists", InjectResult::kAlreadyExists)
      .value("kError", InjectResult::kError)
      .value("kSuccess", InjectResult::kSuccess);
  emscripten::function("getExecutableFormat", &get_executable_format);
  emscripten::function("injectIntoELF", &inject_into_elf);
  emscripten::function("injectIntoMachO", &inject_into_macho);
  emscripten::function("injectIntoPE", &inject_into_pe);
}
