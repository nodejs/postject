#include <memory>
#include <vector>

#include <emscripten/bind.h>
#include <emscripten/val.h>

#include <LIEF/LIEF.hpp>

enum class ExecutableFormat { kELF, kMachO, kPE, kUnknown };

enum class InjectResult { kAlreadyExists, kError, kSuccess };

std::vector<uint8_t> vec_from_val(const emscripten::val& value) {
  // NOTE - vecFromJSArray incurs a copy, so memory usage is higher than it
  //        needs to be. Explore ways to access the memory directly and avoid
  //        the copy.
  return emscripten::vecFromJSArray<uint8_t>(value);
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

  LIEF::ELF::Note* existing_note = nullptr;

  for (LIEF::ELF::Note& note : binary->notes()) {
    if (note.name() == note_name) {
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

  LIEF::ELF::Note note;
  note.name(note_name);
  note.description(vec_from_val(data));
  binary->add(note);

  // Construct a new Uint8Array in JS
  std::vector<uint8_t> output = binary->raw();
  emscripten::val view{
      emscripten::typed_memory_view(output.size(), output.data())};
  auto output_data = emscripten::val::global("Uint8Array").new_(output.size());
  output_data.call<void>("set", view);

  object.set("data", output_data);
  object.set("result", emscripten::val(InjectResult::kSuccess));

  return object;
}

// TODO - There's a bug in here, resulting output segfaults
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

  // Inject into all Mach-O binaries if there's more than one in a fat binary
  for (LIEF::MachO::Binary& app : *fat_binary) {
    LIEF::MachO::Section* existing_section =
        app.get_section(segment_name, section_name);

    if (existing_section) {
      if (!overwrite) {
        object.set("result", emscripten::val(InjectResult::kAlreadyExists));
        return object;
      }

      app.remove_section(segment_name, section_name, true);
    }

    LIEF::MachO::SegmentCommand* segment = app.get_segment(segment_name);
    LIEF::MachO::Section section(section_name, vec_from_val(data));

    if (!segment) {
      // Create the segment and mark it read-only
      LIEF::MachO::SegmentCommand new_segment(segment_name);
      new_segment.max_protection(
          static_cast<uint32_t>(LIEF::MachO::VM_PROTECTIONS::VM_PROT_READ));
      new_segment.init_protection(
          static_cast<uint32_t>(LIEF::MachO::VM_PROTECTIONS::VM_PROT_READ));
      new_segment.add_section(section);
      app.add(new_segment);
    } else {
      app.add_section(*segment, section);
    }

    // It will need to be signed again anyway, so remove the signature
    app.remove_signature();
  }

  // Construct a new Uint8Array in JS
  std::vector<uint8_t> output = fat_binary->raw();
  emscripten::val view{
      emscripten::typed_memory_view(output.size(), output.data())};
  auto output_data = emscripten::val::global("Uint8Array").new_(output.size());
  output_data.call<void>("set", view);

  object.set("data", output_data);
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

  // TODO

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
