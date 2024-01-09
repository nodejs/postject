#include <emscripten/bind.h>
#include <emscripten/val.h>

#include "./postject.hpp"


std::vector<uint8_t> vec_from_val(const emscripten::val& value) {
  // We are using `convertJSArrayToNumberVector()` instead of `vecFromJSArray()`
  // because it is faster. It is okay if we use it without additional type
  // checking because this function is only called on Node.js Buffer instances
  // which is expected to contain elements that are safe to pass to the JS
  // function, `Number()`.
  return emscripten::convertJSArrayToNumberVector<uint8_t>(value);
}

postject::ExecutableFormat get_executable_format(const emscripten::val& executable) {
  return postject::get_executable_format(vec_from_val(executable));
}

emscripten::val inject_result_to_val(postject::InjectResult injectResult) {
  emscripten::val object = emscripten::val::object();
  object.set("type", emscripten::val(injectResult.type));
  if (injectResult.type == postject::InjectResultType::kSuccess) {
    std::vector<uint8_t> output = std::move(injectResult.output);
    emscripten::val view{
        emscripten::typed_memory_view(output.size(), output.data())};
    auto output_data = emscripten::val::global("Uint8Array").new_(output.size());
    output_data.call<void>("set", view);
    object.set("data", emscripten::val(output_data));
  } else {
    object.set("data", emscripten::val::undefined());
  }
  return object;

}

emscripten::val inject_into_elf(const emscripten::val& executable,
                                const std::string& note_name,
                                const emscripten::val& data,
                                bool overwrite) {
  return inject_result_to_val(postject::inject_into_elf(
      vec_from_val(executable),
      note_name,
      vec_from_val(data),
      overwrite
  ));
}

emscripten::val inject_into_macho(const emscripten::val& executable,
                                  const std::string& segment_name,
                                  const std::string& section_name,
                                  const emscripten::val& data,
                                  bool overwrite) {
  return inject_result_to_val(postject::inject_into_macho(
      vec_from_val(executable),
      segment_name,
      section_name,
      vec_from_val(data),
      overwrite
  ));
}

emscripten::val inject_into_pe(const emscripten::val& executable,
                               const std::string& resource_name,
                               const emscripten::val& data,
                               bool overwrite) {
  return inject_result_to_val(postject::inject_into_pe(
      vec_from_val(executable),
      resource_name,
      vec_from_val(data),
      overwrite
  ));
}

EMSCRIPTEN_BINDINGS(postject) {
  emscripten::enum_<postject::ExecutableFormat>("ExecutableFormat")
      .value("kELF", postject::ExecutableFormat::kELF)
      .value("kMachO", postject::ExecutableFormat::kMachO)
      .value("kPE", postject::ExecutableFormat::kPE)
      .value("kUnknown", postject::ExecutableFormat::kUnknown);
  emscripten::enum_<postject::InjectResultType>("InjectResultType")
      .value("kAlreadyExists", postject::InjectResultType::kAlreadyExists)
      .value("kError", postject::InjectResultType::kError)
      .value("kSuccess", postject::InjectResultType::kSuccess);
  emscripten::function("getExecutableFormat", &get_executable_format);
  emscripten::function("injectIntoELF", &inject_into_elf);
  emscripten::function("injectIntoMachO", &inject_into_macho);
  emscripten::function("injectIntoPE", &inject_into_pe);
}
