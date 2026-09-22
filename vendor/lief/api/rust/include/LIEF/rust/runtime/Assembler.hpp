/* Copyright 2022 - 2026 R. Thomas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

#include <cassert>
#include <cstdint>
#include <memory>
#include <string>

#include "LIEF/runtime/assembler.hpp"
#include "LIEF/rust/asm/AssemblerConfig.hpp"
#include "LIEF/rust/helpers.hpp"

inline auto runtime_assemble(uint64_t address, const std::string& Asm) {
  return make_unique_vector<uint8_t>(LIEF::runtime::assemble(address, Asm));
}

inline auto runtime_assemble_with_config(uint64_t address, const std::string& Asm,
                                         const AssemblerConfig_r& ffi_config) {
  std::unique_ptr<LIEF::assembly::AssemblerConfig> config = from_rust(ffi_config);
  assert(config != nullptr);
  return make_unique_vector<uint8_t>(LIEF::runtime::assemble(address, Asm,
                                                             *config));
}
