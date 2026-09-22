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

#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/runtime/windows/LdrDataTableEntry.hpp"

#include "LIEF/runtime/windows/PEB.hpp"

class runtime_windows_PEB : public Mirror<LIEF::runtime::windows::PEB> {
  public:
  using lief_t = LIEF::runtime::windows::PEB;
  using Mirror::Mirror;

  auto being_debugged() const {
    return get().being_debugged();
  }

  auto ldr() const {
    return (uint64_t)get().ldr();
  }

  auto process_parameters() const {
    return (uint64_t)get().process_parameters();
  }

  auto atl_thunk_slist_ptr() const {
    return (uint64_t)get().atl_thunk_slist_ptr();
  }

  auto atl_thunk_slist_ptr32() const {
    return get().atl_thunk_slist_ptr32();
  }

  auto post_process_init_routine() const {
    return (uint64_t)get().post_process_init_routine();
  }

  auto session_id() const {
    return get().session_id();
  }

  auto entries() const {
    return std::make_unique<runtime_windows_it_ldr_data_table_entry>(
        get().entries()
    );
  }
};
