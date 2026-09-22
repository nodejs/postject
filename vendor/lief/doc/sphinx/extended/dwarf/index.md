---
description: Read DWARF functions, types, and variables, attach external debug files, generate declarations, and create new DWARF files with LIEF Extended.
---

(extended-dwarf)=

# {fa}`solid fa-bars-staggered` DWARF

```{eval-rst}
.. toctree::
  :caption: <i class="fa-solid fa-code">&nbsp;</i>API
  :maxdepth: 1

  cpp
  python
  rust
```

## Introduction

LIEF Extended can read DWARF functions, variables, types, and source locations,
generate C/C++ declarations, and create new debug files.

DWARF debug information can be embedded in a binary or stored in a separate file.
To inspect compiler-generated DWARF, build with debug information and preserve
it when stripping the binary. Debug files can also be generated from analysis
results with the {ref}`DWARF editor <extended-dwarf-editor>`. For an overview of
loading and associating debug files, see {ref}`debug-info`.

## Load and inspect DWARF

When DWARF debug information is embedded within the binary,
you can access it using the {sub-ref}`lief-dwarf-binary-debug-info` attribute.
This attribute returns a {sub-ref}`lief-dwarf-debug-info` object:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/dwarf.py", "embedded", prepend="import lief") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/dwarf.cpp", "embedded") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/dwarf.rs", "embedded") }}
:::
::::

Additionally, the {sub-ref}`lief-dwarf-load` function can be used to load a
DWARF file, whether it is embedded or standalone:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/dwarf.py", "load", prepend="import lief") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/dwarf.cpp", "load") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/dwarf.rs", "load") }}
:::
::::

For a macOS `.dSYM` bundle, pass the path to the DWARF object inside
`Contents/Resources/DWARF/`. Check the loader's return value before accessing
compilation units or searching for a function or type.

Once loaded, you can use the {sub-ref}`lief-dwarf-debug-info` API to interact with the
debug information:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/dwarf.py", "iterate") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/dwarf.cpp", "iterate") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/dwarf.rs", "iterate") }}
:::
::::

(extended-dwarf-load-ext)=

## Attach an external debug file

In the case of an external DWARF file, you can bind this debug file to
a {sub-ref}`lief-abstract-binary` using the {sub-ref}`lief-abstract-binary-load_debug_info`
function.

Here's an example:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/dwarf.py", "load-external") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/dwarf.cpp", "load-external") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/dwarf.rs", "load-external") }}
:::
::::

Use a debug file produced by the same build as the binary. Attaching it updates
LIEF's analysis object. It does not insert DWARF sections into the executable.
The {sub-ref}`lief-disassemble` function can then resolve functions defined by
that debug file while reading their machine code from the binary:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/dwarf.py", "disassemble") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/dwarf.cpp", "disassemble") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/dwarf.rs", "disassemble") }}
:::
::::

Additionally, you may also want to explore the
{ref}`BinaryNinja <plugins-binaryninja-dwarf>` and
{ref}`Ghidra <plugins-ghidra-dwarf>` DWARF export plugins, which generate
debug information based on the analysis performed by these frameworks.

(extended-dwarf-to-decl)=

## Generating C/C++ Definitions

DWARF functions, variables, types, and compilation units can be rendered as
C/C++ declarations using:

- {sub-ref}`lief-dwarf-function-to_decl`
- {sub-ref}`lief-dwarf-variable-to_decl`
- {sub-ref}`lief-dwarf-type-to_decl`
- {sub-ref}`lief-dwarf-cu-to_decl`

The generated output can be configured with a {sub-ref}`lief-declopt` structure (e.g. to
prefer C++ syntax or change the indentation):

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/dwarf.py", "to-decl") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/dwarf.cpp", "to-decl") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/dwarf.rs", "to-decl") }}
:::
::::

(extended-dwarf-editor)=

## DWARF Editor

:::{admonition} Editing Existing DWARF
:class: warning

LIEF does not currently support modifying an **existing** DWARF file.
:::

LIEF provides a comprehensive high-level API for programmatically creating
DWARF files. This works by using the {sub-ref}`lief-dwarf-editor` interface, which can be
instantiated using {sub-ref}`lief-dwarf-editor-from_binary`:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/dwarf.py", "editor-from-binary") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/dwarf.cpp", "editor-from-binary") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/dwarf.rs", "editor-from-binary") }}
:::
::::

Given this {sub-ref}`lief-dwarf-editor`, you can create one or more
{sub-ref}`lief-dwarf-editor-CompilationUnit` entries, which own various
{sub-ref}`lief-dwarf-editor-Function`, {sub-ref}`lief-dwarf-editor-Variable`, and
{sub-ref}`lief-dwarf-editor-Type` objects.

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/dwarf.py", "editor-create") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/dwarf.cpp", "editor-create") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/dwarf.rs", "editor-create") }}
:::
::::

:::{admonition} BinaryNinja & Ghidra
:class: note

This feature is provided as a plugin for {ref}`BinaryNinja <plugins-binaryninja-dwarf>`
and {ref}`Ghidra <plugins-ghidra-dwarf>`.
:::

______________________________________________________________________

## API

You can find the documentation of the API for the different languages here:

{fa}`brands fa-python` {doc}`Python API <python>`

{fa}`regular fa-file-code` {doc}`C++ API <cpp>`

{fa}`brands fa-rust` Rust API: {rust:module}`lief::dwarf`

{{ cross_api }}
