---
description: Load DWARF and PDB debug information, attach matching debug files to binaries, and navigate the shared Python, C++, and Rust APIs.
---

(debug-info)=

# {fa}`solid fa-magnifying-glass` Debug Information

Debug information connects machine code with source-level names, types,
functions, variables, and locations. {ref}`LIEF Extended <extended-intro>` reads
{ref}`DWARF <extended-dwarf>` and {ref}`PDB <extended-pdb>` through format-specific
APIs and the common interfaces documented below.

## Choose how to load debug information

| Input | Starting point |
| --- | --- |
| A binary containing DWARF sections | Parse the binary and access {sub-ref}`lief-dwarf-binary-debug-info` |
| A separate DWARF file or a Mach-O debug companion | Load it with {sub-ref}`lief-dwarf-load` |
| A PDB file | Load it with {sub-ref}`lief-pdb-load` |
| A parsed binary and its matching external debug file | Attach the file with {sub-ref}`lief-abstract-binary-load_debug_info` |


Attaching an external file makes its information available to the parsed binary.
The {sub-ref}`lief-disassemble` API can then disassemble functions by name. Attaching the
file does not embed it into the executable. Use the debug file from the same
build: {sub-ref}`lief-abstract-binary-load_debug_info` does not verify build IDs or
PDB identifiers for you.

The {ref}`DWARF <extended-dwarf>` and {ref}`PDB <extended-pdb>` guides show how to
iterate over compilation units, find functions and types, and generate C/C++
declarations.

## Shared API reference

### {fa}`regular fa-file-code` C++

#### DebugInfo

```{eval-rst}
.. doxygenclass:: LIEF::DebugInfo
```

#### debug_location_t

```{eval-rst}
.. doxygenstruct:: LIEF::debug_location_t
```

#### DeclOpt

```{eval-rst}
.. doxygenclass:: LIEF::DeclOpt
```

______________________________________________________________________

### {fa}`brands fa-python` Python

#### DebugInfo

```{eval-rst}
.. autoclass:: lief.DebugInfo

```

#### debug_location_t

```{eval-rst}
.. autoclass:: lief.debug_location_t
```

#### DeclOpt

```{eval-rst}
.. autoclass:: lief.DeclOpt
```

______________________________________________________________________

### {fa}`brands fa-rust` Rust

- {rust:trait}`lief::generic::DebugInfo`
- {rust:struct}`lief::DebugLocation`
- {rust:struct}`lief::DeclOpt`

{{ cross_api }}
