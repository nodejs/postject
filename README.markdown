# postject

Easily inject arbitrary read-only resources into executable formats
(Mach-O, PE, ELF) and use it at runtime.

## Building

### Windows

You'll need CMake and Ninja to build LIEF.

```sh
$ cd vendor\lief
$ python3 ./setup.py --ninja build_ext -b ..\..\dist\lief
```

### macOS / Linux

```sh
$ make lief
```

## Usage

```sh
$ ./postject.py --macho-segment-name __ELECTRON /Users/dsanders/electron/src/out/Testing/Electron.app/Contents/Frameworks/Electron\ Framework.framework/Electron\ Framework app_asar /Users/dsanders/test.asar
```

### Testing

```sh
$ make check
```

## Design

To ensure maximum capatibility and head off unforeseen issues, the
implementation for each format tries to use that format's standard
practices for embedding binary data. As such, it should be possible
to embed the binary data at build-time as well. The CLI provides the
ability to inject the resources into pre-built executables, with the
goal that the end result should be as close as possible to what is
obtained by embedding them at build-time.

### Windows

For PE executables, the resources are added into the `.rsrc` section,
with the `RT_RCDATA` (raw data) type.

The build-time equivalent is adding the binary data as a resource in
the usual manner, such as the Resource Compiler, and marking it as
`RT_RCDATA`.

The run-time lookup uses the `FindResource` and `LoadResource` APIs.

### macOS

For Mach-O executables, the resources are added as sections inside a
new segment.

The build-time equivalent of embedding binary data with this approach
uses a linker flag: `-sectcreate,__FOO,__foo,content.txt`

The run-time lookup uses APIs from `<mach-o/getsect.h>`.

### Linux

For ELF executables, the resources are added as notes.

The build-time equivalent is to use a linker script.
