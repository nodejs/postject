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

For ELF executables, the resources are added as sections. Unfortunately
there is no guaranteed metadata about sections in the ELF format, the
section header table (SHT) is optional and can be stripped after linking
(`llvm-strip --strip-sections`). So while the resources are added as
sections, the run-time lookup requires a bespoke implementation, which
makes it the most complex and non-standard out of the platforms. There
are N+1 sections used for the implementation, where the extra section
serves as our own version of the SHT (which can't be stripped). Finding
the SHT section at run-time is done via a static pointer in the code
which is looked up by its symbol name and has its value updated after
the sections are injected.

The build-time equivalent is somewhat involved since our version of
the SHT has to be manually constructed after adding the sections, and
the section updated with the new content. There's also not a standard
tool that can change the value of a static variable after linking, so
instead the SHT is found by a symbol which is added via
`objcopy --binary-architecture`. The following instructions show how
to embed the binary data at build-time for ELF executables, with the
section holding the data name "foobar":

```sh
# The binary data should be on disk in a file named foobar - the name
# of the file is important as it is used in the added symbols
$ objcopy --input binary --output elf64-x86-64 \
  --binary-architecture i386:x86-64 \
  --rename-section .data=foobar,CONTENTS,ALLOC,LOAD,READONLY,DATA \
  foobar foobar.o
# Also create an empty section for the SHT
$ objcopy --input binary --output elf64-x86-64 \
  --binary-architecture i386:x86-64 \
  --rename-section .data=foobar,CONTENTS,ALLOC,LOAD,READONLY,DATA \
  postject_sht postject_sht.o
# Link the created .o files at build-time. Also define
# `__POSTJECT_NO_SHT_PTR` so that the run-time code uses the
# symbol added by `--binary-architecture` to find the SHT
$ clang++ -D__POSTJECT_NO_SHT_PTR test.cpp foobar.o postject_sht.o
# Dump the sections with readelf, and grab the virtual address and
# size for the "foobar" section
$ readelf -S a.out
# Manually create the SHT - replace 0xAA with the virtual address
# and 0xBB with the size from the readelf output
$ python3 -c "import struct; print((struct.pack('<I', 1) + bytes('foobar', 'ascii') + bytes([0]) + struct.pack('<QI', 0xAA, 0xBB)).decode('ascii'), end='');" > postject_sht
# Update the SHT section with the correct content
$ objcopy --update-section postject_sht=postject_sht a.out
```

The run-time lookup finds our version of the SHT through the static
pointer, and then parses the contents of our SHT to look for the
section with the requested name.
