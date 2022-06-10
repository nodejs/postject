# postject

Easily inject arbitrary read-only resources into executable formats
(MachO, PE, ELF) and use it at runtime.

## Building

### Windows

You'll need CMake and Ninja to build LIEF.

```sh
$ cd vendor\lief
$ python3 ./setup.py --ninja build_ext -b ..\..\dist\lief
```

### macOS

```sh
$ cd vendor/lief
$ python3 ./setup.py build -b ../../dist/lief -j 8
```

### Linux

TODO

## Usage

```sh
$ ./postject.py --macho-segment-name __ELECTRON /Users/dsanders/electron/src/out/Testing/Electron.app/Contents/Frameworks/Electron\ Framework.framework/Electron\ Framework __app_asar /Users/dsanders/test.asar
```
