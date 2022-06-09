# postject

Easily inject arbitrary read-only resources into executable formats
(MachO, PE, ELF) and use it at runtime.

## Installation

TODO

## Example

```sh
./postject.py --macho-segment-name __ELECTRON /Users/dsanders/electron/src/out/Testing/Electron.app/Contents/Frameworks/Electron\ Framework.framework/Versions/A/Electron\ Framework __app_asar /Users/dsanders/test.asar
```
