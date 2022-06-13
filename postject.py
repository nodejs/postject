#!/usr/bin/env python3

import argparse
import pathlib
import struct
import sys
from enum import Enum, auto

# Since we're building LIEF ourselves, add the build output to sys.path so it can be imported
sys.path.append(str(pathlib.Path(__file__).parent.joinpath("dist", "lief")))

import lief


class ExecutableFormat(Enum):
    ELF = auto()
    MACH_O = auto()
    PE = auto()


def get_executable_format(filename):
    if lief.is_pe(filename):
        return ExecutableFormat.PE
    elif lief.is_elf(filename):
        return ExecutableFormat.ELF
    elif lief.is_macho(filename):
        return ExecutableFormat.MACH_O

    return None


# Unlike with Mach-O and PE, there doesn't appear to be a robust way
# to look up sections by name at runtime for ELF. While ELF has a
# Section Header Table (SHT) which provides the virtual address for
# every section by name, it is not required and can be easily stripped,
# such as by `llvm-strip --strip-sections [filename]`. With that in
# mind, we need a more foolproof method which will work 100% of the time
# even if the executable has been stripped to save diskspace, and
# requiring users to not strip the executables is not reasonable.
#
# The solution implemented here is to add a section which will
# serve as our own version of the SHT - there will be only one
# regardless of how many additional sections the user injects.
# We'll then grab the virtual address of this section, and find
# our symbol where we'll replace the value with the virtual address,
# allowing us to find our SHT at runtime simply by dereferencing
# the pointer. That section will then have a list of the injected
# sections, with their name, virtual address, and size.
#
# NOTE - At the moment we're shipping a header-only API, which makes
#        this somewhat awkward, because the symbol needs to be marked
#        extern and the user needs to create it
#
# TODO - At the moment this isn't infinitely repeatable with overwrite=True,
#        the executable becomes corrupted after a few runs
#
# TODO - Parsing and then simply writing back to disk corrupts Electron
#        and causes it to crash on Linux
def inject_into_elf(filename, section_name, data, overwrite=False):
    app = lief.ELF.parse(filename)

    struct_endian_char = ">"

    if app.header.identity_data == lief.ELF.ELF_DATA.LSB:
        struct_endian_char = "<"

    existing_section = app.get_section(section_name)

    if existing_section:
        if not overwrite:
            return False

        app.remove_section(section_name, clear=True)

    # Create the new section we're injecting
    section = lief.ELF.Section()
    section.name = section_name
    section.content = data
    section.add(lief.ELF.SECTION_FLAGS.ALLOC)  # Ensure it's loaded into memory

    # Important to use the return value to get the updated
    # information like the virtual address, LIEF is returning
    # a separate object instead of updating the existing one
    section = app.add(section)

    sections = [section]

    # The contents of our SHT section are laid out as:
    # * section count (uint32)
    # * N sections:
    #   * name as a null-terminated string
    #   * virtual address (uint64)
    #   * section size (uint32)
    postject_sht = app.get_section("postject_sht")

    if postject_sht:
        contents = postject_sht.content

        section_count = struct.unpack(f"{struct_endian_char}I", contents[:4])[0]
        idx = 4

        for _ in range(section_count):
            name = ""

            while True:
                ch = contents[idx]
                idx += 1

                if ch != 0:
                    name += chr(ch)
                else:
                    break

            # We're already overwriting this section
            if name == section_name:
                continue

            section = app.get_section(name)

            if not section:
                raise RuntimeError("Couldn't find section listed in our SHT")
            else:
                sections.append(section)

            idx += 12  # Skip over the other info

        app.remove_section("postject_sht", clear=True)

    section_count = struct.pack(f"{struct_endian_char}I", len(sections))
    content_bytes = section_count

    for section in sections:
        content_bytes += bytes(section.name, "ascii") + bytes([0])
        content_bytes += struct.pack(f"{struct_endian_char}QI", section.virtual_address, section.size)

    postject_sht = lief.ELF.Section()
    postject_sht.name = "postject_sht"
    postject_sht.add(lief.ELF.SECTION_FLAGS.ALLOC)  # Ensure it's loaded into memory
    postject_sht.content = list(content_bytes)

    postject_sht = app.add(postject_sht)

    # TODO - How do we determine the size of void* from the ELF?
    # TODO - Why does it appear to only be 4 bytes when sizeof(void*) is showing 8?
    # TODO - Do we need to care or just let LIEF patch the address and assume it's fine?

    symbol_found = False

    # Find the symbol for our SHT pointer and update the value
    for symbol in app.symbols:
        if symbol.demangled_name == "_binary_postject_sht_start":
            symbol_found = True
            app.patch_address(symbol.value, postject_sht.virtual_address)
            break

    if not symbol_found:
        print("ERROR: Couldn't find symbol")
        sys.exit(1)

    app.write(filename)

    return True


def inject_into_pe(filename, resource_name, data, overwrite=False):
    app = lief.PE.parse(filename)

    # TODO - lief.PE.ResourcesManager doesn't support RCDATA it seems, add support so this is simpler

    resources = app.resources

    # First level => Type (ResourceDirectory node)
    try:
        rcdata_node = next(iter(filter(lambda node: node.id == lief.PE.RESOURCE_TYPES.RCDATA.value, resources.childs)))
    except StopIteration:
        rcdata_node = lief.PE.ResourceDirectory()
        rcdata_node.id = lief.PE.RESOURCE_TYPES.RCDATA
        rcdata_node = resources.add_directory_node(rcdata_node)

        # TODO - This isn't documented, but if this isn't done things don't work
        #        as expected. It seems that standard order for resources in PE
        #        is to be sorted by ID, and if they're not, Windows APIs don't
        #        seem to work as expected. Was not able to find this documented
        #        for the PE format itself.
        resources.sort_by_id()

    # Second level => ID (ResourceDirectory node)
    try:
        id_node = next(iter(filter(lambda node: node.name == resource_name, rcdata_node.childs)))
    except StopIteration:
        id_node = lief.PE.ResourceDirectory()
        id_node.name = resource_name
        # TODO - This isn't documented, but if this isn't set then LIEF won't save the name. Seems
        #        like LIEF should be able to automatically handle this if you've set the node's name
        id_node.id = 0x80000000
        id_node = rcdata_node.add_directory_node(id_node)

    # Third level => Lang (ResourceData node)
    try:
        lang_node = id_node.childs[0]
    except IndexError:
        lang_node = lief.PE.ResourceData()
    else:
        if not overwrite:
            return False

        id_node.delete_child(lang_node)
    finally:
        lang_node.content = data
        lang_node = id_node.add_data_node(lang_node)

    app.remove_section(".rsrc", clear=True)

    # Write out the binary, only modifying the resources
    builder = lief.PE.Builder(app)
    builder.build_dos_stub(True)
    builder.build_imports(False)
    builder.build_overlay(False)
    builder.build_relocations(False)
    builder.build_resources(True)
    builder.build_tls(False)
    builder.build()

    # TODO - Why doesn't LIEF just replace the .rsrc section?
    #        Can we at least change build_resources to take a section name?

    # Re-parse the output so the .l2 section is available
    app = lief.parse(builder.get_build())

    # Rename the rebuilt resource section
    section = app.get_section(".l2")
    section.name = ".rsrc"

    builder = lief.PE.Builder(app)
    builder.build_dos_stub(True)
    builder.build_imports(False)
    builder.build_overlay(False)
    builder.build_relocations(False)
    builder.build_resources(False)
    builder.build_tls(False)
    builder.build()
    builder.write(filename)

    return True


def inject_into_macho(filename, segment_name, section_name, data, overwrite=False):
    app = lief.MachO.parse(filename)

    existing_section = app.get_section(segment_name, section_name)

    if existing_section:
        if not overwrite:
            return False

        app.remove_section(segment_name, section_name, clear=True)

    # Create the section and mark it read-only
    segment = lief.MachO.SegmentCommand(segment_name)
    segment.max_protection = lief.MachO.VM_PROTECTIONS.READ
    segment.init_protection = lief.MachO.VM_PROTECTIONS.READ

    # TODO - Apple says a segment needs to be a multiple of 4096, but LIEF seems to
    # be creating a segment which matches the section size, which is way smaller? It
    # all seems to work correctly, but the discrepancy might cause other problems,
    # so we should try to fix this in LIEF
    #
    # segment.virtual_size = 0x4000
    # segment.file_size = segment.virtual_size - len(data)

    section = lief.MachO.Section(section_name, data)
    segment.add_section(section)
    app.add(segment)

    # It will need to be signed again anyway, so remove the signature
    app.remove_signature()
    app.write(filename)

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Inject arbitrary read-only resources into an executable for use at runtime"
    )
    parser.add_argument(
        "filename",
        type=pathlib.Path,
        help="The executable to inject into",
    )
    parser.add_argument(
        "resource_name",
        type=str,
        help="The resource name to use (section name on Mach-O and ELF, resource name for PE)",
    )
    parser.add_argument(
        "resource",
        type=argparse.FileType("rb"),
        help="The resource to inject",
    )
    parser.add_argument(
        "--macho-segment-name",
        type=str,
        default="__POSTJECT",
        help="Name for the Mach-O segment (default: __POSTJECT)",
    )
    parser.add_argument(
        "--overwrite",
        default=False,
        action="store_true",
        help="Overwrite the resource if it already exists",
    )
    parser.add_argument(
        "--output-api-header",
        default=False,
        action="store_true",
        help="Output the API header to stdout",
    )

    if "--output-api-header" in sys.argv:
        with open(str(pathlib.Path(__file__).parent.joinpath("postject-api.h"))) as f:
            print(f.read())

        sys.exit(0)

    args = parser.parse_args()

    # Resolve path to walk any symlinks
    filename = str(args.filename.resolve())
    executable_format = get_executable_format(filename)

    if not executable_format:
        print("Executable must be a supported format: ELF, PE, or Mach-O")
        sys.exit(1)

    data = list(args.resource.read())

    if executable_format == ExecutableFormat.MACH_O:
        section_name = args.resource_name

        # Mach-O section names are conventionally of the style __foo
        if not section_name.startswith("__"):
            section_name = f"__{section_name}"

        if not inject_into_macho(filename, args.macho_segment_name, section_name, data, overwrite=args.overwrite):
            print(f"Segment and section with that name already exists: {args.macho_segment_name}/{section_name}")
            print("Use --overwrite to overwrite the existing content")
            sys.exit(2)
    elif executable_format == ExecutableFormat.ELF:
        # ELF sections usually start with a dot ("."), but this is
        # technically reserved for the system, so don't transform
        section_name = args.resource_name

        if not inject_into_elf(filename, section_name, data, overwrite=args.overwrite):
            print(f"Section with that name already exists: {section_name}")
            print("Use --overwrite to overwrite the existing content")
            sys.exit(2)
    elif executable_format == ExecutableFormat.PE:
        # PE resource names appear to only work if uppercase
        resource_name = args.resource_name.upper()

        if not inject_into_pe(filename, resource_name, data, overwrite=args.overwrite):
            print(f"Resource with that name already exists: {resource_name}")
            print("Use --overwrite to overwrite the existing content")
            sys.exit(2)


if __name__ == "__main__":
    sys.exit(main())
