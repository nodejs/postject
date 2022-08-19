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

    existing_section = None
    for note in app.notes:
        if note.name == section_name:
            existing_section = note

    if existing_section:
        if not overwrite:
            return False

        app.remove(note)

    note = lief.ELF.Note()
    note.name = section_name
    note.description = data
    note = app.add(note)

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
    fat_binary = lief.MachO.parse(filename)

    # Inject into all Mach-O binaries if there's more than one in a fat binary
    for app in fat_binary:
        existing_section = app.get_section(segment_name, section_name)

        if existing_section:
            if not overwrite:
                return False

            app.remove_section(segment_name, section_name, clear=True)

        segment = app.get_segment(segment_name)
        section = lief.MachO.Section(section_name, data)

        if not segment:
            # Create the segment and mark it read-only
            segment = lief.MachO.SegmentCommand(segment_name)
            segment.max_protection = lief.MachO.VM_PROTECTIONS.READ
            segment.init_protection = lief.MachO.VM_PROTECTIONS.READ
            segment.add_section(section)
            app.add(segment)
        else:
            app.add_section(segment, section)

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
