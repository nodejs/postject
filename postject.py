#!/usr/bin/env python3

import argparse
import pathlib
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


# TODO - This is untested, @robert.gunzler
def inject_into_elf(filename, section_name, data, overwrite=False):
    app = lief.parse(filename)

    existing_section = app.get_section(segment_name, section_name)

    if existing_section:
        if not overwrite:
            return False

        app.remove_section(section_name, clear=True)

    section = lief.ELF.Section()
    section.name = section_name
    section.content = data

    app.add(section)

    app.write(filename)

    return True


# TODO - This is untested, it likely won't work immediately
def inject_into_pe(filename, resource_name, data, overwrite=False):
    app = lief.parse(filename)

    # TODO - lief.PE.ResourcesManager doesn't support RCDATA it seems, add support so this is simpler

    resources = app.resources

    # First level => Type (ResourceDirectory node)
    rcdata_node = next(iter(filter(lambda node: node.id == lief.PE.RESOURCE_TYPES.RCDATA, resources.childs)))

    if not rcdata_node:
        rcdata_node = lief.PE.ResourceDirectory()
        rcdata_node.id = lief.PE.RESOURCE_TYPES.RCDATA
        resources.add_directory_node(rcdata_node)

    # Second level => ID (ResourceDirectory node)
    id_node = next(iter(filter(lambda node: node.name == resource_name, resources.childs)))

    if not id_node:
        id_node = lief.PE.ResourceDirectory()
        id_node.name = resource_name
        rcdata_node.add_directory_node(id_node)

    # Third level => Lang (ResourceData node)
    lang_node = id_node.childs[0]

    if lang_node:
        if not overwrite:
            return False

        lang_node.content = data
    else:
        resource = lief.PE.ResourceData()
        resource.content = data
        resource.name = resource_name

        lang_node.add_data_node(resource)

    app.write(filename)

    return True


def inject_into_macho(filename, segment_name, section_name, data, overwrite=False):
    app = lief.parse(filename)

    existing_section = app.get_section(segment_name, section_name)

    if existing_section:
        if not overwrite:
            return False

        # TODO - There doesn't appear to be a way to specify segment name, not great
        app.remove_section(section_name, clear=True)

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
        type=str,
        help="The executable to inject into",
    )
    parser.add_argument(
        "resource_name",
        type=str,
        help="The resource name to use (section name on MachO and ELF, resource name for PE)",
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
        help="Name for the MachO segment (default: __POSTJECT)",
    )
    parser.add_argument(
        "--overwrite",
        type=bool,
        default=False,
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

    executable_format = get_executable_format(args.filename)

    if not executable_format:
        print("Executable must be a supported format: ELF, PE, or MachO")
        sys.exit(1)

    data = list(args.resource.read())

    if executable_format == ExecutableFormat.MACH_O:
        if not inject_into_macho(
            args.filename, args.macho_segment_name, args.resource_name, data, overwrite=args.overwrite
        ):
            print(f"Segment and section with that name already exists: {args.macho_segment_name}/{args.resource_name}")
            print("Use --overwrite to overwrite the existing content")
            sys.exit(2)
    elif executable_format == ExecutableFormat.ELF:
        if not inject_into_elf(args.filename, args.resource_name, data, overwrite=args.overwrite):
            print(f"Section with that name already exists: {args.resource_name}")
            print("Use --overwrite to overwrite the existing content")
            sys.exit(2)
    elif executable_format == ExecutableFormat.PE:
        if not inject_into_pe(args.filename, args.resource_name, data, overwrite=args.overwrite):
            print(f"Resource with that name already exists: {args.resource_name}")
            print("Use --overwrite to overwrite the existing content")
            sys.exit(2)


if __name__ == "__main__":
    sys.exit(main())
