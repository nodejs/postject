#!/usr/bin/env node

const { constants, promises: fs } = require("fs");
const path = require("path");

const program = require("commander");

const loadPostjectModule = require("./postject.js");

async function main(filename, resourceName, resource, options) {
  if (options.outputApiHeader) {
    console.log(
      await fs.readFile(path.join(__dirname, "postject-api.h"), "utf-8")
    );
    process.exit(0);
  }

  try {
    await fs.access(filename, constants.R_OK | constants.W_OK);
  } catch {
    console.log("Can't read and write to target executable");
    process.exit(1);
  }

  let resourceData;

  try {
    await fs.access(resource, constants.R_OK);
    resourceData = await fs.readFile(resource);
  } catch {
    console.log("Can't read resource file");
    process.exit(1);
  }

  let executable;

  const postject = await loadPostjectModule();

  try {
    executable = await fs.readFile(filename);
  } catch {
    console.log("Couldn't read target executable");
    process.exit(1);
  }
  const executableFormat = postject.getExecutableFormat(executable);

  if (!executableFormat) {
    console.log("Executable must be a supported format: ELF, PE, or Mach-O");
    process.exit(1);
  }

  let data;
  let result;

  switch (executableFormat) {
    case postject.ExecutableFormat.kMachO:
      {
        let sectionName = resourceName;

        // Mach-O section names are conventionally of the style __foo
        if (!sectionName.startsWith("__")) {
          sectionName = `__${sectionName}`;
        }

        ({ result, data } = postject.injectIntoMachO(
          executable,
          options.machoSegmentName,
          sectionName,
          resourceData,
          options.overwrite
        ));

        if (result === postject.InjectResult.kAlreadyExists) {
          console.log(
            `Segment and section with that name already exists: ${options.machoSegmentName}/${sectionName}`
          );
          console.log("Use --overwrite to overwrite the existing content");
          process.exit(2);
        }
      }
      break;

    case postject.ExecutableFormat.kELF:
      {
        // ELF sections usually start with a dot ("."), but this is
        // technically reserved for the system, so don't transform
        let sectionName = resourceName;

        ({ result, data } = postject.injectIntoELF(
          executable,
          sectionName,
          resourceData,
          options.overwrite
        ));

        if (result === postject.InjectResult.kAlreadyExists) {
          console.log(`Section with that name already exists: ${sectionName}`);
          console.log("Use --overwrite to overwrite the existing content");
          process.exit(2);
        }
      }
      break;

    case postject.ExecutableFormat.kPE:
      {
        // PE resource names appear to only work if uppercase
        resourceName = resourceName.toUpperCase();

        ({ result, data } = postject.injectIntoPE(
          executable,
          resourceName,
          resourceData,
          options.overwrite
        ));

        if (result === postject.InjectResult.kAlreadyExists) {
          console.log(
            `Resource with that name already exists: ${resourceName}`
          );
          console.log("Use --overwrite to overwrite the existing content");
          process.exit(2);
        }
      }
      break;
  }

  if (result !== postject.InjectResult.kSuccess) {
    console.log("Error when injecting resource");
    process.exit(3);
  }

  try {
    await fs.writeFile(filename, data);
  } catch {
    console.log("Couldn't write executable");
    process.exit(1);
  }
}

if (require.main === module) {
  program
    .name("postject")
    .description(
      "Inject arbitrary read-only resources into an executable for use at runtime"
    )
    .argument("<filename>", "The executable to inject into")
    .argument(
      "<resource_name>",
      "The resource name to use (section name on Mach-O and ELF, resource name for PE)"
    )
    .argument("<resource>", "The resource to inject")
    .option(
      "--macho-segment-name <segment_name>",
      "Name for the Mach-O segment",
      "__POSTJECT"
    )
    .option("--output-api-header", "Output the API header to stdout")
    .option("--overwrite", "Overwrite the resource if it already exists")
    .action(main)
    .parse(process.argv);
}
