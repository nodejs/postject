const { constants, promises: fs } = require("fs");
const path = require("path");

const loadPostjectModule = require("./postject.js");

async function inject(filename, resourceName, resourceData, options) {
  const machoSegmentName = options?.machoSegmentName || "__POSTJECT";
  const overwrite = options?.overwrite || false;

  if (!Buffer.isBuffer(resourceData)) {
    throw new Error("resourceData must be a buffer");
  }

  try {
    await fs.access(filename, constants.R_OK | constants.W_OK);
  } catch {
    throw new Error("Can't read and write to target executable");
  }

  let executable;

  const postject = await loadPostjectModule();

  try {
    executable = await fs.readFile(filename);
  } catch {
    throw new Error("Couldn't read target executable");
  }
  const executableFormat = postject.getExecutableFormat(executable);

  if (!executableFormat) {
    throw new Error(
      "Executable must be a supported format: ELF, PE, or Mach-O"
    );
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
          machoSegmentName,
          sectionName,
          resourceData,
          overwrite
        ));

        if (result === postject.InjectResult.kAlreadyExists) {
          throw new Error(
            `Segment and section with that name already exists: ${machoSegmentName}/${sectionName}\n` +
              "Use --overwrite to overwrite the existing content"
          );
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
          overwrite
        ));

        if (result === postject.InjectResult.kAlreadyExists) {
          throw new Error(
            `Section with that name already exists: ${sectionName}` +
              "Use --overwrite to overwrite the existing content"
          );
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
          overwrite
        ));

        if (result === postject.InjectResult.kAlreadyExists) {
          throw new Error(
            `Resource with that name already exists: ${resourceName}\n` +
              "Use --overwrite to overwrite the existing content"
          );
        }
      }
      break;
  }

  if (result !== postject.InjectResult.kSuccess) {
    throw new Error("Error when injecting resource");
  }

  try {
    await fs.writeFile(filename, data);
  } catch {
    throw new Error("Couldn't write executable");
  }
}

module.exports = { inject };
