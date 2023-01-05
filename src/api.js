const { constants, promises: fs } = require("fs");
const path = require("path");

const loadPostjectModule = require("./postject.js");

async function inject(filename, resourceName, resourceData, options) {
  const machoSegmentName = options?.machoSegmentName || "__POSTJECT";
  const overwrite = options?.overwrite || false;

  if (!Buffer.isBuffer(resourceData)) {
    throw new TypeError("resourceData must be a buffer");
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

  const SENTINEL = "POSTJECT_SENTINEL_fce680ab2cc467b6e072b8b5df1996b2:";
  const buffer = Buffer.from(data.buffer);
  const firstSentinel = buffer.indexOf(SENTINEL);

  if (firstSentinel === -1) {
    throw new Error(`Could not find the sentinel ${SENTINEL} in the binary`);
  }

  const lastSentinel = buffer.lastIndexOf(SENTINEL);

  if (firstSentinel !== lastSentinel) {
    throw new Error(
      `Multiple occurences of sentinel "${SENTINEL}" found in the binary`
    );
  }

  const hasResourceIndex = firstSentinel + SENTINEL.length;
  const hasResourceValue = buffer[hasResourceIndex];
  if (hasResourceValue === "0".charCodeAt(0)) {
    buffer[hasResourceIndex] = "1".charCodeAt(0);
  } else if (hasResourceValue != "1".charCodeAt(0)) {
    throw new Error(
      `Value at index ${hasResourceIndex} must be '0' or '1' but '${hasResourceValue}' was found`
    );
  }

  try {
    await fs.writeFile(filename, buffer);
  } catch {
    throw new Error("Couldn't write executable");
  }
}

module.exports = { inject };
