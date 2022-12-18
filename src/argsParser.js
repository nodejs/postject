"use strict";
const { parseArgs } = require("util");

const mainOptions = {
  help: { type: 'string', short: "h" },
  "macho-segment-name": { type: "string" },
  "output-api-header": { type: "boolean" },
  overwrite: { type: "boolean" },
};

function helper(command) {
  const helpOptionsDescriptions = {
    help: "display help for command",
    "macho-segment-name": "--macho-segment-name <segment_name>  Name for the Mach-O segment (default: \"__POSTJECT\")",
    "output-api-header": "--output-api-header                  Output the API header to stdout",
    "overwrite": "--overwrite                          Overwrite the resource if it already exists"
  };
  if (command) {
    console.log(helpOptionsDescriptions[command]);
  }
  else {
    console.log("Usage: postject [options] <filename> <resource_name> <resource>");
    console.log("Inject arbitrary read-only resources into an executable for use at runtime");
    console.log("");
    console.log("Arguments:");
    console.log("  filename        The executable to inject the resource into");
    console.log("  resource_name   The resource name to use (section name on Mach-O and ELF, resource name for PE)");
    console.log("  resource        The resource file to inject");
    console.log("Options:");
    for (const [key, value] of Object.entries(helpOptionsDescriptions)) {
      console.log(`  ${value}`);
    }
  }
}

function argumentsParser(clb) {

  const args = process.argv.slice(2);
  if (args.includes('--help') || args.includes('-h')) {
    const { values } = parseArgs({ args, options: mainOptions, strict: false, tokens: true });
    if (typeof values.help === 'string') {
      helper(values.help);
    }
    else {
      helper();
    }
    process.exit();
  }
  if (args.length < 3) {
    console.log("Missing adequate arguments");
    helper();
    process.exit(1);
  }
  const positionalArgs = args.slice(args.length - 3);
  const subCommandArgs = args.slice(0, args.length - 3);

  const optionValuesObj = parseArgs({
    args: subCommandArgs,
    options: mainOptions,
    strict: false,
    tokens: true,
  }).values;
  const options = Object.keys(optionValuesObj).reduce((acc, key) => {
    const camelCaseKey = key.replace(/-([a-z])/g, (g) =>
      g[1].toUpperCase()
    );
    acc[camelCaseKey] = optionValuesObj[key];
    return acc;
  }, {});
  clb(...positionalArgs, options);
}

module.exports = { argumentsParser };