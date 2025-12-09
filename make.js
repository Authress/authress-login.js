/**
 * Module dependencies
 */
import commander from 'commander';
import fs from 'fs-extra';
import { fileURLToPath } from 'url';
import path from 'path';

function getVersion() {
  let release_version = '0.0';
  const pull_request = '';
  const branch = process.env.GITHUB_REF;
  const build_number = `${process.env.GITHUB_RUN_NUMBER || '0'}`;

  //Builds of pull requests
  if (pull_request && !pull_request.match(/false/i)) {
    release_version = `0.${pull_request || '0'}`;
  } else if (!branch || !branch.match(/^(refs\/heads\/)?release[/-]/i)) {
    //Builds of branches that aren't master or release
    release_version = '0.0';
  } else {
    //Builds of release branches (or locally or on server)
    release_version = branch.match(/^(?:refs\/heads\/)?release[/-](\d+(?:\.\d+){0,3})$/i)[1];
  }
  return `${release_version}.${(build_number || '0')}.0.0.0.0`.split('.').slice(0, 3).join('.');
}
const version = getVersion();
commander.version(version);

const underscoreDirname = path.dirname(fileURLToPath(import.meta.url));
const packageMetadataFile = path.join(underscoreDirname, 'package.json');
const packageMetadata = await fs.readJson(packageMetadataFile);

/**
 * Build
 */
commander
.command('build')
.description('Setup require build files for npm package.')
.action(async () => {
  packageMetadata.version = version;
  await fs.writeJson('./package.json', packageMetadata, { spaces: 2 });

  console.log('Building package %s (%s)', packageMetadata.name, version);
  console.log('');
});

commander.on('*', () => {
  if (commander.args.join(' ') === 'tests/**/*.js') { return; }
  console.log(`Unknown Command: ${commander.args.join(' ')}`);
  commander.help();
});
commander.parse(process.argv[2] ? process.argv : process.argv.concat(['build']));
