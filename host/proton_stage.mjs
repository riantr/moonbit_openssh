#!/usr/bin/env node
// Stage the CEF runtime beside the built proton_gui executable.
//
// `moon build` links against the CEF import library from the shared store,
// but at run time the executable wants, relative to ITSELF:
//
//   libcef.dll + the rest of the CEF Release set   (loader resolves these
//                                                   before main() runs --
//                                                   the exe's own directory
//                                                   is on the default
//                                                   search path, `bin\` is
//                                                   not, whatever Proton's
//                                                   own convention is)
//   cef_process.exe                                (the subprocess helper,
//                                                   version-locked to proton)
//   Resources/                                     (CEF pak/icu resources)
//
// All three come from ~/.proton, which `proton_cli cef setup` filled in
// already.  The exact set was derived from the runtime's own error messages --
// it names each missing path in turn, and the three stages above are the
// complete list it asked for.
//
// Run after every `moon build` that removed _build:
//   node host/proton_stage.mjs [build-dir]
//
// Default build-dir: _build/native/debug/build/cmd/proton_gui

import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, copyFileSync, cpSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

const ROOT = join(import.meta.dirname, '..');
const DEST = join(ROOT, process.argv[2] || '_build/native/debug/build/cmd/proton_gui');

// The store directory name is the CEF archive's sha256; read it from the
// proton package's generated requirements instead of hard-coding it, so a
// proton bump takes this script with it.
const reqPath = join(ROOT, '.mooncakes/moonbit-community/proton/cef_requirements.generated.mjs');
const { runtimeRequirements, runtimeLayoutVersion } = await import(
  `file://${reqPath.replace(/\\/g, '/')}`
);
const req = runtimeRequirements['win32-x64'];
if (!req?.supported) {
  console.error('win32-x64 is not a supported Proton CEF platform');
  process.exit(1);
}
const store = join(homedir(), '.proton', 'store', 'win32-x64',
  `cef-${req.sha256}-layout-${runtimeLayoutVersion}`);
const release = join(store, 'sdk', 'Release');
const resources = join(store, 'runtime', 'Resources');
const helper = join(homedir(), '.proton', 'helpers', 'win32-x64',
  '0.3.4', 'cef_process.exe');
for (const p of [release, resources, helper]) {
  if (!existsSync(p)) {
    console.error(`missing: ${p}\nrun: proton_cli cef setup`);
    process.exit(1);
  }
}

mkdirSync(DEST, { recursive: true });
for (const f of ['libcef.dll', 'chrome_elf.dll', 'libEGL.dll', 'libGLESv2.dll',
  'd3dcompiler_47.dll', 'dxcompiler.dll', 'dxil.dll', 'vk_swiftshader.dll',
  'vulkan-1.dll', 'icudtl.dat', 'resources.pak', 'chrome_100_percent.pak',
  'chrome_200_percent.pak', 'v8_context_snapshot.bin',
  'vk_swiftshader_icd.json']) {
  copyFileSync(join(release, f), join(DEST, f));
}
copyFileSync(helper, join(DEST, 'cef_process.exe'));
cpSync(resources, join(DEST, 'Resources'), { recursive: true });
console.log(`staged CEF runtime + helper + Resources into ${DEST}`);
