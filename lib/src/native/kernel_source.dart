/*
  Copyright 2026 - Stephan M. February

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

/// What the build hook and the release tooling agree on: which files make up
/// the kernel crate, the one hash that names them, and the file a prebuilt
/// library is published under for each target.
///
/// A prebuilt library is only ever used for the exact source it was built
/// from. The manifest records that source's hash, and the hook recomputes it
/// from the crate it ships with; any edit to the crate, even a comment, sends
/// the hook to cargo instead of a download that would no longer match.
library;

import 'dart:io';

import 'package:crypto/crypto.dart' as crypto;

/// The crate's directory, relative to the package root.
const crateDir = 'native/stark_kernels';

/// The files whose bytes decide what the library is: the manifest, the lock
/// file, and everything under `src/`, as paths relative to [crateRoot],
/// sorted so the hash does not depend on directory order.
List<String> crateFiles(Directory crateRoot) {
  final src = Directory.fromUri(crateRoot.uri.resolve('src/'));
  final files = <String>[
    'Cargo.toml',
    'Cargo.lock',
    for (final e in src.listSync(recursive: true))
      if (e is File) 'src/${e.uri.pathSegments.skip(src.uri.pathSegments.length - 1).join('/')}',
  ]..sort();
  return files;
}

/// The SHA-256 of the crate's source, over each file's relative path and its
/// contents with line endings normalised, so a checkout that turned `\n` into
/// `\r\n` still hashes the same, and then over [buildRecipe]: a library built
/// with other flags is another library, so changing a flag must retire the
/// prebuilt ones as surely as editing the crate does.
String sourceHash(Directory crateRoot) {
  final bytes = <int>[];
  for (final rel in crateFiles(crateRoot)) {
    final content = File.fromUri(crateRoot.uri.resolve(rel)).readAsStringSync().replaceAll('\r\n', '\n');
    bytes
      ..addAll('$rel\n'.codeUnits)
      ..addAll(content.codeUnits)
      ..add(0);
  }
  bytes.addAll(buildRecipe().codeUnits);
  return crypto.sha256.convert(bytes).toString();
}

/// Every triple a library is built for, prebuilt or from source.
const buildTriples = [
  'aarch64-apple-darwin',
  'x86_64-apple-darwin',
  'x86_64-unknown-linux-gnu',
  'aarch64-unknown-linux-gnu',
  'x86_64-pc-windows-msvc',
  'aarch64-pc-windows-msvc',
  'aarch64-linux-android',
  'armv7-linux-androideabi',
  'x86_64-linux-android',
  'aarch64-apple-ios',
  'aarch64-apple-ios-sim',
  'x86_64-apple-ios',
];

/// How each triple is built, one line each: its features and its rustc flags.
String buildRecipe() => [
      for (final t in buildTriples) '$t features=${cargoFeatures(t).join(',')} flags=${rustFlags(t).join(' ')}\n',
    ].join();

/// The release tag the prebuilt libraries for [hash] are published under.
/// Named by source rather than by package version: the kernels change far
/// less often than tstokenlib does, and two versions that ship the same crate
/// share one set of binaries.
String releaseTag(String hash) => 'stark-kernels-${hash.substring(0, 16)}';

/// The Rust target triple for a Dart target, or null when there is none.
String? rustTriple(String os, String arch, {bool iosSimulator = false}) => switch ((os, arch)) {
      ('macos', 'arm64') => 'aarch64-apple-darwin',
      ('macos', 'x64') => 'x86_64-apple-darwin',
      ('linux', 'x64') => 'x86_64-unknown-linux-gnu',
      ('linux', 'arm64') => 'aarch64-unknown-linux-gnu',
      ('windows', 'x64') => 'x86_64-pc-windows-msvc',
      ('windows', 'arm64') => 'aarch64-pc-windows-msvc',
      ('android', 'arm64') => 'aarch64-linux-android',
      ('android', 'arm') => 'armv7-linux-androideabi',
      ('android', 'x64') => 'x86_64-linux-android',
      ('ios', 'arm64') => iosSimulator ? 'aarch64-apple-ios-sim' : 'aarch64-apple-ios',
      ('ios', 'x64') => 'x86_64-apple-ios',
      _ => null,
    };

/// The cargo features [triple] is built with. Apple Silicon gets the Metal
/// backend, which stays off until `STARK_KERNELS_GPU` asks for it, so
/// building it in costs nothing on a machine that never does. Intel Macs do
/// not: the backend is written for Apple Silicon's unified memory.
List<String> cargoFeatures(String triple) => triple == 'aarch64-apple-darwin' ? const ['metal'] : const [];

/// The rustc flags [triple] is built with, prebuilt or from source alike: an
/// `@rpath` install name on Apple platforms, where rustc would otherwise
/// record the path it was built at and every app bundling it would carry that
/// path, with the most header room the linker allows, since `dart test` and
/// `dart run` rewrite that name to the library's absolute path under
/// `.dart_tool/lib` and without it a path past about 87 characters does not
/// fit; the C runtime linked statically on Windows, so the library needs no
/// Visual C++ redistributable; and 16 KB page alignment on 64-bit Android,
/// which Android 15 devices with 16 KB pages require of every native library.
List<String> rustFlags(String triple) => [
      if (triple.contains('-apple-')) ...[
        '-C',
        'link-arg=-Wl,-install_name,@rpath/libstark_kernels.dylib',
        '-C',
        'link-arg=-Wl,-headerpad_max_install_names',
      ],
      if (triple.endsWith('-windows-msvc')) ...['-C', 'target-feature=+crt-static'],
      if (triple == 'aarch64-linux-android' || triple == 'x86_64-linux-android')
        ...['-C', 'link-arg=-Wl,-z,max-page-size=16384'],
    ];

/// The name of cargo's per-target environment variable [what] for [triple],
/// e.g. `CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS`.
String cargoTargetEnv(String triple, String what) =>
    'CARGO_TARGET_${triple.toUpperCase().replaceAll('-', '_')}_$what';

/// The key a target is listed under in the manifest, e.g. `macos_arm64`.
String targetKey(String os, String arch, {bool iosSimulator = false}) =>
    '${os}_$arch${iosSimulator ? '_simulator' : ''}';

/// The library's file name on [os], the name the loader looks for.
String libraryFileName(String os) => switch (os) {
      'macos' || 'ios' => 'libstark_kernels.dylib',
      'windows' => 'stark_kernels.dll',
      _ => 'libstark_kernels.so',
    };

/// The name a target's library is uploaded under in a release, where every
/// target's file sits side by side.
String releaseFileName(String key, String os) {
  final name = libraryFileName(os);
  final dot = name.lastIndexOf('.');
  return '${name.substring(0, dot)}-$key${name.substring(dot)}';
}
