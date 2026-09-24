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

/// Puts the native STARK kernels in every program that depends on tstokenlib.
///
/// The prover is only practical with them, so they are not left to a
/// consumer to build and point `STARK_KERNELS_LIB` at. For the target being
/// built this hook either downloads the prebuilt library published for the
/// crate's exact source, checked against the SHA-256 in `prebuilt.json`, or
/// builds the crate with cargo. Either way the result is a bundled code
/// asset, which `dart run`, `dart test` and `dart build` all pick up, and
/// `StarkKernels.tryLoad` finds.
///
/// One user-define, set in the application's pubspec, chooses how:
///
///     hooks:
///       user_defines:
///         tstokenlib:
///           stark_kernels: auto     # prebuilt if listed, else cargo (default)
///           # stark_kernels: source # always cargo; never download
///           # stark_kernels: skip   # no kernels; proving falls back to Dart
///
/// A build that can do neither fails rather than quietly shipping without
/// them, and says which of the three to reach for.
library;

import 'dart:convert';
import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:hooks/hooks.dart';

import 'kernel_source.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    if (!input.config.buildCodeAssets) return;
    final mode = (input.userDefines['stark_kernels'] as String?) ?? 'auto';
    if (!const ['auto', 'source', 'skip'].contains(mode)) {
      throw BuildError(message: 'tstokenlib: stark_kernels is "$mode"; it takes auto, source or skip');
    }
    if (mode == 'skip') return;

    final code = input.config.code;
    final os = code.targetOS.name;
    final arch = code.targetArchitecture.name;
    final simulator = code.targetOS == OS.iOS && code.iOS.targetSdk == IOSSdk.iPhoneSimulator;
    final key = targetKey(os, arch, iosSimulator: simulator);

    final crateRoot = Directory.fromUri(input.packageRoot.resolve('$crateDir/'));
    final manifestUri = input.packageRoot.resolve('hook/prebuilt.json');
    output.dependencies
      ..add(manifestUri)
      ..addAll([for (final f in crateFiles(crateRoot)) crateRoot.uri.resolve(f)]);

    final hash = sourceHash(crateRoot);
    File? library;
    String? downloadFailure;
    if (mode == 'auto') {
      final prebuilt = _prebuiltFor(File.fromUri(manifestUri), hash, key);
      if (prebuilt != null) {
        try {
          library = await _download(prebuilt, input.outputDirectoryShared, hash, key, os);
        } on Object catch (e) {
          downloadFailure = '$e';
        }
      }
    }
    library ??= await _cargoBuild(
      crateRoot: crateRoot,
      input: input,
      triple: rustTriple(os, arch, iosSimulator: simulator),
      key: key,
      os: os,
      downloadFailure: downloadFailure,
    );

    output.assets.code.add(CodeAsset(
      package: input.packageName,
      name: 'stark_kernels',
      linkMode: DynamicLoadingBundled(),
      file: library.uri,
    ));
  });
}

typedef _Prebuilt = ({Uri url, String sha256});

/// The published library for [key], or null when the manifest was written
/// for other source (the crate has been edited) or lists no build for it.
_Prebuilt? _prebuiltFor(File manifest, String hash, String key) {
  if (!manifest.existsSync()) return null;
  final json = jsonDecode(manifest.readAsStringSync()) as Map<String, dynamic>;
  if (json['source_sha256'] != hash) return null;
  final entry = (json['assets'] as Map<String, dynamic>? ?? const {})[key] as Map<String, dynamic>?;
  if (entry == null) return null;
  final base = Uri.parse(json['base_url'] as String);
  return (url: base.resolve(entry['file'] as String), sha256: entry['sha256'] as String);
}

/// Fetches [prebuilt] into the shared output directory, once per source hash
/// and target, and refuses it unless its SHA-256 is the manifest's.
Future<File> _download(_Prebuilt prebuilt, Uri shared, String hash, String key, String os) async {
  final dir = Directory.fromUri(shared.resolve('prebuilt/${hash.substring(0, 16)}/$key/'));
  final file = File.fromUri(dir.uri.resolve(libraryFileName(os)));
  if (file.existsSync() && _sha256(file) == prebuilt.sha256) return file;

  dir.createSync(recursive: true);
  final partial = File('${file.path}.part');
  final client = HttpClient();
  try {
    final request = await client.getUrl(prebuilt.url);
    final response = await request.close();
    if (response.statusCode != HttpStatus.ok) {
      throw HttpException('HTTP ${response.statusCode}', uri: prebuilt.url);
    }
    await response.pipe(partial.openWrite());
  } finally {
    client.close();
  }
  final got = _sha256(partial);
  if (got != prebuilt.sha256) {
    partial.deleteSync();
    throw StateError('${prebuilt.url} has SHA-256 $got, expected ${prebuilt.sha256}');
  }
  return partial.renameSync(file.path);
}

String _sha256(File f) => crypto.sha256.convert(f.readAsBytesSync()).toString();

/// Builds the crate for [triple] into the shared output directory, so cargo's
/// own incremental cache survives from one run of the hook to the next.
Future<File> _cargoBuild({
  required Directory crateRoot,
  required BuildInput input,
  required String? triple,
  required String key,
  required String os,
  required String? downloadFailure,
}) async {
  String why(String problem) => [
        'tstokenlib: the native STARK kernels for $key could not be provided. $problem',
        if (downloadFailure != null) 'The prebuilt download failed first: $downloadFailure',
        'Install Rust (https://rustup.rs) to build them from source, or set '
            'hooks: user_defines: tstokenlib: stark_kernels: skip in your pubspec '
            'to go without them (the prover then runs in Dart, far slower).',
      ].join('\n');

  if (triple == null) throw BuildError(message: why('There is no Rust target for $key.'));

  final targetDir = Directory.fromUri(input.outputDirectoryShared.resolve('cargo/'));
  final code = input.config.code;
  final environment = <String, String>{
    if (code.targetOS == OS.macOS) 'MACOSX_DEPLOYMENT_TARGET': '${code.macOS.targetVersion}',
    if (code.targetOS == OS.iOS) 'IPHONEOS_DEPLOYMENT_TARGET': '${code.iOS.targetVersion}',
    if (code.targetOS == OS.android && code.cCompiler != null)
      cargoTargetEnv(triple, 'LINKER'): code.cCompiler!.linker.toFilePath(),
    if (rustFlags(triple).isNotEmpty) cargoTargetEnv(triple, 'RUSTFLAGS'): rustFlags(triple).join(' '),
  };
  final features = cargoFeatures(triple);
  final ProcessResult result;
  try {
    result = await Process.run(
      'cargo',
      [
        'build',
        '--release',
        '--manifest-path',
        crateRoot.uri.resolve('Cargo.toml').toFilePath(),
        '--target',
        triple,
        '--target-dir',
        targetDir.path,
        if (features.isNotEmpty) ...['--features', features.join(',')],
      ],
      environment: environment,
    );
  } on ProcessException {
    throw BuildError(message: why('No prebuilt library could be used for this source and target, and cargo is not on the PATH.'));
  }
  if (result.exitCode != 0) {
    throw BuildError(
      message: why('cargo build --target $triple failed '
          '(if the target is missing: rustup target add $triple):\n${result.stderr}'),
    );
  }
  return File.fromUri(targetDir.uri.resolve('$triple/release/${libraryFileName(os)}'));
}
