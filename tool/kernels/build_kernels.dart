/// Builds the native kernels for one prebuilt target and copies the library
/// into a directory under the name it is released as.
///
///     dart tool/kernels/build_kernels.dart <key> [out-dir]
///
/// `<key>` is a manifest key such as `macos_arm64` or `ios_arm64_simulator`.
/// This is what `.github/workflows/stark-kernels.yml` runs on each runner,
/// and it takes its triple, features and flags from `hook/kernel_source.dart`,
/// so a prebuilt library is built exactly as the hook would build it from
/// source. Two things only CI does: Linux is built with `cargo zigbuild`
/// against glibc 2.17, so one library loads on every distribution still in
/// support, and Android links with the NDK in `$ANDROID_NDK_LATEST_HOME`.
import 'dart:io';

import '../../hook/kernel_source.dart';

const _glibc = '2.17';
const _androidApi = 21;
const _deploymentTargets = {
  'x86_64-apple-darwin': ('MACOSX_DEPLOYMENT_TARGET', '10.15'),
  'aarch64-apple-darwin': ('MACOSX_DEPLOYMENT_TARGET', '11.0'),
  'aarch64-apple-ios': ('IPHONEOS_DEPLOYMENT_TARGET', '13.0'),
  'aarch64-apple-ios-sim': ('IPHONEOS_DEPLOYMENT_TARGET', '13.0'),
  'x86_64-apple-ios': ('IPHONEOS_DEPLOYMENT_TARGET', '13.0'),
};

Future<void> main(List<String> args) async {
  if (args.isEmpty) {
    stderr.writeln('usage: dart tool/kernels/build_kernels.dart <key> [out-dir]');
    exit(64);
  }
  final key = args[0];
  final out = Directory(args.length > 1 ? args[1] : 'dist');
  final parts = key.split('_');
  final os = parts[0], arch = parts[1];
  final simulator = parts.length > 2 && parts[2] == 'simulator';
  final triple = rustTriple(os, arch, iosSimulator: simulator);
  if (triple == null || targetKey(os, arch, iosSimulator: simulator) != key) {
    stderr.writeln('no Rust target for $key');
    exit(64);
  }

  final environment = <String, String>{
    if (_deploymentTargets[triple] case (final name, final version)) name: version,
    if (rustFlags(triple).isNotEmpty) cargoTargetEnv(triple, 'RUSTFLAGS'): rustFlags(triple).join(' '),
    if (os == 'android') cargoTargetEnv(triple, 'LINKER'): _androidLinker(triple),
  };
  final features = cargoFeatures(triple);
  final command = [
    os == 'linux' ? 'zigbuild' : 'build',
    '--release',
    '--locked',
    '--manifest-path',
    '$crateDir/Cargo.toml',
    '--target',
    os == 'linux' ? '$triple.$_glibc' : triple,
    if (features.isNotEmpty) ...['--features', features.join(',')],
  ];
  stdout.writeln('cargo ${command.join(' ')}  ${environment.entries.map((e) => '${e.key}=${e.value}').join(' ')}');
  final cargo = await Process.start('cargo', command, environment: environment, mode: ProcessStartMode.inheritStdio);
  final code = await cargo.exitCode;
  if (code != 0) exit(code);

  out.createSync(recursive: true);
  final built = File('$crateDir/target/$triple/release/${libraryFileName(os)}');
  final released = built.copySync('${out.path}/${releaseFileName(key, os)}');
  stdout.writeln('${released.path} (${released.lengthSync()} bytes)');
}

/// The NDK's clang for [triple] at [_androidApi], which is what cargo has to
/// link an Android library with.
String _androidLinker(String triple) {
  final ndk = Platform.environment['ANDROID_NDK_LATEST_HOME'] ?? Platform.environment['ANDROID_NDK_HOME'];
  if (ndk == null) {
    stderr.writeln('set ANDROID_NDK_LATEST_HOME or ANDROID_NDK_HOME to build for Android');
    exit(69);
  }
  final host = Platform.isMacOS ? 'darwin-x86_64' : 'linux-x86_64';
  final clang = triple == 'armv7-linux-androideabi' ? 'armv7a-linux-androideabi' : triple;
  return '$ndk/toolchains/llvm/prebuilt/$host/bin/$clang$_androidApi-clang';
}
