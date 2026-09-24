/// Writes `native/prebuilt.json` for a directory of released kernel libraries.
///
///     dart tool/kernels/prebuilt_manifest.dart <dist-dir> <base-url>
///
/// Every file in `<dist-dir>` named as `releaseFileName` names one is listed
/// under its target key with its SHA-256, against the hash of the crate
/// source in this checkout, which must be the source the files were built
/// from. The manifest goes to stdout.
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart' as crypto;

import '../../lib/src/native/kernel_source.dart';

void main(List<String> args) {
  if (args.length != 2) {
    stderr.writeln('usage: dart tool/kernels/prebuilt_manifest.dart <dist-dir> <base-url>');
    exit(64);
  }
  final named = RegExp(r'^(?:lib)?stark_kernels-([a-z0-9_]+)\.(?:dylib|so|dll)$');
  final files = Directory(args[0]).listSync().whereType<File>().toList()
    ..sort((a, b) => a.path.compareTo(b.path));
  final assets = <String, Object>{};
  for (final f in files) {
    final name = f.uri.pathSegments.last;
    final key = named.firstMatch(name)?.group(1);
    if (key == null) continue;
    if (releaseFileName(key, key.split('_').first) != name) {
      stderr.writeln('$name is not the release name for $key');
      exit(65);
    }
    assets[key] = {'file': name, 'sha256': crypto.sha256.convert(f.readAsBytesSync()).toString()};
  }
  if (assets.isEmpty) {
    stderr.writeln('no kernel libraries in ${args[0]}');
    exit(66);
  }
  final base = args[1].endsWith('/') ? args[1] : '${args[1]}/';
  stdout.writeln(const JsonEncoder.withIndent('  ').convert({
    'source_sha256': sourceHash(Directory('$crateDir/')),
    'base_url': base,
    'assets': assets,
  }));
}
