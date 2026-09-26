import 'dart:io';

import 'package:crypto/crypto.dart' as crypto;
import 'package:test/test.dart';
import 'package:tstokenlib/src/native/kernel_source.dart';

void main() {
  test('every target the hook can meet is in the recipe', () {
    const targets = [
      ('macos', 'arm64', false), ('macos', 'x64', false),
      ('linux', 'x64', false), ('linux', 'arm64', false),
      ('windows', 'x64', false), ('windows', 'arm64', false),
      ('android', 'arm64', false), ('android', 'arm', false), ('android', 'x64', false),
      ('ios', 'arm64', false), ('ios', 'arm64', true), ('ios', 'x64', false),
    ];
    final triples = {for (final (os, arch, sim) in targets) rustTriple(os, arch, iosSimulator: sim)!};
    expect(triples, buildTriples.toSet());
  });

  test('Apple libraries leave the most header room for their install name', () {
    for (final t in buildTriples.where((t) => t.contains('-apple-'))) {
      expect(rustFlags(t), contains('link-arg=-Wl,-headerpad_max_install_names'), reason: t);
    }
  });

  test('the hash covers the build recipe, not only the files', () {
    final crate = Directory('$crateDir/');
    final files = <int>[];
    for (final rel in crateFiles(crate)) {
      files
        ..addAll('$rel\n'.codeUnits)
        ..addAll(File('$crateDir/$rel').readAsStringSync().replaceAll('\r\n', '\n').codeUnits)
        ..add(0);
    }
    expect(sourceHash(crate), crypto.sha256.convert([...files, ...buildRecipe().codeUnits]).toString());
    expect(sourceHash(crate), isNot(crypto.sha256.convert(files).toString()));
  });

  test('the hook-built library takes an install name of about 200 characters', () {
    final built = File('.dart_tool/lib/libstark_kernels.dylib');
    if (!built.existsSync()) return markTestSkipped('no hook-built library at ${built.path}');
    final dir = Directory.systemTemp.createTempSync('headerpad');
    addTearDown(() => dir.deleteSync(recursive: true));
    final copy = built.copySync('${dir.path}/libstark_kernels.dylib');
    final longName = '/${'x' * 170}/lib/libstark_kernels.dylib';
    final r = Process.runSync('install_name_tool', ['-id', longName, copy.path]);
    expect(r.exitCode, 0, reason: '${r.stderr}');
    expect(Process.runSync('otool', ['-D', copy.path]).stdout, contains(longName));
  }, testOn: 'mac-os');
}
