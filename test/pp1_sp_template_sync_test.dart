import 'dart:convert';
import 'dart:io';
import 'package:convert/convert.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/script_gen/pp1_sp_script_gen.dart';

/// The committed PP1_SP templates must match the generators.
void main() {
  test('PP1_SP templates round-trip', () {
    final state = jsonDecode(File('templates/sp/pp1_sp_k8.json').readAsStringSync());
    final st = state['stark'];
    final p = StarkParams(
        logTrace: st['logTrace'], logBlowup: st['logBlowup'], logExpand: st['logExpand'], logFinal: st['logFinal'],
        numQueries: st['numQueries'], grindBytes: st['grindBytes'], zkRandomizers: st['zkRandomizers']);
    final gen = PP1SpScriptGen(p, k: state['k']);
    final h = PP1SpHeader(
      tokenId: List.generate(32, (i) => i + 1),
      rabinPubKeyHash: List.generate(20, (i) => i + 0x40),
      phase: 1,
      ring: [for (int r = 0; r < 4; r++) List.generate(32, (i) => (i * 7 + r) & 0xff)],
      size: 96,
      nfRoot: List.generate(32, (i) => 0xff - i),
    );
    var hx = state['hex'] as String;
    hx = hx
        .replaceFirst('{{tokenId}}', hex.encode(h.tokenId))
        .replaceFirst('{{rabinPubKeyHash}}', hex.encode(h.rabinPubKeyHash))
        .replaceFirst('{{phase}}', '01')
        .replaceFirst('{{size}}', hex.encode([96, 0, 0, 0]))
        .replaceFirst('{{nfRoot}}', hex.encode(h.nfRoot));
    for (int r = 0; r < 4; r++) {
      hx = hx.replaceFirst('{{ring$r}}', hex.encode(h.ring[r]));
    }
    expect(hx, hex.encode(gen.lock(h).buffer));
    expect(state['verifierSlotHash'], hex.encode(gen.verifierHash));
    expect(state['appendSlotHash'], hex.encode(gen.appendHash));
    final v = jsonDecode(File('templates/sp/pp1_sp_verifier.json').readAsStringSync());
    expect(v['hex'], hex.encode(gen.verifierBytes));
    final a = jsonDecode(File('templates/sp/pp1_sp_append.json').readAsStringSync());
    expect(a['hex'], hex.encode(gen.appendBytes));
  }, timeout: const Timeout(Duration(minutes: 5)));
}
