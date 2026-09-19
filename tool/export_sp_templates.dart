/// Exports the PP1_SP templates (state script for one K, verifier slot,
/// append slot) into templates/sp/. Separate from export_templates.dart
/// while the pool is private exploration.
import 'dart:convert';
import 'dart:io';
import 'package:convert/convert.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';
import 'package:tstokenlib/src/script_gen/pp1_sp_script_gen.dart';

const version = '1.3.0';

/// The parameters the templates are generated for.
const spParams = PoolSpendAir.productionParams;
const spK = 8;

void main() {
  exportPP1Sp(spK);
  print('Done. Templates written to templates/sp/');
}

Map<String, dynamic> _params() => {
      'logTrace': spParams.logTrace,
      'logBlowup': spParams.logBlowup,
      'logExpand': spParams.logExpand,
      'logFinal': spParams.logFinal,
      'numQueries': spParams.numQueries,
      'grindBytes': spParams.grindBytes,
      'zkRandomizers': spParams.zkRandomizers,
    };

void write(String path, Map<String, dynamic> d) {
  final f = File(path);
  f.parent.createSync(recursive: true);
  f.writeAsStringSync('${JsonEncoder.withIndent('  ').convert(d)}\n');
  print('  Wrote $path (${f.lengthSync()} bytes)');
}

void exportPP1Sp(int k) {
  final gen = PP1SpScriptGen(spParams, k: k);
  // sentinel header
  final h = PP1SpHeader(
    tokenId: List.filled(32, 0xBB),
    rabinPubKeyHash: List.filled(20, 0x99),
    phase: 1,
    ring: [for (int r = 0; r < 4; r++) List.filled(32, 0xA0 + r)],
    size: 0x44444444,
    nfRoot: List.filled(32, 0xEE),
  );
  var hex_ = hex.encode(gen.lock(h).buffer);
  String field(int prefix, List<int> sentinel, String name) {
    final s = hex.encode([prefix, ...sentinel]);
    if (!hex_.contains(s)) throw Exception('sentinel for $name not found');
    return s;
  }
  hex_ = hex_.replaceFirst(field(32, List.filled(32, 0xBB), 'tokenId'), '20{{tokenId}}');
  hex_ = hex_.replaceFirst(field(20, List.filled(20, 0x99), 'rabinPubKeyHash'), '14{{rabinPubKeyHash}}');
  if (!hex_.contains('{{rabinPubKeyHash}}0101')) throw Exception('phase not found');
  hex_ = hex_.replaceFirst('{{rabinPubKeyHash}}0101', '{{rabinPubKeyHash}}01{{phase}}');
  for (int r = 0; r < 4; r++) {
    hex_ = hex_.replaceFirst(field(32, List.filled(32, 0xA0 + r), 'ring$r'), '20{{ring$r}}');
  }
  hex_ = hex_.replaceFirst(field(4, [0x44, 0x44, 0x44, 0x44], 'size'), '04{{size}}');
  hex_ = hex_.replaceFirst(field(32, List.filled(32, 0xEE), 'nfRoot'), '20{{nfRoot}}');
  write('templates/sp/pp1_sp_k$k.json', {
    'name': 'PP1_SP',
    'version': version,
    'description': 'Shielded pool state script for rounds of up to $k transfers. 226-byte header with 9 fields; '
        'body bakes in the SHA256 of the verifier and append slot scripts.',
    'category': 'sp',
    'k': k,
    'stark': _params(),
    'verifierSlotHash': hex.encode(gen.verifierHash),
    'appendSlotHash': hex.encode(gen.appendHash),
    'parameters': [
      {'name': 'tokenId', 'size': 32, 'encoding': 'hex', 'description': 'txid whose output 0 the genesis spends (immutable)'},
      {'name': 'rabinPubKeyHash', 'size': 20, 'encoding': 'hex', 'description': "hash160 of the operator's Rabin n (immutable)"},
      {'name': 'phase', 'size': 1, 'encoding': 'hex', 'description': '00 issued, 01 live (mutable)'},
      for (int r = 0; r < 4; r++)
        {'name': 'ring$r', 'size': 32, 'encoding': 'hex', 'description': 'commitment root, ring0 current (mutable)'},
      {'name': 'size', 'size': 4, 'encoding': 'hex', 'description': 'leaves in the tree, LE (mutable)'},
      {'name': 'nfRoot', 'size': 32, 'encoding': 'hex', 'description': 'nullifier set root (mutable)'},
    ],
    'hex': hex_,
  });
  write('templates/sp/pp1_sp_verifier.json', {
    'name': 'PP1_SP_VERIFIER',
    'version': version,
    'description': 'Verifier slot: verifies one spend proof (selector 1) or skips (selector 0); SIGHASH_SINGLE result output.',
    'category': 'sp',
    'stark': _params(),
    'parameters': [],
    'hex': hex.encode(gen.verifierBytes),
  });
  write('templates/sp/pp1_sp_append.json', {
    'name': 'PP1_SP_APPEND',
    'version': version,
    'description': 'Subtree-append slot: Poseidon2 subtree of 32 commitments appended over 27 main levels; SIGHASH_SINGLE result output.',
    'category': 'sp',
    'parameters': [],
    'hex': hex.encode(gen.appendBytes),
  });
}
