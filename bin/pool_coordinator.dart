/*
  Copyright 2024 - Stephan M. February

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

import 'dart:convert';
import 'dart:io';
import 'package:dartsv/dartsv.dart';
import 'package:tstokenlib/src/transaction/pool_coordinator.dart';
import 'package:tstokenlib/src/transaction/shielded_pool_tool.dart';

/// Runs a shielded pool from a configuration file.
///
///   dart run bin/pool_coordinator.dart <config.json> [--check]
///
/// The file says what the pool is (mode, the aggregation plan and its
/// parameters, the round deadline and the padding stock) and where its
/// history is: a file of the genesis transaction in hex and one per round
/// published since. The coordinator rebuilds its ledger from those, since
/// the chain is the source of truth and nothing here is persisted.
///
/// There is no transport yet, so submissions cannot arrive and published
/// rounds are written next to the history rather than broadcast. `--check`
/// stops after printing what it would run, which is how a deployment is
/// verified before it serves anything.
Future<int> run(List<String> args, {void Function(String) out = print}) async {
  final paths = [for (final a in args) if (!a.startsWith('--')) a];
  if (paths.isEmpty) {
    out('usage: pool_coordinator <config.json> [--check]');
    return 64;
  }
  final configFile = File(paths.first);
  if (!configFile.existsSync()) {
    out('no such configuration file: ${configFile.path}');
    return 66;
  }
  final dir = configFile.parent;
  File relative(String p) => File(p).isAbsolute ? File(p) : File('${dir.path}${Platform.pathSeparator}$p');

  final CoordinatorFile described;
  try {
    described = CoordinatorFile.parse(jsonDecode(configFile.readAsStringSync()) as Map<String, dynamic>);
  } catch (e) {
    out('the configuration could not be read: $e');
    return 65;
  }

  Transaction readTx(String p) => Transaction.fromHex(relative(p).readAsStringSync().trim());
  final PoolLedger ledger;
  try {
    ledger = PoolCoordinator.recover(described.gen, readTx(described.genesis), [for (final r in described.rounds) readTx(r)]);
  } catch (e) {
    out('the ledger could not be rebuilt from the chain: $e');
    return 65;
  }

  final published = <Transaction>[];
  final PoolCoordinator coordinator;
  try {
    coordinator = PoolCoordinator(
      config: described.config,
      tool: ShieldedPoolTool(described.gen),
      ledger: ledger,
      publish: (tx) async {
        published.add(tx);
        final at = relative('round-${published.length + described.rounds.length}.hex');
        at.writeAsStringSync(tx.serialize());
        out('round ${published.length} published: ${tx.id} (${at.path})');
      },
    );
  } on StateError catch (e) {
    out('this coordinator does not match the pool it was pointed at: ${e.message}');
    return 65;
  }

  out('pool ${described.gen.aggregated ? 'aggregated' : 'direct-slot'}, '
      '${described.config.plan?.transfers ?? described.gen.k} transfers per round');
  out('ledger rebuilt from ${described.rounds.length} round${described.rounds.length == 1 ? '' : 's'}: '
      'vault ${ledger.vault} sat, tree ${ledger.tree.size} leaves, state ${ledger.tx.id}');
  out('${coordinator.status}');

  if (args.contains('--check')) {
    out('--check: not serving');
    return 0;
  }
  out('idle work: filling the padding stock to ${described.config.paddingStock}');
  await coordinator.runIdleWork();
  out('${coordinator.status}');
  out('no transport is wired yet, so nothing can be submitted; stopping');
  return 0;
}

Future<void> main(List<String> args) async {
  exitCode = await run(args);
}
