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

/// The pool's test chain, for packages built on tstokenlib.
///
/// A wallet, a coordinator server or a tool cannot be tested against a real
/// pool without proving one, and a pool proved at production parameters takes
/// minutes on a machine with a GPU. [PoolChainFixture] proves a two-round pool
/// at [PoolTestParams] in a few seconds: a deposit, a payment to a wallet the
/// caller holds the keys of, a withdrawal, real notes with real ciphertexts,
/// and headers a ledger applies.
///
/// [PoolTestChain] takes that fixture and builds the two rounds as
/// transactions — issuance, witness 0, the slots, the depositor's covenant,
/// and both rounds with their witnesses — which is what a wallet or a server
/// actually reads. [PoolTestKeys] holds the published regtest keys it is built
/// from, so the chain comes out byte-identical everywhere.
///
/// This is a separate entry point so nothing here is pulled into a wallet that
/// only imports `tstokenlib.dart`.
library;

export 'src/testing/pool_chain_fixture.dart' show PoolChainFixture, PoolTestParams;
export 'src/testing/pool_test_chain.dart' show PoolTestChain, PoolTestKeys;
