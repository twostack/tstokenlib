/// The test chain lives in `lib/src/testing/` now, so a package built on
/// tstokenlib can build the same two rounds as transactions
/// (`package:tstokenlib/testing.dart`). This re-export keeps the suite's
/// `import 'pool_test_chain.dart'` working.
export 'package:tstokenlib/src/testing/pool_test_chain.dart';
