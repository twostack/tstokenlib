/// The fixture now lives in `lib/src/testing/`, so packages built on
/// tstokenlib can prove the same two-round chain (`package:tstokenlib/testing.dart`).
/// This re-export keeps the suite's `import 'pool_chain_fixture.dart'` working
/// and carries the parameter names the older tests use.
export 'package:tstokenlib/src/testing/pool_chain_fixture.dart';
