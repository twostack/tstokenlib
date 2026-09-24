import 'package:tstokenlib/src/crypto/stark_kernels.dart';

/// Compiled by stark_kernels_test.dart into a standalone executable, to check
/// where an installed program finds the library. Prints the loaded path, or
/// `none`.
void main() => print(StarkKernels.tryLoad()?.path ?? 'none');
