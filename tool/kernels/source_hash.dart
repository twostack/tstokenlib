/// Prints the SHA-256 of the kernel crate's source, as the build hook
/// computes it. Run from the package root.
import 'dart:io';

import '../../lib/src/native/kernel_source.dart';

void main() => print(sourceHash(Directory('$crateDir/')));
