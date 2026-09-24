import 'dart:io';
import '../hook/kernel_source.dart';
void main() => print(sourceHash(Directory('native/stark_kernels/')));
