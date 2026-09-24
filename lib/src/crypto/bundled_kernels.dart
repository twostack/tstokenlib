/*
  Copyright 2026 - Stephan M. February

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

/// Where the build hook's copy of the kernels is on disk.
///
/// `hook/build.dart` bundles the library as the code asset
/// `package:tstokenlib/stark_kernels`, and the SDK puts it wherever the
/// program being run keeps its assets: under `.dart_tool` for `dart run` and
/// `dart test`, beside the executable for `dart build`, inside the app for
/// Flutter. The SDK can resolve a native symbol in that asset but has no API
/// that names the file. So this binds one symbol through the asset, takes its
/// address, and asks the platform's loader which file that address is in.
/// [StarkKernels.tryLoad] then opens that path like any other candidate,
/// which gets the same handle the SDK already holds, and checks its ABI
/// version the same way.
library;

import 'dart:ffi' as ffi;
import 'dart:io';

import 'package:ffi/ffi.dart';

@ffi.Native<ffi.Uint32 Function()>(symbol: 'sk_version', assetId: 'package:tstokenlib/stark_kernels')
external int _bundledVersion();

/// The bundled library's path, or null when there is no bundled asset (the
/// hook was told to skip, or the program was built without hooks) or the
/// platform will not say.
String? bundledKernelsPath() {
  try {
    final address = ffi.Native.addressOf<ffi.NativeFunction<ffi.Uint32 Function()>>(_bundledVersion);
    return Platform.isWindows ? _windowsModuleOf(address.cast()) : _posixLibraryOf(address.cast());
  } catch (_) {
    return null;
  }
}

final class _DlInfo extends ffi.Struct {
  external ffi.Pointer<Utf8> fname;
  external ffi.Pointer<ffi.Void> fbase;
  external ffi.Pointer<Utf8> sname;
  external ffi.Pointer<ffi.Void> saddr;
}

typedef _DladdrC = ffi.Int32 Function(ffi.Pointer<ffi.Void>, ffi.Pointer<_DlInfo>);
typedef _DladdrD = int Function(ffi.Pointer<ffi.Void>, ffi.Pointer<_DlInfo>);

String? _posixLibraryOf(ffi.Pointer<ffi.Void> address) {
  // in libc on macOS and on glibc from 2.34; in libdl before that
  _DladdrD? dladdr;
  for (final open in [ffi.DynamicLibrary.process, () => ffi.DynamicLibrary.open('libdl.so.2')]) {
    try {
      dladdr = open().lookupFunction<_DladdrC, _DladdrD>('dladdr');
      break;
    } catch (_) {
      continue;
    }
  }
  if (dladdr == null) return null;
  final info = calloc<_DlInfo>();
  try {
    if (dladdr(address, info) == 0 || info.ref.fname == ffi.nullptr) return null;
    return info.ref.fname.toDartString();
  } finally {
    calloc.free(info);
  }
}

typedef _GetModuleHandleExC = ffi.Int32 Function(ffi.Uint32, ffi.Pointer<ffi.Void>, ffi.Pointer<ffi.Pointer<ffi.Void>>);
typedef _GetModuleHandleExD = int Function(int, ffi.Pointer<ffi.Void>, ffi.Pointer<ffi.Pointer<ffi.Void>>);
typedef _GetModuleFileNameC = ffi.Uint32 Function(ffi.Pointer<ffi.Void>, ffi.Pointer<Utf16>, ffi.Uint32);
typedef _GetModuleFileNameD = int Function(ffi.Pointer<ffi.Void>, ffi.Pointer<Utf16>, int);

String? _windowsModuleOf(ffi.Pointer<ffi.Void> address) {
  const fromAddress = 0x4, unchangedRefcount = 0x2, capacity = 32768;
  final kernel32 = ffi.DynamicLibrary.open('kernel32.dll');
  final handleEx = kernel32.lookupFunction<_GetModuleHandleExC, _GetModuleHandleExD>('GetModuleHandleExW');
  final fileName = kernel32.lookupFunction<_GetModuleFileNameC, _GetModuleFileNameD>('GetModuleFileNameW');
  final module = calloc<ffi.Pointer<ffi.Void>>();
  final buffer = calloc<ffi.Uint16>(capacity).cast<Utf16>();
  try {
    if (handleEx(fromAddress | unchangedRefcount, address, module) == 0) return null;
    final n = fileName(module.value, buffer, capacity);
    return n == 0 ? null : buffer.toDartString(length: n);
  } finally {
    calloc.free(module);
    calloc.free(buffer);
  }
}
