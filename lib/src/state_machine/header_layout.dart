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

import 'definition.dart';

/// Layout information for a single header field.
class HeaderFieldLayout {
  final String name;
  final int offset;
  final int dataStart;
  final int dataEnd;
  final int pushdataByte;
  final bool isMutable;

  const HeaderFieldLayout({
    required this.name,
    required this.offset,
    required this.dataStart,
    required this.dataEnd,
    required this.pushdataByte,
    required this.isMutable,
  });

  int get byteSize => dataEnd - dataStart;
  int get totalSize => 1 + byteSize; // pushdata prefix + data
}

/// Describes the mutable region within a header for script rebuild operations.
class MutableRegion {
  final String fieldName;
  final int dataStart;
  final int dataEnd;

  const MutableRegion({
    required this.fieldName,
    required this.dataStart,
    required this.dataEnd,
  });
}

/// Complete header layout for a state machine definition.
class HeaderLayout {
  final List<HeaderFieldLayout> fields;
  final int totalHeaderSize;
  final List<String> altstackOrder;
  final List<MutableRegion> mutableRegions;

  const HeaderLayout({
    required this.fields,
    required this.totalHeaderSize,
    required this.altstackOrder,
    required this.mutableRegions,
  });

  HeaderFieldLayout getField(String name) {
    return fields.firstWhere(
      (f) => f.name == name,
      orElse: () => throw ArgumentError('No field named "$name" in layout'),
    );
  }
}

/// Computes the byte-level header layout from a [StateMachineDefinition].
///
/// The layout algorithm places fields in a fixed order:
/// 1. ownerPKH (20 bytes, mutable)
/// 2. tokenId (32 bytes, immutable)
/// 3. Role PKHs (20 bytes each, immutable, in definition order)
/// 4. currentState (1 byte, mutable)
/// 5. Custom mutable fields (in definition order)
/// 6. commitmentHash (32 bytes, mutable)
/// 7. transitionBitmask (1-2 bytes, immutable)
/// 8. Custom immutable fields (in definition order)
/// 9. timeoutDelta (4 bytes, immutable) — only if any transition uses timelock
class HeaderLayoutEngine {

  HeaderLayout compute(StateMachineDefinition def) {
    final fields = <HeaderFieldLayout>[];
    final altstackOrder = <String>[];
    final mutableRegions = <MutableRegion>[];
    int offset = 0;

    // Helper to add a field
    void addField(String name, int byteSize, bool mutable) {
      int pushdata = _pushdataByte(byteSize);
      int dataStart = offset + 1; // 1 byte for pushdata prefix
      int dataEnd = dataStart + byteSize;
      fields.add(HeaderFieldLayout(
        name: name,
        offset: offset,
        dataStart: dataStart,
        dataEnd: dataEnd,
        pushdataByte: pushdata,
        isMutable: mutable,
      ));
      altstackOrder.add(name);
      if (mutable) {
        mutableRegions.add(MutableRegion(
          fieldName: name,
          dataStart: dataStart,
          dataEnd: dataEnd,
        ));
      }
      offset = dataEnd;
    }

    // 1. ownerPKH — always first, 20 bytes, mutable
    addField('ownerPKH', 20, true);

    // 2. tokenId — always second, 32 bytes, immutable
    addField('tokenId', 32, false);

    // 3. Role PKHs — 20 bytes each, immutable, in definition order
    for (final role in def.roles.values) {
      if (role.authType == AuthType.PKH || role.authType == AuthType.Rabin) {
        addField('${role.name}PKH', 20, false);
      }
      // Rabin_Oracle roles would use larger keys — handled in future phases
    }

    // 4. currentState — 1 byte, mutable
    addField('currentState', 1, true);

    // 5. Custom mutable fields — in definition order
    for (final field in def.customFields.values) {
      if (field.isMutable) {
        addField(field.name, field.byteSize, true);
      }
    }

    // 6. commitmentHash — 32 bytes, mutable
    addField('commitmentHash', 32, true);

    // 7. transitionBitmask — 1 byte (for ≤8 transitions) or 2 bytes, immutable
    int bitmaskSize = def.transitions.length <= 8 ? 1 : 2;
    addField('transitionBitmask', bitmaskSize, false);

    // 8. Custom immutable fields — in definition order
    for (final field in def.customFields.values) {
      if (!field.isMutable) {
        addField(field.name, field.byteSize, false);
      }
    }

    // 9. timeoutDelta — 4 bytes, immutable, only if any transition uses timelock
    if (def.hasTimelock) {
      addField('timeoutDelta', 4, false);
    }

    return HeaderLayout(
      fields: fields,
      totalHeaderSize: offset,
      altstackOrder: altstackOrder,
      mutableRegions: mutableRegions,
    );
  }

  static int _pushdataByte(int byteSize) {
    // Standard pushdata opcodes for common sizes
    if (byteSize <= 0x4b) return byteSize; // OP_PUSH_N for 1-75 bytes
    throw ArgumentError('Field size $byteSize exceeds single-byte pushdata');
  }
}
