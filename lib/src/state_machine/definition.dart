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

/// Data model for generic state machine definitions.
///
/// A [StateMachineDefinition] describes an arbitrary state machine in terms of
/// roles, states, transitions, guards, effects, and custom header fields.
/// The definition is the input to the [HeaderLayoutEngine] (byte offset
/// computation) and eventually to the script compiler.
library;

// --- Enums ---

enum AuthType { PKH, Rabin, Rabin_Oracle }

enum GuardOp { GT, GTE, EQ, LT, LTE, NEQ }

enum EffectType { SET, INCREMENT, HASH_CHAIN }

enum FieldType { COUNTER, HASH, AMOUNT, RAW }

// --- Guard hierarchy ---

abstract class GuardDef {
  final String? description;
  const GuardDef({this.description});

  Map<String, dynamic> toJson();

  static GuardDef fromJson(Map<String, dynamic> json) {
    final type = json['type'] as String;
    return switch (type) {
      'field' => FieldGuardDef.fromJson(json),
      'data' => DataGuardDef.fromJson(json),
      'oracle' => OracleGuardDef.fromJson(json),
      _ => throw ArgumentError('Unknown guard type: $type'),
    };
  }
}

class FieldGuardDef extends GuardDef {
  final String fieldName;
  final GuardOp op;
  final int constant;

  const FieldGuardDef({
    required this.fieldName,
    required this.op,
    required this.constant,
    super.description,
  });

  @override
  Map<String, dynamic> toJson() => {
    'type': 'field',
    'fieldName': fieldName,
    'op': op.name,
    'constant': constant,
    if (description != null) 'description': description,
  };

  factory FieldGuardDef.fromJson(Map<String, dynamic> json) => FieldGuardDef(
    fieldName: json['fieldName'] as String,
    op: GuardOp.values.byName(json['op'] as String),
    constant: json['constant'] as int,
    description: json['description'] as String?,
  );
}

class DataGuardDef extends GuardDef {
  final int payloadOffset;
  final int payloadLength;
  final GuardOp op;
  final int value;

  const DataGuardDef({
    required this.payloadOffset,
    required this.payloadLength,
    required this.op,
    required this.value,
    super.description,
  });

  @override
  Map<String, dynamic> toJson() => {
    'type': 'data',
    'payloadOffset': payloadOffset,
    'payloadLength': payloadLength,
    'op': op.name,
    'value': value,
    if (description != null) 'description': description,
  };

  factory DataGuardDef.fromJson(Map<String, dynamic> json) => DataGuardDef(
    payloadOffset: json['payloadOffset'] as int,
    payloadLength: json['payloadLength'] as int,
    op: GuardOp.values.byName(json['op'] as String),
    value: json['value'] as int,
    description: json['description'] as String?,
  );
}

class OracleGuardDef extends GuardDef {
  final String oracleRole;
  final List<DataGuardDef> dataGuards;

  const OracleGuardDef({
    required this.oracleRole,
    this.dataGuards = const [],
    super.description,
  });

  @override
  Map<String, dynamic> toJson() => {
    'type': 'oracle',
    'oracleRole': oracleRole,
    'dataGuards': dataGuards.map((g) => g.toJson()).toList(),
    if (description != null) 'description': description,
  };

  factory OracleGuardDef.fromJson(Map<String, dynamic> json) => OracleGuardDef(
    oracleRole: json['oracleRole'] as String,
    dataGuards: (json['dataGuards'] as List<dynamic>?)
        ?.map((g) => DataGuardDef.fromJson(g as Map<String, dynamic>))
        .toList() ?? [],
    description: json['description'] as String?,
  );
}

// --- Component classes ---

class RoleDef {
  final String name;
  final AuthType authType;
  final String? description;

  const RoleDef({
    required this.name,
    required this.authType,
    this.description,
  });

  Map<String, dynamic> toJson() => {
    'name': name,
    'authType': authType.name,
    if (description != null) 'description': description,
  };

  factory RoleDef.fromJson(Map<String, dynamic> json) => RoleDef(
    name: json['name'] as String,
    authType: AuthType.values.byName(json['authType'] as String),
    description: json['description'] as String?,
  );
}

class StateDef {
  final String name;
  final bool isTerminal;
  int encoding;

  StateDef({
    required this.name,
    this.isTerminal = false,
    this.encoding = -1,
  });

  Map<String, dynamic> toJson() => {
    'name': name,
    'isTerminal': isTerminal,
    'encoding': encoding,
  };

  factory StateDef.fromJson(Map<String, dynamic> json) => StateDef(
    name: json['name'] as String,
    isTerminal: json['isTerminal'] as bool? ?? false,
    encoding: json['encoding'] as int? ?? -1,
  );
}

class TransitionDef {
  final String name;
  final List<String> fromStates;
  final String toState;
  final List<String> requiredSigners;
  final String ownerAfter;
  final List<GuardDef> guards;
  final List<EffectDef> effects;
  final bool usesTimelock;
  final String? description;

  const TransitionDef({
    required this.name,
    required this.fromStates,
    required this.toState,
    required this.requiredSigners,
    required this.ownerAfter,
    this.guards = const [],
    this.effects = const [],
    this.usesTimelock = false,
    this.description,
  });

  Map<String, dynamic> toJson() => {
    'name': name,
    'fromStates': fromStates,
    'toState': toState,
    'requiredSigners': requiredSigners,
    'ownerAfter': ownerAfter,
    'guards': guards.map((g) => g.toJson()).toList(),
    'effects': effects.map((e) => e.toJson()).toList(),
    'usesTimelock': usesTimelock,
    if (description != null) 'description': description,
  };

  factory TransitionDef.fromJson(Map<String, dynamic> json) => TransitionDef(
    name: json['name'] as String,
    fromStates: (json['fromStates'] as List<dynamic>).cast<String>(),
    toState: json['toState'] as String,
    requiredSigners: (json['requiredSigners'] as List<dynamic>).cast<String>(),
    ownerAfter: json['ownerAfter'] as String,
    guards: (json['guards'] as List<dynamic>?)
        ?.map((g) => GuardDef.fromJson(g as Map<String, dynamic>))
        .toList() ?? [],
    effects: (json['effects'] as List<dynamic>?)
        ?.map((e) => EffectDef.fromJson(e as Map<String, dynamic>))
        .toList() ?? [],
    usesTimelock: json['usesTimelock'] as bool? ?? false,
    description: json['description'] as String?,
  );
}

class EffectDef {
  final String fieldName;
  final EffectType type;
  final int? value;

  const EffectDef({
    required this.fieldName,
    required this.type,
    this.value,
  });

  Map<String, dynamic> toJson() => {
    'fieldName': fieldName,
    'type': type.name,
    if (value != null) 'value': value,
  };

  factory EffectDef.fromJson(Map<String, dynamic> json) => EffectDef(
    fieldName: json['fieldName'] as String,
    type: EffectType.values.byName(json['type'] as String),
    value: json['value'] as int?,
  );
}

class FieldDef {
  final String name;
  final int byteSize;
  final FieldType type;
  final bool isMutable;

  const FieldDef({
    required this.name,
    required this.byteSize,
    required this.type,
    required this.isMutable,
  });

  Map<String, dynamic> toJson() => {
    'name': name,
    'byteSize': byteSize,
    'type': type.name,
    'isMutable': isMutable,
  };

  factory FieldDef.fromJson(Map<String, dynamic> json) => FieldDef(
    name: json['name'] as String,
    byteSize: json['byteSize'] as int,
    type: FieldType.values.byName(json['type'] as String),
    isMutable: json['isMutable'] as bool,
  );
}

// --- Top-level definition ---

class StateMachineDefinition {
  final String name;
  final String? description;
  final Map<String, RoleDef> roles;
  final Map<String, StateDef> states;
  final List<TransitionDef> transitions;
  final Map<String, FieldDef> customFields;

  StateMachineDefinition({
    required this.name,
    this.description,
    required this.roles,
    required this.states,
    required this.transitions,
    this.customFields = const {},
  }) {
    _assignStateEncodings();
  }

  void _assignStateEncodings() {
    int encoding = 0;
    for (final state in states.values) {
      if (state.encoding < 0) {
        state.encoding = encoding++;
      }
    }
  }

  bool get hasTimelock => transitions.any((t) => t.usesTimelock);

  Map<String, dynamic> toJson() => {
    'name': name,
    if (description != null) 'description': description,
    'roles': roles.map((k, v) => MapEntry(k, v.toJson())),
    'states': states.map((k, v) => MapEntry(k, v.toJson())),
    'transitions': transitions.map((t) => t.toJson()).toList(),
    'customFields': customFields.map((k, v) => MapEntry(k, v.toJson())),
  };

  factory StateMachineDefinition.fromJson(Map<String, dynamic> json) {
    final def = StateMachineDefinition(
      name: json['name'] as String,
      description: json['description'] as String?,
      roles: (json['roles'] as Map<String, dynamic>).map(
        (k, v) => MapEntry(k, RoleDef.fromJson(v as Map<String, dynamic>)),
      ),
      states: (json['states'] as Map<String, dynamic>).map(
        (k, v) => MapEntry(k, StateDef.fromJson(v as Map<String, dynamic>)),
      ),
      transitions: (json['transitions'] as List<dynamic>)
          .map((t) => TransitionDef.fromJson(t as Map<String, dynamic>))
          .toList(),
      customFields: (json['customFields'] as Map<String, dynamic>?)?.map(
        (k, v) => MapEntry(k, FieldDef.fromJson(v as Map<String, dynamic>)),
      ) ?? {},
    );
    return def;
  }
}
