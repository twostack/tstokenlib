import 'dart:convert';
import 'package:test/test.dart';
import '../../lib/src/state_machine/definition.dart';

/// Constructs the PP1_SM funnel as a StateMachineDefinition.
StateMachineDefinition buildPP1SmFunnel() {
  return StateMachineDefinition(
    name: 'PP1_SM_Funnel',
    description: 'The PP1 state machine funnel (marketing/escrow)',
    roles: {
      'merchant': RoleDef(name: 'merchant', authType: AuthType.PKH, description: 'Organization/merchant'),
      'customer': RoleDef(name: 'customer', authType: AuthType.PKH, description: 'Customer/participant'),
      'rabin': RoleDef(name: 'rabin', authType: AuthType.Rabin, description: 'Rabin identity binding'),
    },
    states: {
      'CREATED': StateDef(name: 'CREATED'),
      'ENROLLED': StateDef(name: 'ENROLLED'),
      'CONFIRMED': StateDef(name: 'CONFIRMED'),
      'CONVERTED': StateDef(name: 'CONVERTED'),
      'SETTLED': StateDef(name: 'SETTLED', isTerminal: true),
      'TIMED_OUT': StateDef(name: 'TIMED_OUT', isTerminal: true),
    },
    transitions: [
      TransitionDef(
        name: 'enroll',
        fromStates: ['CREATED'],
        toState: 'ENROLLED',
        requiredSigners: ['merchant'],
        ownerAfter: 'merchant',
      ),
      TransitionDef(
        name: 'confirm',
        fromStates: ['ENROLLED', 'CONFIRMED'],
        toState: 'CONFIRMED',
        requiredSigners: ['merchant', 'customer'],
        ownerAfter: 'merchant',
        effects: [
          EffectDef(fieldName: 'milestoneCount', type: EffectType.INCREMENT),
          EffectDef(fieldName: 'commitmentHash', type: EffectType.HASH_CHAIN),
        ],
      ),
      TransitionDef(
        name: 'convert',
        fromStates: ['CONFIRMED'],
        toState: 'CONVERTED',
        requiredSigners: ['merchant', 'customer'],
        ownerAfter: 'merchant',
        guards: [
          FieldGuardDef(fieldName: 'milestoneCount', op: GuardOp.GT, constant: 0),
        ],
        effects: [
          EffectDef(fieldName: 'commitmentHash', type: EffectType.HASH_CHAIN),
        ],
      ),
      TransitionDef(
        name: 'settle',
        fromStates: ['ENROLLED', 'CONFIRMED', 'CONVERTED'],
        toState: 'SETTLED',
        requiredSigners: ['merchant'],
        ownerAfter: 'merchant',
      ),
      TransitionDef(
        name: 'timeout',
        fromStates: ['ENROLLED', 'CONFIRMED', 'CONVERTED'],
        toState: 'TIMED_OUT',
        requiredSigners: ['merchant'],
        ownerAfter: 'merchant',
        usesTimelock: true,
      ),
    ],
    customFields: {
      'milestoneCount': FieldDef(name: 'milestoneCount', byteSize: 1, type: FieldType.COUNTER, isMutable: true),
    },
  );
}

void main() {
  group('StateMachineDefinition', () {
    test('PP1_SM funnel has correct structure', () {
      final def = buildPP1SmFunnel();

      expect(def.name, 'PP1_SM_Funnel');
      expect(def.roles.length, 3);
      expect(def.states.length, 6);
      expect(def.transitions.length, 5);
      expect(def.customFields.length, 1);
      expect(def.hasTimelock, isTrue);
    });

    test('state encodings auto-assigned in order', () {
      final def = buildPP1SmFunnel();

      expect(def.states['CREATED']!.encoding, 0);
      expect(def.states['ENROLLED']!.encoding, 1);
      expect(def.states['CONFIRMED']!.encoding, 2);
      expect(def.states['CONVERTED']!.encoding, 3);
      expect(def.states['SETTLED']!.encoding, 4);
      expect(def.states['TIMED_OUT']!.encoding, 5);
    });

    test('terminal states identified correctly', () {
      final def = buildPP1SmFunnel();

      expect(def.states['CREATED']!.isTerminal, isFalse);
      expect(def.states['ENROLLED']!.isTerminal, isFalse);
      expect(def.states['SETTLED']!.isTerminal, isTrue);
      expect(def.states['TIMED_OUT']!.isTerminal, isTrue);
    });

    test('roles have correct auth types', () {
      final def = buildPP1SmFunnel();

      expect(def.roles['merchant']!.authType, AuthType.PKH);
      expect(def.roles['customer']!.authType, AuthType.PKH);
      expect(def.roles['rabin']!.authType, AuthType.Rabin);
    });

    test('transitions have correct guards and effects', () {
      final def = buildPP1SmFunnel();

      // convert has a FieldGuard
      final convert = def.transitions.firstWhere((t) => t.name == 'convert');
      expect(convert.guards.length, 1);
      expect(convert.guards[0], isA<FieldGuardDef>());
      final guard = convert.guards[0] as FieldGuardDef;
      expect(guard.fieldName, 'milestoneCount');
      expect(guard.op, GuardOp.GT);
      expect(guard.constant, 0);

      // confirm has effects
      final confirm = def.transitions.firstWhere((t) => t.name == 'confirm');
      expect(confirm.effects.length, 2);
      expect(confirm.effects[0].type, EffectType.INCREMENT);
      expect(confirm.effects[1].type, EffectType.HASH_CHAIN);

      // timeout uses timelock
      final timeout = def.transitions.firstWhere((t) => t.name == 'timeout');
      expect(timeout.usesTimelock, isTrue);
    });

    test('JSON round-trip preserves all fields', () {
      final def = buildPP1SmFunnel();
      final json = def.toJson();
      final jsonStr = jsonEncode(json);
      final decoded = jsonDecode(jsonStr) as Map<String, dynamic>;
      final restored = StateMachineDefinition.fromJson(decoded);

      expect(restored.name, def.name);
      expect(restored.description, def.description);
      expect(restored.roles.length, def.roles.length);
      expect(restored.states.length, def.states.length);
      expect(restored.transitions.length, def.transitions.length);
      expect(restored.customFields.length, def.customFields.length);
      expect(restored.hasTimelock, def.hasTimelock);

      // Verify state encodings survive round-trip
      for (final key in def.states.keys) {
        expect(restored.states[key]!.encoding, def.states[key]!.encoding);
        expect(restored.states[key]!.isTerminal, def.states[key]!.isTerminal);
      }

      // Verify guards survive round-trip
      final convert = restored.transitions.firstWhere((t) => t.name == 'convert');
      expect(convert.guards.length, 1);
      expect(convert.guards[0], isA<FieldGuardDef>());
      final guard = convert.guards[0] as FieldGuardDef;
      expect(guard.fieldName, 'milestoneCount');
      expect(guard.op, GuardOp.GT);
      expect(guard.constant, 0);

      // Verify effects survive round-trip
      final confirm = restored.transitions.firstWhere((t) => t.name == 'confirm');
      expect(confirm.effects.length, 2);
      expect(confirm.effects[0].fieldName, 'milestoneCount');
      expect(confirm.effects[0].type, EffectType.INCREMENT);
    });

    test('JSON round-trip with DataGuardDef and OracleGuardDef', () {
      final def = StateMachineDefinition(
        name: 'test',
        roles: {
          'operator': RoleDef(name: 'operator', authType: AuthType.PKH),
        },
        states: {
          'INIT': StateDef(name: 'INIT'),
          'DONE': StateDef(name: 'DONE', isTerminal: true),
        },
        transitions: [
          TransitionDef(
            name: 'advance',
            fromStates: ['INIT'],
            toState: 'DONE',
            requiredSigners: ['operator'],
            ownerAfter: 'operator',
            guards: [
              DataGuardDef(payloadOffset: 0, payloadLength: 4, op: GuardOp.GT, value: 1000),
              OracleGuardDef(oracleRole: 'oracle1', dataGuards: [
                DataGuardDef(payloadOffset: 4, payloadLength: 1, op: GuardOp.EQ, value: 1),
              ]),
            ],
          ),
        ],
      );

      final json = jsonEncode(def.toJson());
      final restored = StateMachineDefinition.fromJson(jsonDecode(json) as Map<String, dynamic>);

      final guards = restored.transitions[0].guards;
      expect(guards.length, 2);
      expect(guards[0], isA<DataGuardDef>());
      expect(guards[1], isA<OracleGuardDef>());

      final dataGuard = guards[0] as DataGuardDef;
      expect(dataGuard.payloadOffset, 0);
      expect(dataGuard.payloadLength, 4);
      expect(dataGuard.value, 1000);

      final oracleGuard = guards[1] as OracleGuardDef;
      expect(oracleGuard.oracleRole, 'oracle1');
      expect(oracleGuard.dataGuards.length, 1);
      expect(oracleGuard.dataGuards[0].op, GuardOp.EQ);
    });
  });
}
