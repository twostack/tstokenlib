import 'package:test/test.dart';
import '../../lib/src/state_machine/definition.dart';
import '../../lib/src/state_machine/header_layout.dart';
import 'definition_test.dart' show buildPP1SmFunnel;

void main() {
  final engine = HeaderLayoutEngine();

  group('HeaderLayoutEngine — PP1_SM equivalence', () {
    late HeaderLayout layout;

    setUp(() {
      layout = engine.compute(buildPP1SmFunnel());
    });

    test('total header size is 161 bytes', () {
      expect(layout.totalHeaderSize, 161);
    });

    test('field count matches PP1_SM (10 fields)', () {
      expect(layout.fields.length, 10);
    });

    test('ownerPKH at offset 0, data [1:21]', () {
      final f = layout.getField('ownerPKH');
      expect(f.offset, 0);
      expect(f.dataStart, 1);
      expect(f.dataEnd, 21);
      expect(f.pushdataByte, 0x14);
      expect(f.isMutable, isTrue);
    });

    test('tokenId at offset 21, data [22:54]', () {
      final f = layout.getField('tokenId');
      expect(f.offset, 21);
      expect(f.dataStart, 22);
      expect(f.dataEnd, 54);
      expect(f.pushdataByte, 0x20);
      expect(f.isMutable, isFalse);
    });

    test('merchantPKH at offset 54, data [55:75]', () {
      final f = layout.getField('merchantPKH');
      expect(f.offset, 54);
      expect(f.dataStart, 55);
      expect(f.dataEnd, 75);
      expect(f.pushdataByte, 0x14);
      expect(f.isMutable, isFalse);
    });

    test('customerPKH at offset 75, data [76:96]', () {
      final f = layout.getField('customerPKH');
      expect(f.offset, 75);
      expect(f.dataStart, 76);
      expect(f.dataEnd, 96);
      expect(f.pushdataByte, 0x14);
      expect(f.isMutable, isFalse);
    });

    test('rabinPKH at offset 96, data [97:117]', () {
      final f = layout.getField('rabinPKH');
      expect(f.offset, 96);
      expect(f.dataStart, 97);
      expect(f.dataEnd, 117);
      expect(f.pushdataByte, 0x14);
      expect(f.isMutable, isFalse);
    });

    test('currentState at offset 117, data [118:119]', () {
      final f = layout.getField('currentState');
      expect(f.offset, 117);
      expect(f.dataStart, 118);
      expect(f.dataEnd, 119);
      expect(f.pushdataByte, 0x01);
      expect(f.isMutable, isTrue);
    });

    test('milestoneCount at offset 119, data [120:121]', () {
      final f = layout.getField('milestoneCount');
      expect(f.offset, 119);
      expect(f.dataStart, 120);
      expect(f.dataEnd, 121);
      expect(f.pushdataByte, 0x01);
      expect(f.isMutable, isTrue);
    });

    test('commitmentHash at offset 121, data [122:154]', () {
      final f = layout.getField('commitmentHash');
      expect(f.offset, 121);
      expect(f.dataStart, 122);
      expect(f.dataEnd, 154);
      expect(f.pushdataByte, 0x20);
      expect(f.isMutable, isTrue);
    });

    test('transitionBitmask at offset 154, data [155:156]', () {
      final f = layout.getField('transitionBitmask');
      expect(f.offset, 154);
      expect(f.dataStart, 155);
      expect(f.dataEnd, 156);
      expect(f.pushdataByte, 0x01);
      expect(f.isMutable, isFalse);
    });

    test('timeoutDelta at offset 156, data [157:161]', () {
      final f = layout.getField('timeoutDelta');
      expect(f.offset, 156);
      expect(f.dataStart, 157);
      expect(f.dataEnd, 161);
      expect(f.pushdataByte, 0x04);
      expect(f.isMutable, isFalse);
    });

    test('altstack order matches PP1_SM push order', () {
      expect(layout.altstackOrder, [
        'ownerPKH', 'tokenId', 'merchantPKH', 'customerPKH', 'rabinPKH',
        'currentState', 'milestoneCount', 'commitmentHash',
        'transitionBitmask', 'timeoutDelta',
      ]);
    });

    test('mutable regions are correct', () {
      expect(layout.mutableRegions.length, 4);

      final ownerRegion = layout.mutableRegions.firstWhere((r) => r.fieldName == 'ownerPKH');
      expect(ownerRegion.dataStart, 1);
      expect(ownerRegion.dataEnd, 21);

      final stateRegion = layout.mutableRegions.firstWhere((r) => r.fieldName == 'currentState');
      expect(stateRegion.dataStart, 118);
      expect(stateRegion.dataEnd, 119);

      final mcRegion = layout.mutableRegions.firstWhere((r) => r.fieldName == 'milestoneCount');
      expect(mcRegion.dataStart, 120);
      expect(mcRegion.dataEnd, 121);

      final chRegion = layout.mutableRegions.firstWhere((r) => r.fieldName == 'commitmentHash');
      expect(chRegion.dataStart, 122);
      expect(chRegion.dataEnd, 154);
    });
  });

  group('HeaderLayoutEngine — alternate definitions', () {
    test('definition with 2 roles produces smaller header', () {
      final def = StateMachineDefinition(
        name: 'simple',
        roles: {
          'operator': RoleDef(name: 'operator', authType: AuthType.PKH),
          'verifier': RoleDef(name: 'verifier', authType: AuthType.PKH),
        },
        states: {
          'INIT': StateDef(name: 'INIT'),
          'DONE': StateDef(name: 'DONE', isTerminal: true),
        },
        transitions: [
          TransitionDef(
            name: 'complete',
            fromStates: ['INIT'],
            toState: 'DONE',
            requiredSigners: ['operator'],
            ownerAfter: 'operator',
          ),
        ],
      );

      final layout = engine.compute(def);

      // ownerPKH(21) + tokenId(33) + operatorPKH(21) + verifierPKH(21)
      // + currentState(2) + commitmentHash(33) + transitionBitmask(2)
      // = 133 bytes, no timeoutDelta, no custom fields
      expect(layout.totalHeaderSize, 133);
      expect(layout.totalHeaderSize, lessThan(161));

      // No timeoutDelta field
      expect(
        () => layout.getField('timeoutDelta'),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('definition with 2 custom mutable fields', () {
      final def = StateMachineDefinition(
        name: 'custom_fields',
        roles: {
          'operator': RoleDef(name: 'operator', authType: AuthType.PKH),
        },
        states: {
          'INIT': StateDef(name: 'INIT'),
          'DONE': StateDef(name: 'DONE', isTerminal: true),
        },
        transitions: [
          TransitionDef(
            name: 'finish',
            fromStates: ['INIT'],
            toState: 'DONE',
            requiredSigners: ['operator'],
            ownerAfter: 'operator',
          ),
        ],
        customFields: {
          'counter1': FieldDef(name: 'counter1', byteSize: 1, type: FieldType.COUNTER, isMutable: true),
          'counter2': FieldDef(name: 'counter2', byteSize: 2, type: FieldType.COUNTER, isMutable: true),
        },
      );

      final layout = engine.compute(def);

      // ownerPKH(21) + tokenId(33) + operatorPKH(21) + currentState(2)
      // + counter1(2) + counter2(3) + commitmentHash(33) + transitionBitmask(2)
      // = 117 bytes
      expect(layout.totalHeaderSize, 117);

      // Custom fields appear between currentState and commitmentHash
      final cs = layout.getField('currentState');
      final c1 = layout.getField('counter1');
      final c2 = layout.getField('counter2');
      final ch = layout.getField('commitmentHash');

      expect(c1.offset, greaterThan(cs.dataEnd - 1));
      expect(c2.offset, greaterThan(c1.dataEnd - 1));
      expect(ch.offset, greaterThan(c2.dataEnd - 1));
      expect(c1.isMutable, isTrue);
      expect(c2.isMutable, isTrue);
    });

    test('definition with no timelock has no timeoutDelta', () {
      final def = StateMachineDefinition(
        name: 'no_timelock',
        roles: {
          'admin': RoleDef(name: 'admin', authType: AuthType.PKH),
        },
        states: {
          'START': StateDef(name: 'START'),
          'END': StateDef(name: 'END', isTerminal: true),
        },
        transitions: [
          TransitionDef(
            name: 'go',
            fromStates: ['START'],
            toState: 'END',
            requiredSigners: ['admin'],
            ownerAfter: 'admin',
          ),
        ],
      );

      final layout = engine.compute(def);
      expect(def.hasTimelock, isFalse);
      expect(
        () => layout.getField('timeoutDelta'),
        throwsA(isA<ArgumentError>()),
      );
    });
  });
}
