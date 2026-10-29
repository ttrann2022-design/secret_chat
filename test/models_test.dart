// Unit tests for models and helpers. No Firebase needed.
// Run: flutter test test/models_test.dart

import 'package:firebase_database/firebase_database.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:security_app/main.dart';

/// Minimal stand-in for a Realtime Database snapshot.
class FakeSnapshot implements DataSnapshot {
  FakeSnapshot(this.key, this.value);

  @override
  final String? key;
  @override
  final Object? value;

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

void main() {
  group('roomIdFor', () {
    test('is the same no matter who opens the chat', () {
      expect(
        ChatRepository.roomIdFor('alice', 'bob'),
        ChatRepository.roomIdFor('bob', 'alice'),
      );
    });

    test('contains both user ids', () {
      final id = ChatRepository.roomIdFor('uidB', 'uidA');
      expect(id, 'uidA_uidB');
    });

    test('is different for different pairs', () {
      expect(
        ChatRepository.roomIdFor('alice', 'bob'),
        isNot(ChatRepository.roomIdFor('alice', 'carol')),
      );
    });
  });

  group('ChatMessage.fromSnapshot', () {
    test('reads a text message', () {
      final m = ChatMessage.fromSnapshot(
        FakeSnapshot('m1', {
          'senderId': 'alice',
          'type': 'text',
          'text': 'hello',
          'timestamp': 1700000000000,
        }),
      );
      expect(m.id, 'm1');
      expect(m.senderId, 'alice');
      expect(m.text, 'hello');
      expect(m.isFile, isFalse);
      expect(m.fileId, isNull);
      expect(m.timestamp, 1700000000000);
    });

    test('reads a file message', () {
      final m = ChatMessage.fromSnapshot(
        FakeSnapshot('m2', {
          'senderId': 'bob',
          'type': 'file',
          'text': 'report.pdf',
          'fileId': 'f1',
          'fileSize': 2048,
          'timestamp': 1,
        }),
      );
      expect(m.isFile, isTrue);
      expect(m.text, 'report.pdf');
      expect(m.fileId, 'f1');
      expect(m.fileSize, 2048);
    });

    test('reads older messages that kept text in packet.body', () {
      final m = ChatMessage.fromSnapshot(
        FakeSnapshot('m3', {
          'senderId': 'alice',
          'packet': {'body': 'legacy'},
        }),
      );
      expect(m.text, 'legacy');
      expect(m.type, 'text');
    });

    test('falls back to safe defaults when fields are missing', () {
      final m = ChatMessage.fromSnapshot(FakeSnapshot(null, null));
      expect(m.id, '');
      expect(m.senderId, '');
      expect(m.text, '');
      expect(m.fileSize, 0);
      expect(m.timestamp, 0);
    });
  });

  group('Contact / ContactRequest', () {
    test('Contact reads code and since', () {
      final c = Contact.fromSnapshot(
        FakeSnapshot('bobUid', {'code': 'ABCD2345', 'since': 42}),
      );
      expect(c.uid, 'bobUid');
      expect(c.code, 'ABCD2345');
      expect(c.since, 42);
    });

    test('Contact shows ???????? when the code is missing', () {
      final c = Contact.fromSnapshot(FakeSnapshot('x', {}));
      expect(c.code, '????????');
    });

    test('ContactRequest reads sender uid and code', () {
      final r = ContactRequest.fromSnapshot(
        FakeSnapshot('aliceUid', {'fromCode': 'WXYZ6789', 'createdAt': 7}),
      );
      expect(r.fromUid, 'aliceUid');
      expect(r.fromCode, 'WXYZ6789');
      expect(r.createdAt, 7);
    });
  });

  group('helpers', () {
    test('asMap normalizes keys to strings', () {
      final m = asMap(<Object?, Object?>{1: 'a', 'b': 2});
      expect(m, {'1': 'a', 'b': 2});
    });

    test('asMap returns an empty map for non-maps', () {
      expect(asMap(null), isEmpty);
      expect(asMap('text'), isEmpty);
    });

    test('asInt handles numbers and junk', () {
      expect(asInt(5), 5);
      expect(asInt(5.9), 5);
      expect(asInt('5'), 0);
      expect(asInt(null), 0);
    });

    test('formatSize picks the right unit', () {
      expect(formatSize(0), '0 B');
      expect(formatSize(1023), '1023 B');
      expect(formatSize(1024), '1.0 KB');
      expect(formatSize(kMaxFileBytes), '5.0 MB');
    });

    test('formatTime shows --:-- for missing timestamps', () {
      expect(formatTime(0), '--:--');
    });

    test('formatTime shows only HH:mm for today', () {
      final now = DateTime.now();
      final t = DateTime(now.year, now.month, now.day, 9, 5);
      expect(formatTime(t.millisecondsSinceEpoch), '09:05');
    });

    test('formatTime adds the date for other days', () {
      final t = DateTime(2020, 3, 7, 14, 30);
      expect(formatTime(t.millisecondsSinceEpoch), '07/03 14:30');
    });

    test('UpperCaseFormatter uppercases input', () {
      final out = UpperCaseFormatter().formatEditUpdate(
        TextEditingValue.empty,
        const TextEditingValue(text: 'ab12cd'),
      );
      expect(out.text, 'AB12CD');
    });
  });
}
