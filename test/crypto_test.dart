// Tests for the hybrid encryption scheme (public-key + private-key).
//
// lib/crypto/ currently holds placeholders that throw UnimplementedError, so
// every test here fails until the real code is written. The API:
//
//   lib/crypto/key_manager.dart   (public-key part)
//     class UserKeyPair { Uint8List get publicKey; ... }
//     class KeyManager {
//       static Future<UserKeyPair> generate();
//       // Same 32-byte (256-bit) key for both users of a pair:
//       //   sharedKey(alice, bob.publicKey) == sharedKey(bob, alice.publicKey)
//       static Future<Uint8List> sharedKey(UserKeyPair mine, Uint8List peerPublicKey);
//     }
//
//   lib/crypto/cipher.dart        (private-key part)
//     class MessageCipher {
//       // Output is base64 so it can be stored in the database.
//       static Future<String> encryptText(String plain, Uint8List key);
//       static Future<String> decryptText(String cipherText, Uint8List key);
//       static Future<String> encryptBytes(Uint8List data, Uint8List key);
//       static Future<Uint8List> decryptBytes(String cipherText, Uint8List key);
//     }
//
// Example fit: X25519 key agreement + HKDF -> AES-256-GCM.
// Rename things if you like, but keep the behaviour these tests check.
//
// Run: flutter test test/crypto_test.dart

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:security_app/crypto/cipher.dart';
import 'package:security_app/crypto/key_manager.dart';

Uint8List randomBytes(int n) {
  final rng = Random(42);
  return Uint8List.fromList(List.generate(n, (_) => rng.nextInt(256)));
}

class Keys {
  Keys(this.alice, this.bob, this.carol, this.pairKey);
  final UserKeyPair alice;
  final UserKeyPair bob;
  final UserKeyPair carol; // outsider
  final Uint8List pairKey; // alice <-> bob
}

// Made once and shared. Each test awaits it, so if key generation is broken
// every test reports its own failure instead of one setUpAll failure.
Future<Keys>? _keys;
Future<Keys> keys() => _keys ??= () async {
  final alice = await KeyManager.generate();
  final bob = await KeyManager.generate();
  final carol = await KeyManager.generate();
  return Keys(alice, bob, carol, await KeyManager.sharedKey(alice, bob.publicKey));
}();

void main() {
  group('Key pairs (public-key part)', () {
    test('public key is at least 256 bits', () async {
      final k = await keys();
      expect(k.alice.publicKey.length, greaterThanOrEqualTo(32));
    });

    test('every user gets a different key pair', () async {
      final k = await keys();
      expect(k.alice.publicKey, isNot(k.bob.publicKey));
      expect(k.bob.publicKey, isNot(k.carol.publicKey));
    });

    test('both users of a pair derive the SAME shared key', () async {
      final k = await keys();
      final fromBob = await KeyManager.sharedKey(k.bob, k.alice.publicKey);
      expect(fromBob, k.pairKey);
    });

    test('shared key is 256 bits', () async {
      final k = await keys();
      expect(k.pairKey.length, 32);
    });

    test('a different pair gets a different shared key', () async {
      final k = await keys();
      final aliceCarol = await KeyManager.sharedKey(k.alice, k.carol.publicKey);
      expect(aliceCarol, isNot(k.pairKey));
    });
  });

  group('Text messages (private-key part)', () {
    test('peer decrypts exactly what was sent', () async {
      final k = await keys();
      const msg = 'meet at 7pm';
      final enc = await MessageCipher.encryptText(msg, k.pairKey);
      final bobKey = await KeyManager.sharedKey(k.bob, k.alice.publicKey);
      expect(await MessageCipher.decryptText(enc, bobKey), msg);
    });

    test('handles unicode, emoji and empty text', () async {
      final k = await keys();
      for (final msg in ['', 'xin chào 👋 ñ 日本', 'a' * 5000]) {
        final enc = await MessageCipher.encryptText(msg, k.pairKey);
        expect(await MessageCipher.decryptText(enc, k.pairKey), msg);
      }
    });

    test('ciphertext does not reveal the plaintext', () async {
      final k = await keys();
      const msg = 'my bank pin is 4821';
      final enc = await MessageCipher.encryptText(msg, k.pairKey);
      expect(enc, isNot(contains(msg)));
      expect(enc, isNot(contains('4821')));
      expect(enc, isNot(base64Encode(utf8.encode(msg))));
    });

    test('ciphertext is valid base64 (safe to store)', () async {
      final k = await keys();
      final enc = await MessageCipher.encryptText('hi', k.pairKey);
      expect(() => base64Decode(enc), returnsNormally);
    });

    test('same message encrypted twice looks different (random IV)', () async {
      final k = await keys();
      final a = await MessageCipher.encryptText('same', k.pairKey);
      final b = await MessageCipher.encryptText('same', k.pairKey);
      expect(a, isNot(b));
    });

    test('an outsider with their own key cannot decrypt', () async {
      final k = await keys();
      final enc = await MessageCipher.encryptText('secret', k.pairKey);
      final carolKey = await KeyManager.sharedKey(k.carol, k.alice.publicKey);
      await expectLater(
        MessageCipher.decryptText(enc, carolKey),
        throwsA(anything),
      );
    });

    test('tampered ciphertext is rejected', () async {
      final k = await keys();
      final enc = await MessageCipher.encryptText('pay 10 dollars', k.pairKey);
      final bytes = base64Decode(enc);
      bytes[bytes.length ~/ 2] ^= 0x01; // flip one bit
      await expectLater(
        MessageCipher.decryptText(base64Encode(bytes), k.pairKey),
        throwsA(anything),
      );
    });
  });

  group('Files (private-key part)', () {
    test('peer gets back the exact same bytes', () async {
      final k = await keys();
      final data = randomBytes(1024 * 1024); // 1 MB
      final enc = await MessageCipher.encryptBytes(data, k.pairKey);
      final bobKey = await KeyManager.sharedKey(k.bob, k.alice.publicKey);
      expect(await MessageCipher.decryptBytes(enc, bobKey), data);
    });

    test('encrypted file is not just base64 of the original', () async {
      final k = await keys();
      final data = Uint8List.fromList(utf8.encode('PDF-1.7 top secret'));
      final enc = await MessageCipher.encryptBytes(data, k.pairKey);
      expect(enc, isNot(base64Encode(data)));
      expect(
        utf8.decode(base64Decode(enc), allowMalformed: true),
        isNot(contains('top secret')),
      );
    });

    test('an outsider cannot decrypt the file', () async {
      final k = await keys();
      final enc = await MessageCipher.encryptBytes(randomBytes(64), k.pairKey);
      final carolKey = await KeyManager.sharedKey(k.carol, k.bob.publicKey);
      await expectLater(
        MessageCipher.decryptBytes(enc, carolKey),
        throwsA(anything),
      );
    });

    test('empty file round-trips', () async {
      final k = await keys();
      final enc = await MessageCipher.encryptBytes(Uint8List(0), k.pairKey);
      expect(await MessageCipher.decryptBytes(enc, k.pairKey), isEmpty);
    });
  });
}
