// Tests for the hybrid encryption scheme (public-key + private-key).
//
//   lib/crypto/key_manager.dart   (public-key part, RSA)        DONE
//     KeyManager.generate({bits})       RSA key pair, 256 to 1024 bits
//     KeyManager.wrapKey(key, pub)      RSA-encrypt an AES key
//     KeyManager.unwrapKey(wrapped, priv)
//     KeyManager.createRoomKey({uid: pub})  new AES key, one copy per member
//     KeyManager.unwrapRoomKey(wrapped, priv)
//     KeyManager.load/save/deleteKeyPair(uid)   key pair kept on the device
//     KeyManager.export/importPrivateKey        backup for a new device
//
//   lib/crypto/cipher.dart        (private-key part, AES-256)
//     MessageCipher.generateKey()       random 256-bit room key  DONE
//     MessageCipher.unlockRoomKey(locked, priv) -> real AES key  DONE
//     // Output is base64 so it can be stored in the database.  TODO
//     static Future<String> encryptText(String plain, Uint8List key);
//     static Future<String> decryptText(String cipherText, Uint8List key);
//     static Future<String> encryptBytes(Uint8List data, Uint8List key);
//     static Future<Uint8List> decryptBytes(String cipherText, Uint8List key);
//
// The "Text messages" and "Files" groups fail until AES is written.
//
// Run: flutter test test/crypto_test.dart

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:security_app/crypto/cipher.dart';
import 'package:security_app/crypto/key_manager.dart';
import 'package:shared_preferences/shared_preferences.dart';

Uint8List randomBytes(int n) {
  final rng = Random(42);
  return Uint8List.fromList(List.generate(n, (_) => rng.nextInt(256)));
}

class Keys {
  Keys(
    this.alice,
    this.bob,
    this.carol,
    this.roomKey,
    this.forAlice,
    this.forBob,
  );
  final RsaKeyPair alice;
  final RsaKeyPair bob;
  final RsaKeyPair carol; // outsider
  final Uint8List roomKey; // alice <-> bob AES key
  final String forAlice; // roomKey wrapped with alice's public key
  final String forBob; // roomKey wrapped with bob's public key
}

// Made once and shared, like the app does when two users become contacts.
// Each test awaits it, so if key generation is broken every test reports
// its own failure instead of one setUpAll failure.
Future<Keys>? _keys;
Future<Keys> keys() => _keys ??= () async {
  final alice = KeyManager.generate();
  final bob = KeyManager.generate();
  final carol = KeyManager.generate();
  final roomKey = MessageCipher.generateKey();
  return Keys(
    alice,
    bob,
    carol,
    roomKey,
    KeyManager.wrapKey(roomKey, alice.publicKey),
    KeyManager.wrapKey(roomKey, bob.publicKey),
  );
}();

/// Bob's copy of the room key, unwrapped with his private key.
Future<Uint8List> bobsKey() async {
  final k = await keys();
  return KeyManager.unwrapKey(k.forBob, k.bob.privateKey);
}

void main() {
  group('RSA math (written by hand)', () {
    test('modPow matches the built-in BigInt.modPow', () {
      final rng = Random(1);
      BigInt big() =>
          BigInt.parse(List.generate(60, (_) => rng.nextInt(10)).join());
      for (var i = 0; i < 50; i++) {
        final b = big(), e = big(), m = big() + BigInt.two;
        expect(KeyManager.modPow(b, e, m), b.modPow(e, m));
      }
    });

    test('modInverse gives a * x = 1 (mod m)', () {
      final a = BigInt.from(65537);
      final m = BigInt.parse('1000000000000000000000000000000000000000');
      final x = KeyManager.modInverse(a, m);
      expect(a * x % m, BigInt.one);
      expect(x, a.modInverse(m));
    });

    test('modInverse rejects numbers that share a factor', () {
      expect(
        () => KeyManager.modInverse(BigInt.from(6), BigInt.from(9)),
        throwsArgumentError,
      );
    });

    test('gcd', () {
      expect(KeyManager.gcd(BigInt.from(84), BigInt.from(36)), BigInt.from(12));
      expect(KeyManager.gcd(BigInt.from(17), BigInt.from(5)), BigInt.one);
    });

    test('Miller-Rabin knows primes from composites', () {
      final primes = [2, 3, 997, 7919, 104729].map(BigInt.from).toList()
        ..add((BigInt.one << 127) - BigInt.one) // Mersenne prime 2^127 - 1
        ..add((BigInt.one << 521) - BigInt.one); // Mersenne prime 2^521 - 1
      for (final p in primes) {
        expect(KeyManager.isProbablePrime(p), isTrue, reason: '$p is prime');
      }
      // 561 and 41041 are Carmichael numbers, which fool the simpler
      // Fermat test but not Miller-Rabin.
      final composites =
          [0, 1, 4, 561, 41041, 1000001].map(BigInt.from).toList()
            ..add((BigInt.one << 128) + BigInt.one)
            ..add(((BigInt.one << 127) - BigInt.one) * BigInt.from(1000003));
      for (final c in composites) {
        expect(KeyManager.isProbablePrime(c), isFalse, reason: '$c is not');
      }
    });

    test('randomPrime has exactly the requested size and is prime', () {
      final p = KeyManager.randomPrime(256);
      expect(p.bitLength, 256);
      expect(p.isOdd, isTrue);
      expect(KeyManager.isProbablePrime(p), isTrue);
    });
  });

  group('RSA key pairs (public-key part)', () {
    test('the app default is 1024 bits', () async {
      final k = await keys();
      expect(KeyManager.defaultBits, 1024);
      expect(k.alice.publicKey.bits, 1024);
    });

    test('any even size from 256 to 1024 bits works', () {
      for (final bits in [256, 512, 768, 1024]) {
        expect(KeyManager.generate(bits: bits).publicKey.bits, bits);
      }
    });

    test('sizes outside 256..1024 are rejected', () {
      for (final bits in [128, 255, 1025, 2048]) {
        expect(() => KeyManager.generate(bits: bits), throwsArgumentError);
      }
    });

    test('decrypting undoes encrypting: (m^e)^d = m mod n', () async {
      final k = await keys();
      final pub = k.alice.publicKey, priv = k.alice.privateKey;
      final m = BigInt.parse('123456789012345678901234567890');
      final c = KeyManager.modPow(m, pub.e, pub.n);
      expect(c, isNot(m));
      expect(KeyManager.modPow(c, priv.d, priv.n), m);
    });

    test('every user gets a different key pair', () async {
      final k = await keys();
      expect(k.alice.publicKey.n, isNot(k.bob.publicKey.n));
      expect(k.bob.publicKey.n, isNot(k.carol.publicKey.n));
      expect(k.alice.privateKey.d, isNot(k.bob.privateKey.d));
    });

    test('key pairs survive saving and loading', () async {
      final k = await keys();
      final json = jsonDecode(jsonEncode(k.alice.toJson()));
      final loaded = RsaKeyPair.fromJson(json as Map<String, dynamic>);
      expect(loaded.publicKey.n, k.alice.publicKey.n);
      expect(loaded.publicKey.e, k.alice.publicKey.e);
      expect(loaded.privateKey.d, k.alice.privateKey.d);
    });

    test('the public form does not contain the private exponent', () async {
      final k = await keys();
      expect(k.alice.publicKey.toJson().keys, unorderedEquals(['n', 'e']));
    });
  });

  group('Room key exchange (hybrid scheme)', () {
    test('the AES room key is 256 bits and random', () {
      final a = MessageCipher.generateKey();
      final b = MessageCipher.generateKey();
      expect(a.length, 32);
      expect(a, isNot(b));
    });

    test('both members unwrap the SAME room key', () async {
      final k = await keys();
      expect(KeyManager.unwrapKey(k.forAlice, k.alice.privateKey), k.roomKey);
      expect(KeyManager.unwrapKey(k.forBob, k.bob.privateKey), k.roomKey);
    });

    test('the two wrapped copies are different', () async {
      final k = await keys();
      expect(k.forAlice, isNot(k.forBob));
    });

    test(
      'wrapping is randomized: same key, same RSA key, new result',
      () async {
        final k = await keys();
        final again = KeyManager.wrapKey(k.roomKey, k.bob.publicKey);
        expect(again, isNot(k.forBob));
        expect(KeyManager.unwrapKey(again, k.bob.privateKey), k.roomKey);
      },
    );

    test('the wrapped key is base64 and does not contain the key', () async {
      final k = await keys();
      final bytes = base64Decode(k.forBob);
      expect(bytes.length, 128); // one 1024-bit RSA block
      expect(k.forBob, isNot(contains(base64Encode(k.roomKey))));
    });

    test('each copy only opens with its own private key', () async {
      final k = await keys();
      // Unwrapping with the wrong key either fails the padding check or,
      // very rarely, gives garbage. It never gives the room key.
      Uint8List? tryUnwrap(String w, RsaPrivateKey p) {
        try {
          return KeyManager.unwrapKey(w, p);
        } on FormatException {
          return null;
        }
      }

      expect(tryUnwrap(k.forBob, k.alice.privateKey), isNot(k.roomKey));
      expect(tryUnwrap(k.forBob, k.carol.privateKey), isNot(k.roomKey));
      expect(tryUnwrap(k.forAlice, k.carol.privateKey), isNot(k.roomKey));
    });

    test('a tampered wrapped key is rejected', () async {
      final k = await keys();
      final bytes = base64Decode(k.forBob);
      bytes[bytes.length ~/ 2] ^= 0x01; // flip one bit
      Uint8List? result;
      try {
        result = KeyManager.unwrapKey(base64Encode(bytes), k.bob.privateKey);
      } on FormatException {
        result = null;
      }
      expect(result, isNot(k.roomKey));
    });

    test('a 256-bit RSA key is too small to wrap a 256-bit AES key', () {
      final tiny = KeyManager.generate(bits: 256);
      expect(
        () => KeyManager.wrapKey(MessageCipher.generateKey(), tiny.publicKey),
        throwsArgumentError,
      );
    });
  });

  group('Room keys and device storage', () {
    test('createRoomKey locks the same AES key once per member', () async {
      final k = await keys();
      final copies = KeyManager.createRoomKey({
        'alice': k.alice.publicKey,
        'bob': k.bob.publicKey,
      });
      expect(copies.keys, unorderedEquals(['alice', 'bob']));
      expect(copies['alice'], isNot(copies['bob']));

      final forAlice = KeyManager.unwrapRoomKey(
        copies['alice']!,
        k.alice.privateKey,
      );
      final forBob = KeyManager.unwrapRoomKey(copies['bob']!, k.bob.privateKey);
      expect(forAlice.length, 32);
      expect(forBob, forAlice);
    });

    test('unwrapRoomKey rejects the wrong private key', () async {
      final k = await keys();
      final copies = KeyManager.createRoomKey({'bob': k.bob.publicKey});
      Uint8List? got;
      try {
        got = KeyManager.unwrapRoomKey(copies['bob']!, k.carol.privateKey);
      } on FormatException {
        got = null;
      }
      expect(
        got,
        isNot(KeyManager.unwrapRoomKey(copies['bob']!, k.bob.privateKey)),
      );
    });

    test('a saved key pair loads back; delete removes it', () async {
      SharedPreferences.setMockInitialValues({}); // empty fake device storage
      final k = await keys();
      expect(await KeyManager.loadKeyPair('alice'), isNull);

      await KeyManager.saveKeyPair('alice', k.alice);
      final loaded = await KeyManager.loadKeyPair('alice');
      expect(loaded!.publicKey.n, k.alice.publicKey.n);
      expect(loaded.privateKey.d, k.alice.privateKey.d);
      expect(await KeyManager.loadKeyPair('bob'), isNull);

      // Saved under the name existing installs already use.
      final prefs = await SharedPreferences.getInstance();
      expect(prefs.getString('rsa_key_pair_alice'), isNotNull);

      await KeyManager.deleteKeyPair('alice');
      expect(await KeyManager.loadKeyPair('alice'), isNull);
    });

    test('unlockRoomKey gives the real key, only with the right key', () async {
      final k = await keys();
      final key = MessageCipher.unlockRoomKey(k.forBob, k.bob.privateKey);
      expect(key, k.roomKey);
      expect(
        () => MessageCipher.unlockRoomKey(k.forBob, k.carol.privateKey),
        throwsFormatException,
      );
    });
  });

  group('Private key backup (new device)', () {
    test('the exported private key restores the same key pair', () async {
      final k = await keys();
      final saved = KeyManager.exportPrivateKey(k.alice.privateKey);
      final restored = KeyManager.importPrivateKey(saved, k.alice.publicKey);
      expect(restored.privateKey.d, k.alice.privateKey.d);
      expect(restored.publicKey.n, k.alice.publicKey.n);
      // The restored key still opens Alice's room key.
      expect(KeyManager.unwrapKey(k.forAlice, restored.privateKey), k.roomKey);
    });

    test('spaces and line breaks in the pasted key are ignored', () async {
      final k = await keys();
      final saved = KeyManager.exportPrivateKey(k.alice.privateKey);
      final messy = ' ${saved.substring(0, 40)}\n${saved.substring(40)} \n';
      final restored = KeyManager.importPrivateKey(messy, k.alice.publicKey);
      expect(restored.privateKey.d, k.alice.privateKey.d);
    });

    test("someone else's private key is rejected", () async {
      final k = await keys();
      final bobsKey = KeyManager.exportPrivateKey(k.bob.privateKey);
      expect(
        () => KeyManager.importPrivateKey(bobsKey, k.alice.publicKey),
        throwsFormatException,
      );
    });

    test('a typo or garbage is rejected', () async {
      final k = await keys();
      final saved = KeyManager.exportPrivateKey(k.alice.privateKey);
      final typo = saved.replaceRange(10, 11, saved[10] == 'A' ? 'B' : 'A');
      for (final bad in [typo, 'not a key!!', '']) {
        expect(
          () => KeyManager.importPrivateKey(bad, k.alice.publicKey),
          throwsFormatException,
          reason: bad,
        );
      }
    });
  });

  group('Text messages (private-key part)', () {
    test('peer decrypts exactly what was sent', () async {
      final k = await keys();
      const msg = 'meet at 7pm';
      final enc = await MessageCipher.encryptText(msg, k.roomKey);
      expect(await MessageCipher.decryptText(enc, await bobsKey()), msg);
    });

    test('handles unicode, emoji and empty text', () async {
      final k = await keys();
      for (final msg in ['', 'xin chào 👋 ñ 日本', 'a' * 5000]) {
        final enc = await MessageCipher.encryptText(msg, k.roomKey);
        expect(await MessageCipher.decryptText(enc, k.roomKey), msg);
      }
    });

    test('ciphertext does not reveal the plaintext', () async {
      final k = await keys();
      const msg = 'my bank pin is 4821';
      final enc = await MessageCipher.encryptText(msg, k.roomKey);
      expect(enc, isNot(contains(msg)));
      expect(enc, isNot(contains('4821')));
      expect(enc, isNot(base64Encode(utf8.encode(msg))));
    });

    test('ciphertext is valid base64 (safe to store)', () async {
      final k = await keys();
      final enc = await MessageCipher.encryptText('hi', k.roomKey);
      expect(() => base64Decode(enc), returnsNormally);
    });

    test('same message encrypted twice looks different (random IV)', () async {
      final k = await keys();
      final a = await MessageCipher.encryptText('same', k.roomKey);
      final b = await MessageCipher.encryptText('same', k.roomKey);
      expect(a, isNot(b));
    });

    test('a different key cannot decrypt', () async {
      final k = await keys();
      final enc = await MessageCipher.encryptText('secret', k.roomKey);
      await expectLater(
        MessageCipher.decryptText(enc, MessageCipher.generateKey()),
        throwsA(anything),
      );
    });

    test('tampered ciphertext is rejected', () async {
      final k = await keys();
      final enc = await MessageCipher.encryptText('pay 10 dollars', k.roomKey);
      final bytes = base64Decode(enc);
      bytes[bytes.length ~/ 2] ^= 0x01; // flip one bit
      await expectLater(
        MessageCipher.decryptText(base64Encode(bytes), k.roomKey),
        throwsA(anything),
      );
    });
  });

  group('Files (private-key part)', () {
    test('peer gets back the exact same bytes', () async {
      final k = await keys();
      final data = randomBytes(1024 * 1024); // 1 MB
      final enc = await MessageCipher.encryptBytes(data, k.roomKey);
      expect(await MessageCipher.decryptBytes(enc, await bobsKey()), data);
    });

    test('encrypted file is not just base64 of the original', () async {
      final k = await keys();
      final data = Uint8List.fromList(utf8.encode('PDF-1.7 top secret'));
      final enc = await MessageCipher.encryptBytes(data, k.roomKey);
      expect(enc, isNot(base64Encode(data)));
      expect(
        utf8.decode(base64Decode(enc), allowMalformed: true),
        isNot(contains('top secret')),
      );
    });

    test('a different key cannot decrypt the file', () async {
      final k = await keys();
      final enc = await MessageCipher.encryptBytes(randomBytes(64), k.roomKey);
      await expectLater(
        MessageCipher.decryptBytes(enc, MessageCipher.generateKey()),
        throwsA(anything),
      );
    });

    test('empty file round-trips', () async {
      final k = await keys();
      final enc = await MessageCipher.encryptBytes(Uint8List(0), k.roomKey);
      expect(await MessageCipher.decryptBytes(enc, k.roomKey), isEmpty);
    });
  });
}
