import 'dart:math';
import 'dart:typed_data';

/// AES-256 encryption for chat rooms. Output is base64 text so it can be
/// stored in the database.
class MessageCipher {
  /// AES-256 key size: 32 bytes = 256 bits.
  static const int keyBytes = 32;

  // Secure random numbers from the operating system.
  static final Random _rng = Random.secure();

  /// Makes a new random AES key (one per chat room).
  /// Example: [183, 7, 92, ..., 61]  (32 numbers from 0-255, new every time)
  static Uint8List generateKey() => Uint8List.fromList(
    List.generate(keyBytes, (_) => _rng.nextInt(256)),
  );

  /// TODO: Encrypts [plain] with [key] using AES-256. Returns base64 text.
  /// Encrypting the same text twice must give different results.
  /// Example: encryptText("hello", key) -> "3q2+7wAA...Zg=="
  ///
  /// Test: flutter test test/crypto_test.dart --plain-name "same message encrypted twice"
  /// Expected: +1: All tests passed!
  static Future<String> encryptText(String plain, Uint8List key) async {
    throw UnimplementedError('MessageCipher.encryptText is not implemented yet.');
  }

  /// TODO: Reverses [encryptText] and returns the original text.
  /// Must throw if [key] is wrong or [cipherText] was changed.
  /// Example: decryptText(encryptText("hello", key), key) -> "hello"
  ///
  /// Test: flutter test test/crypto_test.dart --plain-name "Text messages"
  /// Expected: +7: All tests passed!
  static Future<String> decryptText(String cipherText, Uint8List key) async {
    throw UnimplementedError('MessageCipher.decryptText is not implemented yet.');
  }

  /// TODO: Same as [encryptText], but for file bytes. Returns base64 text.
  /// A file is just bytes here (the app reads it with readAsBytes()), so
  /// the tests use fake files made in memory: no real file needed.
  /// Example: encryptBytes([1, 2, 3], key) -> "q8Lz...=="
  ///
  /// Test: flutter test test/crypto_test.dart --plain-name "encrypted file is not just base64"
  /// Expected: +1: All tests passed!
  static Future<String> encryptBytes(Uint8List data, Uint8List key) async {
    throw UnimplementedError('MessageCipher.encryptBytes is not implemented yet.');
  }

  /// TODO: Reverses [encryptBytes] and returns the original bytes.
  /// Must throw if [key] is wrong or [cipherText] was changed.
  /// Example: decryptBytes(encryptBytes([1, 2, 3], key), key) -> [1, 2, 3]
  ///
  /// Test: flutter test test/crypto_test.dart --plain-name "Files"
  /// Expected: +4: All tests passed!
  /// (fake files: 1 MB of random bytes, 64 random bytes, an empty file,
  /// and the bytes of "PDF-1.7 top secret")
  ///
  /// When all 4 functions are done, run everything:
  ///   flutter test test/crypto_test.dart   Expected: +35: All tests passed!
  ///   flutter test                         Expected: All tests passed!
  static Future<Uint8List> decryptBytes(String cipherText, Uint8List key) async {
    throw UnimplementedError('MessageCipher.decryptBytes is not implemented yet.');
  }
}
