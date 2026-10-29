// Private-key part of the hybrid scheme.
// TODO: implement. test/crypto_test.dart checks the expected behaviour.

import 'dart:typed_data';

/// Encrypts with the 256-bit pair key from KeyManager.sharedKey.
/// All ciphertext is base64 so it can be stored in the database.
class MessageCipher {
  static Future<String> encryptText(String plain, Uint8List key) async {
    throw UnimplementedError('MessageCipher.encryptText is not implemented yet.');
  }

  static Future<String> decryptText(String cipherText, Uint8List key) async {
    throw UnimplementedError('MessageCipher.decryptText is not implemented yet.');
  }

  static Future<String> encryptBytes(Uint8List data, Uint8List key) async {
    throw UnimplementedError('MessageCipher.encryptBytes is not implemented yet.');
  }

  static Future<Uint8List> decryptBytes(String cipherText, Uint8List key) async {
    throw UnimplementedError('MessageCipher.decryptBytes is not implemented yet.');
  }
}
