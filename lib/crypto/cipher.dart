// Private-key half of the hybrid scheme: AES-256-GCM.
//
// Each chat room has one 32-byte AES key that encrypts all of its messages
// and files. RSA (key_manager.dart) is only used to share that key safely
// between the two members.
//
// Sections:
//   1. ROOM AES KEYS      create a room key, unlock your copy of it
//   2. ENCRYPT & DECRYPT  encrypt / decrypt text and file bytes

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:pointycastle/export.dart'; // AES engine + GCM mode
import 'key_manager.dart';

/// AES-256-GCM encryption for chat rooms. Ciphertext is base64 text so it
/// can be stored in the database.
class MessageCipher {
  // ───────────────────────────────────────────────────────────────────────
  // 1. ROOM AES KEYS
  // One random 32-byte key per room, made when two people become contacts.
  // Firebase only stores RSA-locked copies; the real key lives in memory.
  // ───────────────────────────────────────────────────────────────────────

  /// AES-256 key size: 32 bytes = 256 bits.
  static const int keyBytes = 32;

  // Cryptographically secure random numbers from the OS.
  static final Random _rng = Random.secure();

  /// A new random 32-byte AES key for a room.
  static Uint8List generateKey() => Uint8List.fromList(
    List.generate(keyBytes, (_) => _rng.nextInt(256)),
  );

  /// Unlocks your copy of a room key ([lockedKey], from
  /// rooms/{roomId}/keys/{yourUid}) with your RSA [privateKey].
  /// Returns the 32-byte AES key. Throws FormatException on a wrong key.
  static Uint8List unlockRoomKey(String lockedKey, RsaPrivateKey privateKey) =>
      KeyManager.unwrapRoomKey(lockedKey, privateKey);


  // ───────────────────────────────────────────────────────────────────────
  // 2. ENCRYPT & DECRYPT
  // AES-256-GCM with the room key. Each call uses a fresh random 12-byte
  // nonce, so the same input never encrypts the same way twice. GCM adds a
  // 16-byte tag, so a wrong key or edited ciphertext fails to decrypt.
  // Stored format: base64( nonce[12] | ciphertext | tag[16] ).
  // ───────────────────────────────────────────────────────────────────────

  /// Encrypts the text [plain] with [key]. Returns base64.
  static Future<String> encryptText(String plain, Uint8List key) async {
    // Text -> UTF-8 bytes, then the same path as files.
    return await encryptBytes(Uint8List.fromList(utf8.encode(plain)), key);
  }

  /// Reverses [encryptText]. Throws if [key] is wrong or [cipherText] was
  /// changed.
  static Future<String> decryptText(String cipherText, Uint8List key) async {
    return utf8.decode(await decryptBytes(cipherText, key));
  }

  /// Encrypts raw bytes (a file, or UTF-8 text) with [key]. Returns base64.
  static Future<String> encryptBytes(Uint8List data, Uint8List key) async {
    // A new random nonce for every message.
    final nonce = Uint8List.fromList(List.generate(12, (_) => _rng.nextInt(256)));
    // true = encrypt; 128-bit tag; no extra authenticated data.
    final cipher = GCMBlockCipher(AESEngine())
      ..init(
        true,
        AEADParameters(KeyParameter(key), 128, nonce, Uint8List(0)),
      );
    // Ciphertext with the tag appended.
    final encrypt = cipher.process(data);


    // The nonce goes in front so decryptBytes can read it back.
    return base64Encode([...nonce, ...encrypt]);
  }

  /// Reverses [encryptBytes]. Throws if [key] is wrong or [cipherText] was
  /// changed (the GCM tag check fails).
  static Future<Uint8List> decryptBytes(String cipherText, Uint8List key) async {
    try{
      // Split the stored value back into nonce and ciphertext + tag.
      final message = base64Decode(cipherText);
      final nonce = message.sublist(0, 12);
      final encrypt = message.sublist(12);
      // Same setup as encryptBytes, but false = decrypt.
      final cipher = GCMBlockCipher(AESEngine())
        ..init(
          false,
          AEADParameters(KeyParameter(key), 128, nonce, Uint8List(0)),
        );
      return cipher.process(encrypt);
    } catch (e, s) {
      // Bad base64, too short, wrong key or tampered data: one error.
      throw Exception("Decryption failed");
    }
  }
}
