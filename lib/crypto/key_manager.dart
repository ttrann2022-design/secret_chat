// Public-key part of the hybrid scheme.
// TODO: implement. test/crypto_test.dart checks the expected behaviour.

import 'dart:typed_data';

/// A user's key pair. The public key is shared through the database; the
/// private key never leaves the device.
class UserKeyPair {
  const UserKeyPair({required this.publicKey, required this.privateKey});

  final Uint8List publicKey;
  final Uint8List privateKey;
}

class KeyManager {
  /// Creates a new key pair (at least 256-bit).
  static Future<UserKeyPair> generate() async {
    throw UnimplementedError('KeyManager.generate is not implemented yet.');
  }

  /// Derives the 32-byte (256-bit) key shared by a pair of users. Both sides
  /// must get the same key:
  ///   sharedKey(alice, bob.publicKey) == sharedKey(bob, alice.publicKey)
  static Future<Uint8List> sharedKey(
    UserKeyPair mine,
    Uint8List peerPublicKey,
  ) async {
    throw UnimplementedError('KeyManager.sharedKey is not implemented yet.');
  }
}
