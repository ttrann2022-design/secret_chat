// Sections:
//   1. KEY CLASSES         RsaPublicKey, RsaPrivateKey, RsaKeyPair
//   2. KEY GENERATION      random primes -> key pair
//   3. LOCKING A KEY       wrap / unwrap an AES key with RSA
//   4. ROOM KEYS           per-room AES key, its signature, safety number
//   5. KEYS ON THE DEVICE  save / load / delete the key pair
//   6. PRIVATE KEY BACKUP  export / import for a new device
//   7. NUMBER THEORY       modPow, gcd, modInverse, random numbers
//   8. HASHING             SHA-256
//   9. SIGNATURES          RSA sign / verify
//  10. BYTE HELPERS        BigInt <-> bytes <-> base64

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:shared_preferences/shared_preferences.dart';

import 'cipher.dart';

// ═════════════════════════════════════════════════════════════════════════
// 1. KEY CLASSES
// Containers for the RSA numbers, with toJson/fromJson for storage.
// ═════════════════════════════════════════════════════════════════════════

/// Public RSA key (n, e). Safe to share.
class RsaPublicKey {
  const RsaPublicKey({required this.n, required this.e});

  /// Modulus n = p * q.
  final BigInt n;

  /// Public exponent (always 65537 here).
  final BigInt e;

  /// Key size in bits.
  int get bits => n.bitLength;

  /// {n, e} as base64 big-endian bytes, e.g. 65537 -> "AQAB".
  Map<String, String> toJson() => {'n': _toBase64(n), 'e': _toBase64(e)};

  /// Reads the form written by [toJson].
  factory RsaPublicKey.fromJson(Map<String, dynamic> m) =>
      RsaPublicKey(n: _fromBase64(m['n']), e: _fromBase64(m['e']));
}

/// Private RSA key (n, d). Never leaves the device.
class RsaPrivateKey {
  const RsaPrivateKey({required this.n, required this.d});

  /// Same modulus as the public key.
  final BigInt n;

  /// Secret exponent.
  final BigInt d;
}

/// A user's RSA key pair.
class RsaKeyPair {
  const RsaKeyPair({required this.publicKey, required this.privateKey});

  final RsaPublicKey publicKey;
  final RsaPrivateKey privateKey;

  /// {n, e, d} for device storage only. Contains the private key, so never
  /// write it to the database.
  Map<String, String> toJson() => {
    ...publicKey.toJson(),
    'd': _toBase64(privateKey.d),
  };

  /// Reads the form written by [toJson].
  factory RsaKeyPair.fromJson(Map<String, dynamic> m) {
    final pub = RsaPublicKey.fromJson(m);
    return RsaKeyPair(
      publicKey: pub,
      privateKey: RsaPrivateKey(n: pub.n, d: _fromBase64(m['d'])),
    );
  }
}

/// All RSA operations, as static methods.
class KeyManager {
  /// Allowed RSA key sizes, in bits.
  static const int minBits = 256;
  static const int maxBits = 1024;

  /// Size the app uses (the only allowed size that is still reasonably secure).
  static const int defaultBits = 1024;

  /// Standard public exponent 2^16 + 1: prime, and fast to use.
  static final BigInt publicExponent = BigInt.from(65537);

  /// Miller-Rabin rounds: error chance at most 1 in 4^40 = 2^80.
  static const int _rounds = 40;

  // Secure random numbers from the OS.
  static final Random _rng = Random.secure();

  // Primes below 1000, to reject most candidates before Miller-Rabin.
  static final List<BigInt> _smallPrimes = [
    for (var i = 2; i < 1000; i++)
      if (_isSmallPrime(i)) BigInt.from(i),
  ];

  // ───────────────────────────────────────────────────────────────────────
  // 2. KEY GENERATION
  // Two random primes p, q -> n = p * q, phi = (p-1)(q-1), d = e^-1 mod phi.
  // ───────────────────────────────────────────────────────────────────────

  /// A new key pair whose modulus has exactly [bits] bits.
  /// [bits] must be even and between [minBits] and [maxBits].
  static RsaKeyPair generate({int bits = defaultBits}) {
    // Even, so p and q can each be bits / 2.
    if (bits < minBits || bits > maxBits || bits.isOdd) {
      throw ArgumentError.value(
        bits,
        'bits',
        'must be an even number from $minBits to $maxBits',
      );
    }
    final e = publicExponent;
    // Almost always succeeds on the first try.
    while (true) {
      final p = randomPrime(bits ~/ 2);
      final q = randomPrime(bits ~/ 2);
      if (p == q) continue; // n = p^2 would be easy to factor
      final phi = (p - BigInt.one) * (q - BigInt.one);
      // d exists only if e and phi share no factor.
      if (gcd(e, phi) != BigInt.one) continue;
      final n = p * q;
      // Keep only n, e, d; p, q and phi are discarded.
      return RsaKeyPair(
        publicKey: RsaPublicKey(n: n, e: e),
        privateKey: RsaPrivateKey(n: n, d: modInverse(e, phi)),
      );
    }
  }

  /// A random prime of exactly [bits] bits.
  static BigInt randomPrime(int bits) {
    while (true) {
      // Top two bits set: p * q always has exactly 2 * bits bits.
      // Lowest bit set: the candidate is odd.
      final candidate =
          randomBits(bits) | (BigInt.from(3) << (bits - 2)) | BigInt.one;
      if (isProbablePrime(candidate)) return candidate;
    }
  }

  /// Miller-Rabin primality test. False = certainly composite; true = prime
  /// with overwhelming probability.
  ///
  /// Writes n - 1 = 2^s * d. For a prime n, a^d is 1, or repeated squaring
  /// of it reaches n - 1. A random a where neither happens proves n is
  /// composite.
  static bool isProbablePrime(BigInt n) {
    if (n < BigInt.two) return false;
    // Quick check: divide by every prime below 1000.
    for (final p in _smallPrimes) {
      if (n == p) return true;
      if (n % p == BigInt.zero) return false;
    }

    // n - 1 = 2^s * d, with d odd.
    final nMinus1 = n - BigInt.one;
    var d = nMinus1;
    var s = 0;
    while (d.isEven) {
      d >>= 1;
      s++;
    }

    witnessLoop:
    for (var i = 0; i < _rounds; i++) {
      final a = _randomBetween(BigInt.two, n - BigInt.two);
      var x = modPow(a, d, n);
      if (x == BigInt.one || x == nMinus1) continue; // round passed
      // Square up to s - 1 times, looking for n - 1.
      for (var r = 1; r < s; r++) {
        x = x * x % n;
        if (x == nMinus1) continue witnessLoop; // round passed
      }
      return false; // a proves n is composite
    }
    return true; // passed every round
  }

  // ───────────────────────────────────────────────────────────────────────
  // 3. LOCKING A KEY (wrap / unwrap)
  // RSA-encrypts a room's AES key with PKCS#1 v1.5 padding (RFC 8017 7.2).
  // ───────────────────────────────────────────────────────────────────────

  /// Encrypts [key] with [publicKey]. Returns base64.
  ///
  /// Padded block (k = size of n in bytes):
  ///   00 02 [at least 8 random non-zero bytes] 00 [key]
  /// The random bytes make every wrap of the same key look different.
  static String wrapKey(Uint8List key, RsaPublicKey publicKey) {
    // The block is k bytes and starts with 00, so its value is below n.
    final k = _byteLength(publicKey.n);
    // Room left for random padding after 00, 02, the 00 separator and key.
    final padLen = k - key.length - 3;
    if (padLen < 8) {
      throw ArgumentError(
        'A ${publicKey.bits}-bit RSA key is too small to wrap a '
        '${key.length * 8}-bit key; it needs at least '
        '${(key.length + 11) * 8} bits.',
      );
    }
    final block = Uint8List(k); // all zeros; block[0] stays 00
    block[1] = 0x02; // block type 2 = encryption
    for (var i = 2; i < 2 + padLen; i++) {
      // Non-zero: the first 00 marks where the key starts.
      block[i] = 1 + _rng.nextInt(255);
    }
    // block[2 + padLen] stays 00 (separator).
    block.setRange(3 + padLen, k, key);

    // c = m^e mod n
    final c = modPow(_bytesToInt(block), publicKey.e, publicKey.n);
    // Always k bytes, so every wrap has the same length.
    return base64Encode(_intToBytes(c, k));
  }

  /// Reverses [wrapKey]. Throws FormatException if [wrapped] was made for
  /// another key or was changed.
  static Uint8List unwrapKey(String wrapped, RsaPrivateKey privateKey) {
    final k = _byteLength(privateKey.n);
    final bytes = base64Decode(wrapped);
    final c = _bytesToInt(bytes);
    // A valid wrap is exactly k bytes and smaller than n.
    if (bytes.length != k || c >= privateKey.n) {
      throw const FormatException('This key was wrapped for another RSA key.');
    }
    // m = c^d mod n
    final block = _intToBytes(modPow(c, privateKey.d, privateKey.n), k);

    // Check the padding: 00 02, 8+ non-zero bytes (separator at index 10
    // or later), then 00. A wrong key almost never passes.
    final separator = block.indexOf(0, 2);
    if (block[0] != 0 || block[1] != 2 || separator < 10) {
      throw const FormatException(
        'Could not unwrap the key (wrong private key or damaged data).',
      );
    }
    // The key is everything after the separator.
    return Uint8List.fromList(block.sublist(separator + 1));
  }

  // ───────────────────────────────────────────────────────────────────────
  // 4. ROOM KEYS (the hybrid part)
  // A new room gets one AES key, wrapped once per member. The creator signs
  // the wrapped copies so nobody else (not even the server) can swap them.
  // The safety number lets two people check their public keys in person.
  // ───────────────────────────────────────────────────────────────────────

  // Cache of unwrapped room keys, keyed by (your n, wrapped copy). Keying by
  // the copy means a re-created room gets its new key.
  static final Map<(BigInt, String), Uint8List> _unwrapped = {};

  /// Makes a new AES room key and wraps it for each member.
  /// [members]: uid -> public key. Returns uid -> wrapped copy, ready for
  /// rooms/{roomId}/keys. The plain key is not returned.
  static Map<String, String> createRoomKey(Map<String, RsaPublicKey> members) {
    final aesKey = MessageCipher.generateKey();
    return {
      for (final member in members.entries)
        member.key: wrapKey(aesKey, member.value),
    };
  }

  /// Unwraps your copy of a room key (cached after the first time).
  /// Throws FormatException if it can't be opened.
  static Uint8List unwrapRoomKey(String wrapped, RsaPrivateKey privateKey) =>
      _unwrapped[(privateKey.n, wrapped)] ??= _checkRoomKeyLength(
        unwrapKey(wrapped, privateKey),
      );

  /// Rejects anything that isn't exactly 32 bytes. A wrong private key can
  /// pass the padding check by chance (~1 in 70,000) and give random bytes.
  static Uint8List _checkRoomKeyLength(Uint8List key) {
    if (key.length != MessageCipher.keyBytes) {
      throw const FormatException(
        'Could not unwrap the key (wrong private key or damaged data).',
      );
    }
    return key;
  }

  /// Clears the room key cache. Called on log out.
  static void forgetRoomKeys() => _unwrapped.clear();

  /// Signs a room's wrapped copies with the creator's [privateKey]
  /// (stored at rooms/{roomId}/keySig).
  static String signRoomKey(
    String roomId,
    Map<String, String> copies,
    RsaPrivateKey privateKey,
  ) => sign(_roomKeyStatement(roomId, copies), privateKey);

  /// True if [signature] is [publicKey]'s signature over exactly these
  /// [copies] of [roomId].
  static bool verifyRoomKey(
    String roomId,
    Map<String, String> copies,
    String signature,
    RsaPublicKey publicKey,
  ) => verify(_roomKeyStatement(roomId, copies), signature, publicKey);

  /// The bytes a room key signature covers: a label, the room id, then
  /// each "uid=copy" in uid order. The room id stops reuse in other rooms.
  static Uint8List _roomKeyStatement(String roomId, Map<String, String> copies) {
    final uids = copies.keys.toList()..sort();
    return Uint8List.fromList(
      utf8.encode(
        [
          'secret_chat room key v1',
          roomId,
          for (final uid in uids) '$uid=${copies[uid]}',
        ].join('\n'),
      ),
    );
  }

  /// SHA-256 of both people's public keys (order doesn't matter). Both
  /// phones show the same value unless a key was swapped. Returns 32 bytes;
  /// the app shows the first 16.
  static Uint8List safetyNumber(Map<String, RsaPublicKey> keys) {
    final uids = keys.keys.toList()..sort();
    return sha256(
      utf8.encode(
        [
          'secret_chat safety number v1',
          for (final uid in uids)
            '$uid=${_toBase64(keys[uid]!.n)},${_toBase64(keys[uid]!.e)}',
        ].join('\n'),
      ),
    );
  }

  // ───────────────────────────────────────────────────────────────────────
  // 5. KEYS ON THE DEVICE
  // The key pair is stored with shared_preferences and never sent anywhere.
  // ───────────────────────────────────────────────────────────────────────

  // Don't rename: existing installs store keys under this name.
  static String _storageName(String uid) => 'rsa_key_pair_$uid';

  /// [uid]'s saved key pair, or null if this device has none.
  static Future<RsaKeyPair?> loadKeyPair(String uid) async {
    final prefs = await SharedPreferences.getInstance();
    final saved = prefs.getString(_storageName(uid));
    if (saved == null) return null;
    return RsaKeyPair.fromJson(jsonDecode(saved) as Map<String, dynamic>);
  }

  /// Saves [uid]'s key pair, replacing any older one.
  static Future<void> saveKeyPair(String uid, RsaKeyPair pair) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_storageName(uid), jsonEncode(pair.toJson()));
  }

  /// Deletes [uid]'s key pair from this device.
  static Future<void> deleteKeyPair(String uid) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_storageName(uid));
  }

  // ───────────────────────────────────────────────────────────────────────
  // 6. PRIVATE KEY BACKUP
  // Export d as text; import it on a new device after checking it against
  // the published public key.
  // ───────────────────────────────────────────────────────────────────────

  /// The private key as text: base64 of d (n is public, so not included).
  static String exportPrivateKey(RsaPrivateKey privateKey) =>
      _toBase64(privateKey.d);

  /// Rebuilds the key pair from [exportPrivateKey] text and the published
  /// [publicKey]. Whitespace is ignored. Throws FormatException if it isn't
  /// the matching private key.
  static RsaKeyPair importPrivateKey(String text, RsaPublicKey publicKey) {
    final BigInt d;
    try {
      d = _fromBase64(text.replaceAll(RegExp(r'\s'), ''));
    } on FormatException {
      throw const FormatException('That is not a private key.');
    }
    // The right d satisfies (m^e)^d = m mod n. Test m = 2 and a random m.
    final n = publicKey.n, e = publicKey.e;
    for (final m in [BigInt.two, _randomBetween(BigInt.two, n - BigInt.two)]) {
      if (modPow(modPow(m, e, n), d, n) != m) {
        throw const FormatException('Wrong private key.');
      }
    }
    return RsaKeyPair(
      publicKey: publicKey,
      privateKey: RsaPrivateKey(n: n, d: d),
    );
  }

  // ───────────────────────────────────────────────────────────────────────
  // 7. NUMBER THEORY
  // Modular exponentiation, gcd, modular inverse and random numbers.
  // ───────────────────────────────────────────────────────────────────────

  /// base^exp mod m by square-and-multiply: one squaring per bit of exp,
  /// plus a multiply for each 1 bit. Reducing mod m each step keeps the
  /// numbers small.
  static BigInt modPow(BigInt base, BigInt exp, BigInt m) {
    if (m == BigInt.one) return BigInt.zero; // anything mod 1 is 0
    var result = BigInt.one;
    var b = base % m; // base^1, base^2, base^4, ...
    var e = exp;
    while (e > BigInt.zero) {
      if (e.isOdd) result = result * b % m; // this bit is 1
      b = b * b % m;
      e >>= 1; // next bit
    }
    return result;
  }

  /// Greatest common divisor (Euclid): gcd(x, y) = gcd(y, x mod y).
  static BigInt gcd(BigInt a, BigInt b) {
    var x = a;
    var y = b;
    while (y != BigInt.zero) {
      final t = x % y;
      x = y;
      y = t;
    }
    return x;
  }

  /// x with a * x = 1 (mod m), by the extended Euclidean algorithm.
  /// Throws if a and m share a factor. Example: 17^-1 mod 3120 = 2753.
  static BigInt modInverse(BigInt a, BigInt m) {
    // Invariant: oldS * a = oldR and s * a = r (mod m).
    var oldR = a % m, r = m;
    var oldS = BigInt.one, s = BigInt.zero;
    while (r != BigInt.zero) {
      final q = oldR ~/ r;
      (oldR, r) = (r, oldR - q * r);
      (oldS, s) = (s, oldS - q * s);
    }
    // oldR is gcd(a, m); an inverse exists only if it is 1.
    if (oldR != BigInt.one) throw ArgumentError('$a has no inverse mod $m');
    return oldS % m; // make it positive
  }

  /// A random number of at most [bits] bits.
  static BigInt randomBits(int bits) {
    // Enough whole bytes for [bits] bits.
    final bytes = Uint8List(_byteLength(BigInt.one << (bits - 1)));
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = _rng.nextInt(256);
    }
    // Mask off the extra bits.
    return _bytesToInt(bytes) & ((BigInt.one << bits) - BigInt.one);
  }

  /// A uniformly random number from [lo] to [hi], inclusive.
  static BigInt _randomBetween(BigInt lo, BigInt hi) {
    final range = hi - lo + BigInt.one;
    while (true) {
      // Rejection sampling (unlike "% range", this has no bias).
      final r = randomBits(range.bitLength);
      if (r < range) return lo + r;
    }
  }

  /// Trial division; only used to build [_smallPrimes].
  static bool _isSmallPrime(int n) {
    for (var i = 2; i * i <= n; i++) {
      if (n % i == 0) return false;
    }
    return true;
  }

  // ───────────────────────────────────────────────────────────────────────
  // 8. HASHING (SHA-256, FIPS 180-4)
  // Any data -> 32-byte fingerprint. Used by signatures and the safety
  // number. Uses only 32-bit operations so it also works on the web.
  // ───────────────────────────────────────────────────────────────────────

  static const int _mask32 = 0xFFFFFFFF;

  // Round constants (FIPS 180-4, section 4.2.2).
  static const List<int> _k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, //
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];

  /// SHA-256 of [data] (32 bytes).
  ///   1. pad to a multiple of 64 bytes
  ///   2. mix each 64-byte chunk into the 8-word state (64 rounds)
  ///   3. output the state
  static Uint8List sha256(List<int> data) {
    // Initial state (FIPS 180-4, section 5.3.3).
    final h = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, //
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // 1. Padding: data, 0x80, zeros, then the length in bits (8 bytes).
    // Uses % and ~/ instead of >> so it works on the web.
    final padded = Uint8List(((data.length + 9 + 63) ~/ 64) * 64)
      ..setRange(0, data.length, data);
    padded[data.length] = 0x80;
    var bits = data.length * 8;
    for (var i = padded.length - 1; i >= padded.length - 8; i--) {
      padded[i] = bits % 256;
      bits ~/= 256;
    }

    // 2. Process each 64-byte chunk.
    final w = List<int>.filled(64, 0);
    for (var chunk = 0; chunk < padded.length; chunk += 64) {
      // Message schedule: 16 words from the chunk, 48 derived from them.
      for (var t = 0; t < 16; t++) {
        final i = chunk + 4 * t;
        w[t] =
            ((padded[i] << 24) |
                (padded[i + 1] << 16) |
                (padded[i + 2] << 8) |
                padded[i + 3]) &
            _mask32;
      }
      for (var t = 16; t < 64; t++) {
        final s0 =
            _rotr(w[t - 15], 7) ^ _rotr(w[t - 15], 18) ^ (w[t - 15] >> 3);
        final s1 = _rotr(w[t - 2], 17) ^ _rotr(w[t - 2], 19) ^ (w[t - 2] >> 10);
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) & _mask32;
      }

      // 64 compression rounds.
      var a = h[0], b = h[1], c = h[2], d = h[3];
      var e = h[4], f = h[5], g = h[6], hh = h[7];
      for (var t = 0; t < 64; t++) {
        final s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25);
        final choose = (e & f) ^ ((~e & _mask32) & g); // e picks f or g
        final temp1 = (hh + s1 + choose + _k[t] + w[t]) & _mask32;
        final s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22);
        final majority = (a & b) ^ (a & c) ^ (b & c); // 2 of 3 bits
        final temp2 = (s0 + majority) & _mask32;
        hh = g;
        g = f;
        f = e;
        e = (d + temp1) & _mask32;
        d = c;
        c = b;
        b = a;
        a = (temp1 + temp2) & _mask32;
      }

      // Add the chunk's result into the state.
      h[0] = (h[0] + a) & _mask32;
      h[1] = (h[1] + b) & _mask32;
      h[2] = (h[2] + c) & _mask32;
      h[3] = (h[3] + d) & _mask32;
      h[4] = (h[4] + e) & _mask32;
      h[5] = (h[5] + f) & _mask32;
      h[6] = (h[6] + g) & _mask32;
      h[7] = (h[7] + hh) & _mask32;
    }

    // 3. The state as big-endian bytes.
    final out = Uint8List(32);
    for (var i = 0; i < 8; i++) {
      out[4 * i] = (h[i] >> 24) & 0xFF;
      out[4 * i + 1] = (h[i] >> 16) & 0xFF;
      out[4 * i + 2] = (h[i] >> 8) & 0xFF;
      out[4 * i + 3] = h[i] & 0xFF;
    }
    return out;
  }

  /// Rotates the 32-bit word [x] right by [n] bits.
  static int _rotr(int x, int n) => ((x >> n) | (x << (32 - n))) & _mask32;

  // ───────────────────────────────────────────────────────────────────────
  // 9. SIGNATURES (RSA, PKCS#1 v1.5, RFC 8017 section 8.2)
  // Sign with the private key, verify with the public key:
  //   block   = 00 01 FF..FF 00 [SHA-256 label][hash of the data]
  //   sign:     s = block^d mod n
  //   verify:   s^e mod n == block
  // ───────────────────────────────────────────────────────────────────────

  // DER prefix meaning "SHA-256 hash follows" (RFC 8017, section 9.2).
  static const List<int> _sha256Label = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, //
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
  ];

  /// Smallest key (bytes) that fits a signature block: 51 bytes of label +
  /// hash, plus 11 bytes of padding.
  static const int _minSignBytes = 62;

  /// The [k]-byte block that gets signed for [message].
  static Uint8List _signatureBlock(List<int> message, int k) {
    final labelAndHash = [..._sha256Label, ...sha256(message)]; // 51 bytes
    final block = Uint8List(k); // all zeros
    block[1] = 0x01;
    block.fillRange(2, k - labelAndHash.length - 1, 0xFF);
    // The 00 before the label is left as is.
    block.setRange(k - labelAndHash.length, k, labelAndHash);
    return block;
  }

  /// Signs [message] with [privateKey]. Returns base64. Needs a key of at
  /// least 496 bits.
  static String sign(List<int> message, RsaPrivateKey privateKey) {
    final k = _byteLength(privateKey.n);
    if (k < _minSignBytes) {
      throw ArgumentError('A ${privateKey.n.bitLength}-bit RSA key is too '
          'small to sign; it needs at least ${_minSignBytes * 8} bits.');
    }
    final m = _bytesToInt(_signatureBlock(message, k));
    return base64Encode(_intToBytes(modPow(m, privateKey.d, privateKey.n), k));
  }

  /// True if [signature] is a valid signature of [message] by the owner of
  /// [publicKey].
  static bool verify(
    List<int> message,
    String signature,
    RsaPublicKey publicKey,
  ) {
    final k = _byteLength(publicKey.n);
    if (k < _minSignBytes) return false;
    final Uint8List bytes;
    try {
      bytes = base64Decode(signature);
    } on FormatException {
      return false; // not base64
    }
    final s = _bytesToInt(bytes);
    if (bytes.length != k || s >= publicKey.n) return false;

    final block = _intToBytes(modPow(s, publicKey.e, publicKey.n), k);
    final expected = _signatureBlock(message, k);
    // Constant-time compare: no early exit.
    var diff = 0;
    for (var i = 0; i < k; i++) {
      diff |= block[i] ^ expected[i];
    }
    return diff == 0;
  }
}

// ═════════════════════════════════════════════════════════════════════════
// 10. BYTE HELPERS
// BigInt <-> big-endian bytes <-> base64, e.g. 65537 <-> [01 00 01] <-> "AQAB".
// ═════════════════════════════════════════════════════════════════════════

/// Bytes needed to hold [v], e.g. 1024 bits -> 128 bytes.
int _byteLength(BigInt v) => (v.bitLength + 7) ~/ 8;

/// Big-endian bytes -> number.
BigInt _bytesToInt(List<int> bytes) {
  var result = BigInt.zero;
  for (final b in bytes) {
    result = (result << 8) | BigInt.from(b); // shift in the next byte
  }
  return result;
}

/// Number -> exactly [length] big-endian bytes, zero-padded on the left.
Uint8List _intToBytes(BigInt v, int length) {
  final out = Uint8List(length);
  var rest = v;
  for (var i = length - 1; i >= 0; i--) {
    out[i] = (rest & _byteMask).toInt(); // lowest byte
    rest >>= 8;
  }
  return out;
}

/// Keeps only the lowest 8 bits.
final BigInt _byteMask = BigInt.from(0xFF);

/// Number -> base64 text.
String _toBase64(BigInt v) => base64Encode(_intToBytes(v, _byteLength(v)));

/// base64 text -> number. Throws if the field is missing.
BigInt _fromBase64(Object? v) {
  if (v is! String) throw const FormatException('Missing RSA key field.');
  return _bytesToInt(base64Decode(v));
}
