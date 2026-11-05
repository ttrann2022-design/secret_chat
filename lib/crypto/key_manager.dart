// Public-key part of the hybrid scheme: RSA, implemented by hand.
//
// Only two things here come from outside this file:
//   - Random.secure() for random numbers;
//   - Dart's BigInt for plain big-number arithmetic.
// Prime generation, the Miller-Rabin primality test, modular exponentiation,
// the modular inverse and the padding are all written below.
//
// How the app uses it:
//   1. Every user generates an RSA key pair. The public key is published in
//      the database; the private key never leaves the device.
//   2. When two users become contacts, one random AES key is made for their
//      room (MessageCipher.generateKey) and wrapped (RSA-encrypted) twice:
//      once with each user's public key.
//   3. Each user unwraps their own copy with their private key, so both end
//      up with the same AES key without it ever being stored in the clear.
//   4. The private key can be exported as text, saved by the user, and
//      imported again on a new device (exportPrivateKey / importPrivateKey).
//
// RSA in one small example (tiny numbers so you can check by hand; the app
// uses 512-bit primes and e = 65537):
//
//   pick primes      p = 61, q = 53
//   modulus          n = p * q = 3233              (public)
//   phi              (p - 1)(q - 1) = 60 * 52 = 3120   (secret)
//   public exponent  e = 17                        (public)
//   private exponent d = 17^-1 mod 3120 = 2753     (secret)
//                    check: 17 * 2753 = 46801 = 15 * 3120 + 1
//
//   encrypt m = 65:  c = 65^17   mod 3233 = 2790
//   decrypt c:       m = 2790^2753 mod 3233 = 65   (back to the original)
//
// Anyone can encrypt with (n, e). Only the holder of d can decrypt, and
// finding d means knowing phi, which means factoring n into p and q. For a
// 1024-bit n, that is far beyond a normal computer.
//
// Sections in this file:
//   1. KEY CLASSES         RsaPublicKey, RsaPrivateKey, RsaKeyPair
//   2. KEY GENERATION      make a new key pair from two random primes
//   3. LOCKING A KEY       wrap / unwrap: RSA-encrypt the AES room key
//   4. ROOM KEYS           one AES key per room, locked once per member,
//                          signed by its creator, plus the safety number
//   5. KEYS ON THE DEVICE  save, load and delete the key pair on the phone
//   6. PRIVATE KEY BACKUP  export as text, import on a new device
//   7. NUMBER THEORY       modPow, gcd, modInverse, random numbers
//   8. HASHING             SHA-256, written by hand
//   9. SIGNATURES          sign with a private key, verify with a public key
//  10. BYTE HELPERS        numbers <-> bytes <-> base64 text

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:shared_preferences/shared_preferences.dart';

import 'cipher.dart';

// ═════════════════════════════════════════════════════════════════════════
// 1. KEY CLASSES
// Small containers for the numbers that make up an RSA key, plus the
// toJson/fromJson code that turns them into text for Firebase (public key)
// or the phone's storage (whole key pair).
// ═════════════════════════════════════════════════════════════════════════

/// The public half of an RSA key: modulus n and exponent e. Safe to share.
class RsaPublicKey {
  const RsaPublicKey({required this.n, required this.e});

  /// The modulus p * q. Different for every user.
  final BigInt n;

  /// The public exponent. Always 65537 in this app (see
  /// KeyManager.publicExponent), which is normal: the secret is in d.
  final BigInt e;

  /// Key size in bits (the size of n).
  int get bits => n.bitLength;

  /// Database/storage form: each number as base64 of its big-endian bytes.
  /// For example e = 65537 = bytes 01 00 01 = "AQAB".
  Map<String, String> toJson() => {'n': _toBase64(n), 'e': _toBase64(e)};

  /// Reads the form written by [toJson] (from the database or the device).
  factory RsaPublicKey.fromJson(Map<String, dynamic> m) =>
      RsaPublicKey(n: _fromBase64(m['n']), e: _fromBase64(m['e']));
}

/// The private half: modulus n and secret exponent d. Never leaves the device.
class RsaPrivateKey {
  const RsaPrivateKey({required this.n, required this.d});

  /// Same modulus as the public key.
  final BigInt n;

  /// The secret exponent. Whoever has d can unwrap keys wrapped for n.
  final BigInt d;
}

/// A user's RSA key pair.
class RsaKeyPair {
  const RsaKeyPair({required this.publicKey, required this.privateKey});

  final RsaPublicKey publicKey;
  final RsaPrivateKey privateKey;

  /// Storage form for the device only: {n, e, d}. It contains the private
  /// key, so it must never be written to the database.
  Map<String, String> toJson() => {
    ...publicKey.toJson(),
    'd': _toBase64(privateKey.d),
  };

  /// Reads the form written by [toJson]. n is stored once and shared by
  /// both halves.
  factory RsaKeyPair.fromJson(Map<String, dynamic> m) {
    final pub = RsaPublicKey.fromJson(m);
    return RsaKeyPair(
      publicKey: pub,
      privateKey: RsaPrivateKey(n: pub.n, d: _fromBase64(m['d'])),
    );
  }
}

/// All the RSA operations. Every method is static: there is nothing to
/// set up, you just call KeyManager.generate(), KeyManager.wrapKey(), etc.
class KeyManager {
  /// Allowed RSA key sizes, in bits.
  static const int minBits = 256;
  static const int maxBits = 1024;

  /// The size the app uses. It is also the only size in the allowed range
  /// with real (if dated) security; 256-bit RSA can be factored on a laptop.
  static const int defaultBits = 1024;

  /// The standard public exponent 2^16 + 1: prime, and only two 1-bits, so
  /// encrypting with it is fast.
  ///
  /// In binary it is 1 0000 0000 0000 0001, so modPow needs only 16
  /// squarings plus one extra multiply.
  static final BigInt publicExponent = BigInt.from(65537);

  /// Miller-Rabin rounds. A composite survives one round with probability at
  /// most 1/4, so 40 rounds leave at most a 1 in 2^80 chance of error.
  static const int _rounds = 40;

  // The only source of randomness in this file. Random.secure() asks the
  // operating system for cryptographically secure random bytes (unlike
  // Random(), whose output can be predicted).
  static final Random _rng = Random.secure();

  // Primes below 1000, used to throw out most candidates cheaply before
  // running the slower Miller-Rabin test. More than 80% of random odd
  // numbers are divisible by one of these, so most candidates never reach
  // Miller-Rabin at all.
  static final List<BigInt> _smallPrimes = [
    for (var i = 2; i < 1000; i++)
      if (_isSmallPrime(i)) BigInt.from(i),
  ];

  // ───────────────────────────────────────────────────────────────────────
  // 2. KEY GENERATION
  // Makes a brand-new RSA key pair: find two big random primes p and q,
  // then compute n, phi and d from them. Done once per account (and again
  // only if the user generates a new pair after losing their key).
  // ───────────────────────────────────────────────────────────────────────

  /// Creates a new RSA key pair whose modulus n has exactly [bits] bits.
  /// [bits] must be even and between [minBits] and [maxBits].
  ///
  ///   1. pick two random primes p and q of bits/2 bits each
  ///   2. n = p * q
  ///   3. phi = (p - 1)(q - 1)
  ///   4. e = 65537, which must share no factor with phi
  ///   5. d = e^-1 mod phi, so that (m^e)^d = m (mod n)
  static RsaKeyPair generate({int bits = defaultBits}) {
    // Even, so n splits into two primes of the same size (bits / 2 each).
    if (bits < minBits || bits > maxBits || bits.isOdd) {
      throw ArgumentError.value(
        bits,
        'bits',
        'must be an even number from $minBits to $maxBits',
      );
    }
    final e = publicExponent;
    // Loops only in rare cases; almost always the first p and q work.
    while (true) {
      // Steps 1-2: two independent random primes. For a 1024-bit key each
      // is 512 bits, a number about 154 digits long.
      final p = randomPrime(bits ~/ 2);
      final q = randomPrime(bits ~/ 2);
      if (p == q) continue; // n = p^2 would be trivial to factor
      // Step 3: phi counts the numbers below n that share no factor with
      // it. It's easy to compute from p and q but, without them, as hard
      // as factoring n. That is why d stays secret.
      final phi = (p - BigInt.one) * (q - BigInt.one);
      // Step 4: d only exists if e and phi share no factor. With e = 65537
      // (a prime) this fails only when 65537 divides p - 1 or q - 1.
      if (gcd(e, phi) != BigInt.one) continue; // e has no inverse: try again
      final n = p * q;
      // Step 5: d is the number with e * d = 1 (mod phi). That is what
      // makes decrypting undo encrypting: (m^e)^d = m^(e*d) = m (mod n).
      // p, q and phi are thrown away here; only n, e and d are kept.
      return RsaKeyPair(
        publicKey: RsaPublicKey(n: n, e: e),
        privateKey: RsaPrivateKey(n: n, d: modInverse(e, phi)),
      );
    }
  }

  /// A random prime of exactly [bits] bits.
  ///
  /// Draws random odd numbers until one passes the primality test. Primes
  /// are common enough that this is fast: about 1 in every 177 odd 512-bit
  /// numbers is prime.
  static BigInt randomPrime(int bits) {
    while (true) {
      // Setting the top TWO bits makes p * q always have exactly 2 * bits
      // bits. Setting the lowest bit makes the candidate odd.
      //
      // Why two bits: with both set, p and q are each at least 3/4 of
      // 2^bits, so p * q is at least 9/16 of 2^(2 * bits), which is more
      // than half of it, so the top bit of n is always 1.
      //
      //   randomBits(bits)             1011 0110 ... 0110
      //   | (3 << (bits - 2))          11.. .... ... ....   top two bits on
      //   | 1                          .... .... ... ...1   odd
      final candidate =
          randomBits(bits) | (BigInt.from(3) << (bits - 2)) | BigInt.one;
      if (isProbablePrime(candidate)) return candidate;
    }
  }

  /// Miller-Rabin test. False means [n] is certainly composite; true means
  /// it is prime with overwhelming probability.
  ///
  /// Idea: if n is prime, then for any a, a^(n-1) = 1 (mod n) (Fermat), and
  /// the only square roots of 1 mod n are 1 and n - 1. So if we start from
  /// a^d and keep squaring up to a^(n-1), we must either start at 1 or hit
  /// n - 1 on the way. If neither happens, n cannot be prime, and a is a
  /// "witness" that proves it.
  ///
  /// Small example, n = 221 (= 13 * 17, so composite):
  ///   n - 1 = 220 = 2^2 * 55, so s = 2, d = 55
  ///   a = 137: 137^55 mod 221 = 188, then 188^2 mod 221 = 205
  ///            never 1 or 220, so 221 is composite (137 is a witness)
  ///   a = 174: 174^55 mod 221 = 47, then 47^2 mod 221 = 220 = n - 1
  ///            looks prime: 174 is a "liar" for 221
  /// Liars exist, which is why we try 40 random values of a: for a
  /// composite n, at most 1 in 4 values lie, so all 40 lying is
  /// practically impossible. (In the real code, 221 would already be
  /// caught by dividing by the small prime 13.)
  static bool isProbablePrime(BigInt n) {
    if (n < BigInt.two) return false;
    // Cheap first pass: divide by every prime below 1000.
    for (final p in _smallPrimes) {
      if (n == p) return true;
      if (n % p == BigInt.zero) return false;
    }

    // Write n - 1 as 2^s * d with d odd, by halving until it's odd.
    // Example: 220 -> 110 -> 55, so s = 2 and d = 55.
    final nMinus1 = n - BigInt.one;
    var d = nMinus1;
    var s = 0;
    while (d.isEven) {
      d >>= 1; // >> 1 is the same as dividing by 2
      s++;
    }

    // The label lets the inner loop jump straight to the next round.
    witnessLoop:
    for (var i = 0; i < _rounds; i++) {
      // If n is prime, a^d is 1, or squaring it reaches n - 1 within s - 1
      // steps. Any other outcome proves n is composite.
      final a = _randomBetween(BigInt.two, n - BigInt.two);
      var x = modPow(a, d, n);
      if (x == BigInt.one || x == nMinus1) continue; // passed this round
      // Square up to s - 1 times: x goes a^(2d), a^(4d), ... a^((n-1)/2).
      for (var r = 1; r < s; r++) {
        x = x * x % n;
        if (x == nMinus1) continue witnessLoop; // passed this round
      }
      return false; // a is a witness: n is definitely composite
    }
    return true; // survived every round: prime
  }

  // ───────────────────────────────────────────────────────────────────────
  // 3. LOCKING A KEY (wrap / unwrap)
  // RSA encryption of one small secret: the room's AES key. "Wrap" locks it
  // with someone's public key; "unwrap" unlocks it with the matching
  // private key. Random padding makes every locked copy look different.
  // ───────────────────────────────────────────────────────────────────────

  /// Encrypts [key] (the room's AES key) with [publicKey] so only the owner
  /// of the matching private key can read it. Returns base64.
  ///
  /// Uses PKCS#1 v1.5 padding (RFC 8017, section 7.2):
  /// `00 02 [random non-zero bytes, at least 8] 00 [key]`.
  /// The random bytes make every wrap different, even of the same key, and
  /// stop the plain "textbook RSA" attacks.
  ///
  /// For a 1024-bit RSA key (k = 128 bytes) and a 32-byte AES key:
  ///
  ///   byte:  0    1    2 ......... 94   95   96 ......... 127
  ///         [00] [02] [93 random bytes] [00] [32-byte AES key ]
  ///
  /// Without padding, the same AES key would always give the same result,
  /// and an attacker could test guesses by encrypting them with the
  /// public key and comparing.
  static String wrapKey(Uint8List key, RsaPublicKey publicKey) {
    // k = size of n in bytes. The padded block has exactly this size, and
    // because it starts with 00 its value is always less than n, as RSA
    // requires.
    final k = _byteLength(publicKey.n);
    // Bytes left for random padding after 00, 02, the 00 separator and the
    // key itself.
    final padLen = k - key.length - 3;
    if (padLen < 8) {
      throw ArgumentError(
        'A ${publicKey.bits}-bit RSA key is too small to wrap a '
        '${key.length * 8}-bit key; it needs at least '
        '${(key.length + 11) * 8} bits.',
      );
    }
    final block = Uint8List(k); // starts as all zeros
    // block[0] stays 0x00.
    block[1] = 0x02; // "02" = this block holds encrypted data (type 2)
    for (var i = 2; i < 2 + padLen; i++) {
      // Non-zero, because unwrapKey finds the end of the padding by
      // looking for the first 00 byte.
      block[i] = 1 + _rng.nextInt(255); // 1..255, never 0
    }
    // block[2 + padLen] stays 0: it marks where the key starts.
    block.setRange(3 + padLen, k, key);

    // The RSA step itself: treat the block as one big number m and
    // compute c = m^e mod n.
    final c = modPow(_bytesToInt(block), publicKey.e, publicKey.n); // c = m^e
    // Always output k bytes (pad c with leading zeros if it is smaller),
    // so every wrapped key for this RSA key has the same length.
    return base64Encode(_intToBytes(c, k));
  }

  /// Reverses [wrapKey] with the private key. Throws FormatException if
  /// [wrapped] was made for a different key or has been changed.
  static Uint8List unwrapKey(String wrapped, RsaPrivateKey privateKey) {
    final k = _byteLength(privateKey.n);
    final bytes = base64Decode(wrapped);
    final c = _bytesToInt(bytes);
    // A wrap made for this key is exactly k bytes and smaller than n.
    // Anything else was made for another key (or is corrupted).
    if (bytes.length != k || c >= privateKey.n) {
      throw const FormatException('This key was wrapped for another RSA key.');
    }
    // The RSA step: m = c^d mod n gives back the padded block.
    final block = _intToBytes(modPow(c, privateKey.d, privateKey.n), k);

    // Check the padding: 00 02, at least 8 non-zero bytes, then a 00.
    // With the wrong private key (or a tampered wrap), the result is
    // random-looking bytes, which almost never pass this check.
    // separator is the index of the first 00 after the 02; the padding
    // runs from index 2 to separator - 1, so 8+ bytes means separator >= 10.
    final separator = block.indexOf(0, 2);
    if (block[0] != 0 || block[1] != 2 || separator < 10) {
      throw const FormatException(
        'Could not unwrap the key (wrong private key or damaged data).',
      );
    }
    // Everything after the separator is the AES key.
    return Uint8List.fromList(block.sublist(separator + 1));
  }

  // ───────────────────────────────────────────────────────────────────────
  // 4. ROOM KEYS (the hybrid part)
  // When two people become contacts, their room gets one new AES key,
  // locked once for each of them. Each person later unlocks only their own
  // copy. Unlocked keys are remembered so the RSA math runs only once.
  //
  // The person who creates the room key also SIGNS it (section 9). Before
  // using a room key, the app checks that signature with that person's
  // public key, so a key slipped in by anyone else (even the server) is
  // rejected. The SAFETY NUMBER lets two people check, in person, that the
  // public keys themselves weren't swapped.
  // ───────────────────────────────────────────────────────────────────────

  // Room keys already unwrapped, by (whose private key, wrapped copy).
  // Keyed by the wrapped copy rather than the room id, so a room that was
  // wiped and re-created gets its new key; keyed by n too, so two accounts
  // on one device never share entries.
  static final Map<(BigInt, String), Uint8List> _unwrapped = {};

  /// Makes a new AES key for a room and locks one copy of it for each
  /// member, with that member's public key.
  ///
  /// [members] maps user id -> public key. Returns user id -> wrapped copy,
  /// ready to store at rooms/{roomId}/keys. The plain AES key is not
  /// returned: every member, including the one creating the room, gets it
  /// by unwrapping their own copy with [unwrapRoomKey].
  static Map<String, String> createRoomKey(Map<String, RsaPublicKey> members) {
    final aesKey = MessageCipher.generateKey();
    return {
      for (final member in members.entries)
        member.key: wrapKey(aesKey, member.value),
    };
  }

  /// Unwraps your copy of a room key with your private key. The result is
  /// remembered, so decrypting many messages doesn't redo the RSA math each
  /// time. Throws FormatException, like [unwrapKey], if it can't be opened.
  static Uint8List unwrapRoomKey(String wrapped, RsaPrivateKey privateKey) =>
      _unwrapped[(privateKey.n, wrapped)] ??= _checkRoomKeyLength(
        unwrapKey(wrapped, privateKey),
      );

  /// A room key is always exactly 32 bytes (AES-256). With a wrong private
  /// key, the padding check in [unwrapKey] can be fooled by chance (about 1
  /// in 70,000 times) and return random bytes of any length; this catches
  /// that, so a wrong key always throws.
  static Uint8List _checkRoomKeyLength(Uint8List key) {
    if (key.length != MessageCipher.keyBytes) {
      throw const FormatException(
        'Could not unwrap the key (wrong private key or damaged data).',
      );
    }
    return key;
  }

  /// Forgets every unwrapped room key. Called on log out.
  static void forgetRoomKeys() => _unwrapped.clear();

  /// Signs a room's locked copies with the creator's [privateKey]. Stored
  /// next to them (rooms/{roomId}/keySig), it proves which member made the
  /// room key, and that no copy was swapped or added afterwards.
  static String signRoomKey(
    String roomId,
    Map<String, String> copies,
    RsaPrivateKey privateKey,
  ) => sign(_roomKeyStatement(roomId, copies), privateKey);

  /// True if [signature] is a valid [signRoomKey] signature by the owner of
  /// [publicKey] over exactly these [copies] of this [roomId].
  static bool verifyRoomKey(
    String roomId,
    Map<String, String> copies,
    String signature,
    RsaPublicKey publicKey,
  ) => verify(_roomKeyStatement(roomId, copies), signature, publicKey);

  /// The exact bytes a room key signature covers: a label, the room id, and
  /// every member's locked copy in user-id order. Including the room id
  /// stops a signature from one room being reused in another.
  /// Example: "secret_chat room key v1\na_b\na=kX9f...\nb=Qm2a..."
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

  /// The safety number of two people: a SHA-256 hash of both their public
  /// keys ([keys] maps user id -> public key; order doesn't matter). Both
  /// phones show the same number; if a public key was swapped on the
  /// server, the numbers differ. Returns 32 bytes; the app shows the first 16.
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
  // The pair, private key included, is saved with shared_preferences: the
  // app's own storage on a phone, or local storage in a browser. It is never
  // sent anywhere. On a new phone or after a reinstall it's gone, and the
  // user restores it from their backup (see importPrivateKey).
  // ───────────────────────────────────────────────────────────────────────

  // Don't rename: existing users' keys are saved under this name.
  static String _storageName(String uid) => 'rsa_key_pair_$uid';

  /// [uid]'s key pair saved on this device, or null if there is none.
  static Future<RsaKeyPair?> loadKeyPair(String uid) async {
    final prefs = await SharedPreferences.getInstance();
    final saved = prefs.getString(_storageName(uid));
    if (saved == null) return null;
    return RsaKeyPair.fromJson(jsonDecode(saved) as Map<String, dynamic>);
  }

  /// Saves [uid]'s key pair on this device, replacing any older one.
  static Future<void> saveKeyPair(String uid, RsaKeyPair pair) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_storageName(uid), jsonEncode(pair.toJson()));
  }

  /// Removes [uid]'s key pair from this device (as if it were a new phone).
  static Future<void> deleteKeyPair(String uid) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_storageName(uid));
  }

  // ───────────────────────────────────────────────────────────────────────
  // 6. PRIVATE KEY BACKUP (for moving to a new device)
  // The user copies their private key as text when the account is made.
  // On a new device they paste it back; it's checked against their public
  // key in Firebase before it's accepted.
  // ───────────────────────────────────────────────────────────────────────

  /// Your private key as text you can copy and keep: base64 of d.
  ///
  /// n isn't included because it's public anyway (users/{uid}/publicKey),
  /// so d is all that has to be saved.
  static String exportPrivateKey(RsaPrivateKey privateKey) =>
      _toBase64(privateKey.d);

  /// Rebuilds a key pair from text made by [exportPrivateKey] plus the
  /// account's published [publicKey]. Spaces and line breaks are ignored.
  ///
  /// Throws FormatException if [text] isn't the private key that belongs to
  /// [publicKey], so a typo can't break any chats.
  static RsaKeyPair importPrivateKey(String text, RsaPublicKey publicKey) {
    final BigInt d;
    try {
      d = _fromBase64(text.replaceAll(RegExp(r'\s'), ''));
    } on FormatException {
      throw const FormatException('That is not a private key.');
    }
    // The matching d undoes e: (m^e)^d = m (mod n). Test with m = 2 and
    // with one random m.
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
  // The hand-written math RSA is built on: fast powers mod m, greatest
  // common divisor, modular inverse, and secure random numbers.
  // ───────────────────────────────────────────────────────────────────────

  /// base^exp mod m by square-and-multiply: walk the bits of exp from the
  /// lowest, squaring base each step and multiplying it into the result
  /// when the bit is 1. Takes about 2 * bitLength(exp) multiplications
  /// instead of exp of them.
  ///
  /// Example, 3^13 mod 7 (13 = 1101 in binary, so 3^13 = 3^8 * 3^4 * 3^1):
  ///
  ///   bit of 13 (low first)  b (3, 3^2, 3^4, 3^8 mod 7)  result
  ///   1                      3                          1 * 3 = 3
  ///   0                      2                          3       (skip)
  ///   1                      4                          3 * 4 = 12 = 5
  ///   1                      2                          5 * 2 = 10 = 3
  ///   answer: 3
  ///
  /// Taking "% m" after every multiplication keeps the numbers small (below
  /// m^2). Without it, c^d for a 1024-bit d would have more digits than
  /// there are atoms in the universe.
  static BigInt modPow(BigInt base, BigInt exp, BigInt m) {
    if (m == BigInt.one) return BigInt.zero; // everything is 0 mod 1
    var result = BigInt.one;
    var b = base % m; // b takes the values base, base^2, base^4, base^8, ...
    var e = exp; // e is shifted right, so e.isOdd reads one bit at a time
    while (e > BigInt.zero) {
      if (e.isOdd) result = result * b % m; // this bit is 1: include b
      b = b * b % m; // next power: base^(2^(i+1))
      e >>= 1; // move to the next bit
    }
    return result;
  }

  /// Greatest common divisor (Euclid's algorithm).
  ///
  /// Uses gcd(x, y) = gcd(y, x mod y), repeated until y is 0.
  /// Example: gcd(84, 36) -> gcd(36, 12) -> gcd(12, 0) = 12.
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

  /// x such that a * x = 1 (mod m), by the extended Euclidean algorithm.
  /// Throws if a and m share a factor (no inverse exists).
  ///
  /// It runs Euclid's algorithm on (a, m) and, alongside each remainder r,
  /// tracks a number s with s * a = r (mod m). When the remainder reaches
  /// gcd = 1, its s is the inverse.
  ///
  /// Example from the RSA demo above, the inverse of 17 mod 3120:
  ///
  ///   q      r (remainders)   s (s * 17 = r mod 3120)
  ///          3120             0
  ///          17               1
  ///   183    9                0 - 183 * 1     = -183
  ///   1      8                1 - 1 * (-183)  = 184
  ///   1      1                -183 - 1 * 184  = -367
  ///   gcd is 1, so the answer is -367 mod 3120 = 2753
  ///   check: 17 * 2753 = 46801 = 15 * 3120 + 1
  static BigInt modInverse(BigInt a, BigInt m) {
    // Invariant: oldS * a = oldR (mod m) and s * a = r (mod m).
    var oldR = a % m, r = m;
    var oldS = BigInt.one, s = BigInt.zero;
    while (r != BigInt.zero) {
      final q = oldR ~/ r; // ~/ is whole-number division
      // Move both columns one step down the table above. A record
      // assignment updates both values at once, so the old ones are
      // still available on the right-hand side.
      (oldR, r) = (r, oldR - q * r);
      (oldS, s) = (s, oldS - q * s);
    }
    // oldR is now gcd(a, m). Only when it's 1 does an inverse exist.
    if (oldR != BigInt.one) throw ArgumentError('$a has no inverse mod $m');
    return oldS % m; // % makes it positive
  }

  /// A random number with at most [bits] bits, from the secure generator.
  static BigInt randomBits(int bits) {
    // Enough whole bytes to hold [bits] bits (e.g. 13 bits -> 2 bytes).
    final bytes = Uint8List(_byteLength(BigInt.one << (bits - 1)));
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = _rng.nextInt(256); // one random byte, 0..255
    }
    // The bytes may hold a few too many bits (16 for 13), so mask the
    // number down to [bits] bits: (1 << bits) - 1 is [bits] ones in binary.
    return _bytesToInt(bytes) & ((BigInt.one << bits) - BigInt.one);
  }

  /// A random number from [lo] to [hi], both included.
  static BigInt _randomBetween(BigInt lo, BigInt hi) {
    final range = hi - lo + BigInt.one; // how many possible values
    while (true) {
      // Draw numbers of the same bit size and reject those out of range, so
      // every value is equally likely.
      // (Taking "random % range" instead would make small values slightly
      // more likely.) Each draw is in range at least half the time, so this
      // rarely loops more than once or twice.
      final r = randomBits(range.bitLength);
      if (r < range) return lo + r;
    }
  }

  /// Trial division, only used once to build the small-prime list.
  static bool _isSmallPrime(int n) {
    for (var i = 2; i * i <= n; i++) {
      if (n % i == 0) return false;
    }
    return true;
  }

  // ───────────────────────────────────────────────────────────────────────
  // 8. HASHING (SHA-256, FIPS 180-4)
  // A hash turns any data into a 32-byte "fingerprint". Changing even one
  // bit of the input changes the whole hash, and you can't work backwards
  // from it. Signatures (section 9) sign the hash of the data, and the
  // safety number is the hash of two public keys. Written by hand, using
  // only 32-bit steps so it also works in Chrome.
  // ───────────────────────────────────────────────────────────────────────

  static const int _mask32 = 0xFFFFFFFF;

  // Round constants: the first 32 bits of the fractional parts of the cube
  // roots of the first 64 primes (FIPS 180-4, section 4.2.2).
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

  /// SHA-256 hash of [data]: always 32 bytes.
  /// Example: sha256(utf8.encode('abc')) -> ba7816bf 8f01cfea 414140de ...
  ///
  ///   1. pad the data to a multiple of 64 bytes: a 1 bit, zeros, then the
  ///      length in bits
  ///   2. for every 64-byte chunk, mix it into the 8-word state with 64
  ///      rounds of shifts, XORs and additions
  ///   3. the final 8 words are the hash
  static Uint8List sha256(List<int> data) {
    // Starting state: the first 32 bits of the fractional parts of the
    // square roots of the first 8 primes.
    final h = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, //
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // 1. Padding: data, then 0x80, then zeros, then the length in bits as
    // the last 8 bytes. (% and ~/ instead of >> so it works in Chrome.)
    final padded = Uint8List(((data.length + 9 + 63) ~/ 64) * 64)
      ..setRange(0, data.length, data);
    padded[data.length] = 0x80;
    var bits = data.length * 8;
    for (var i = padded.length - 1; i >= padded.length - 8; i--) {
      padded[i] = bits % 256;
      bits ~/= 256;
    }

    // 2. Each 64-byte chunk.
    final w = List<int>.filled(64, 0);
    for (var chunk = 0; chunk < padded.length; chunk += 64) {
      // The chunk as 16 words of 4 bytes, then 48 more words mixed from
      // the earlier ones.
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

      // 64 rounds over the working copy a..h of the state.
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

      // Add this chunk's result into the state.
      h[0] = (h[0] + a) & _mask32;
      h[1] = (h[1] + b) & _mask32;
      h[2] = (h[2] + c) & _mask32;
      h[3] = (h[3] + d) & _mask32;
      h[4] = (h[4] + e) & _mask32;
      h[5] = (h[5] + f) & _mask32;
      h[6] = (h[6] + g) & _mask32;
      h[7] = (h[7] + hh) & _mask32;
    }

    // 3. The 8 state words, big-endian, are the hash.
    final out = Uint8List(32);
    for (var i = 0; i < 8; i++) {
      out[4 * i] = (h[i] >> 24) & 0xFF;
      out[4 * i + 1] = (h[i] >> 16) & 0xFF;
      out[4 * i + 2] = (h[i] >> 8) & 0xFF;
      out[4 * i + 3] = h[i] & 0xFF;
    }
    return out;
  }

  /// Rotates the 32-bit word [x] right by [n] bits (bits that fall off the
  /// right come back on the left).
  static int _rotr(int x, int n) => ((x >> n) | (x << (32 - n))) & _mask32;

  // ───────────────────────────────────────────────────────────────────────
  // 9. SIGNATURES (RSA, PKCS#1 v1.5, RFC 8017 section 8.2)
  // The reverse use of a key pair: SIGN with your private key, and anyone
  // can VERIFY with your public key. A valid signature proves the data came
  // from you and wasn't changed. What gets signed is the SHA-256 hash of the
  // data, padded to the size of n:
  //   00 01 FF FF ... FF 00 [SHA-256 label][32-byte hash]
  //   sign:    s = padded^d mod n
  //   verify:  s^e mod n must equal the padded hash again
  // ───────────────────────────────────────────────────────────────────────

  // The standard label that says "this is a SHA-256 hash" inside a
  // signature (RFC 8017, section 9.2, note 1).
  static const List<int> _sha256Label = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, //
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
  ];

  /// The smallest RSA key, in bytes, that can hold a signature block:
  /// label + hash (51 bytes) + at least 11 bytes of padding = 62 bytes.
  static const int _minSignBytes = 62;

  /// The padded block that gets signed for [message], exactly [k] bytes:
  /// 00 01 FF..FF 00 [label][hash].
  static Uint8List _signatureBlock(List<int> message, int k) {
    final labelAndHash = [..._sha256Label, ...sha256(message)]; // 51 bytes
    final block = Uint8List(k); // starts as all zeros
    block[1] = 0x01;
    block.fillRange(2, k - labelAndHash.length - 1, 0xFF);
    // block[k - 52] stays 0: it marks where the label starts.
    block.setRange(k - labelAndHash.length, k, labelAndHash);
    return block;
  }

  /// Signs [message] with [privateKey]: s = (padded hash)^d mod n.
  /// Returns base64. Needs a key of at least 496 bits (the app uses 1024).
  static String sign(List<int> message, RsaPrivateKey privateKey) {
    final k = _byteLength(privateKey.n);
    if (k < _minSignBytes) {
      throw ArgumentError('A ${privateKey.n.bitLength}-bit RSA key is too '
          'small to sign; it needs at least ${_minSignBytes * 8} bits.');
    }
    final m = _bytesToInt(_signatureBlock(message, k));
    return base64Encode(_intToBytes(modPow(m, privateKey.d, privateKey.n), k));
  }

  /// True if [signature] was made with the private key matching [publicKey]
  /// for exactly this [message]. Undoes the signature (s^e mod n) and
  /// compares it with the padded hash of [message], byte for byte.
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
      return false; // not even base64
    }
    final s = _bytesToInt(bytes);
    if (bytes.length != k || s >= publicKey.n) return false;

    final block = _intToBytes(modPow(s, publicKey.e, publicKey.n), k);
    final expected = _signatureBlock(message, k);
    // Compare every byte (no early exit, so timing reveals nothing).
    var diff = 0;
    for (var i = 0; i < k; i++) {
      diff |= block[i] ^ expected[i];
    }
    return diff == 0;
  }
}

// ═════════════════════════════════════════════════════════════════════════
// 10. BYTE HELPERS
// RSA works on numbers, but keys are stored and sent as bytes. These turn
// one into the other using big-endian order (most significant byte first),
// the same order you'd write the number in hex:
//
//   65537 = 0x010001  <->  bytes [01, 00, 01]  <->  base64 "AQAB"
// ═════════════════════════════════════════════════════════════════════════

/// Number of bytes needed to hold [v]. bitLength rounded up to whole bytes,
/// e.g. 17 bits -> 3 bytes, 1024 bits -> 128 bytes.
int _byteLength(BigInt v) => (v.bitLength + 7) ~/ 8;

/// Big-endian bytes to a number.
/// [01, 00, 01] -> 1, then 1 * 256 + 0 = 256, then 256 * 256 + 1 = 65537.
BigInt _bytesToInt(List<int> bytes) {
  var result = BigInt.zero;
  for (final b in bytes) {
    // Shifting left by 8 bits multiplies by 256, making room for the next
    // byte; "| b" then puts the byte in that space.
    result = (result << 8) | BigInt.from(b);
  }
  return result;
}

/// A number to exactly [length] big-endian bytes (zero-padded on the left).
/// The reverse of [_bytesToInt]: fills the output from the last byte back,
/// taking the lowest 8 bits each time.
Uint8List _intToBytes(BigInt v, int length) {
  final out = Uint8List(length); // starts as zeros, so unused bytes stay 0
  var rest = v;
  for (var i = length - 1; i >= 0; i--) {
    out[i] = (rest & _byteMask).toInt(); // lowest 8 bits
    rest >>= 8; // drop them (divide by 256)
  }
  return out;
}

/// 0xFF = 1111 1111: "& _byteMask" keeps only the lowest 8 bits.
final BigInt _byteMask = BigInt.from(0xFF);

/// A number as base64 text, for storing in the database or on the device.
String _toBase64(BigInt v) => base64Encode(_intToBytes(v, _byteLength(v)));

/// Reads a number written by [_toBase64]. Throws if the field is missing.
BigInt _fromBase64(Object? v) {
  if (v is! String) throw const FormatException('Missing RSA key field.');
  return _bytesToInt(base64Decode(v));
}
