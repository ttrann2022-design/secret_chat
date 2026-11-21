// Data layer: the models and every Firebase read/write (Auth for accounts,
// Realtime Database for everything else). Screens use it through [repo].
// The crypto itself is in crypto/; this file stores and fetches its results.
//
// Sections:
//    1. CONFIG               database address, file size limit
//    2. DATA MODELS          Contact, ContactRequest, ChatMessage, ...
//    3. FIREBASE CONNECTION  the repo object and shared helpers
//    4. ACCOUNTS             register, log in, log out
//    5. PROFILE & CODE       your profile and 8-character code
//    6. YOUR KEYS (RSA)      create, check, restore, replace your key pair
//    7. ROOM KEYS (AES)      verify and unlock each room's AES key
//    8. CONTACTS & REQUESTS  add, accept, decline, remove contacts
//    9. MESSAGES & FILES     send and read encrypted messages and files
//   10. HELPERS              safe readers for database values
//
// Database layout:
//   users/{uid}                   {email, code, createdAt, publicKey: {n, e}}
//   codes/{code}                  uid (who owns the code)
//   requests/{toUid}/{fromUid}    {fromCode, createdAt}
//   contacts/{uid}/{peerUid}      {code, roomId, since}
//   rooms/{roomId}/meta           {members, createdAt}
//   rooms/{roomId}/messages/{id}  {senderId, type, text, fileId, fileSize,
//                                  timestamp}   (text is AES-encrypted)
//   rooms/{roomId}/keys/{uid}     room AES key, RSA-wrapped for uid
//   rooms/{roomId}/keySig         {by, sig}     creator's RSA signature
//   files/{roomId}/{fileId}       {data}        AES-encrypted file, base64
//
// The RSA private key never goes to the database; it stays on the device.
// A roomId is the two uids sorted and joined with "_".

import 'dart:math';
import 'dart:typed_data';

import 'package:firebase_auth/firebase_auth.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_database/firebase_database.dart';
import 'package:flutter/foundation.dart' show ValueNotifier;

import 'crypto/key_manager.dart';
import 'crypto/cipher.dart';

// ═════════════════════════════════════════════════════════════════════════
// 1. CONFIG
// ═════════════════════════════════════════════════════════════════════════

/// Address of the Firebase Realtime Database.
const String kDatabaseUrl =
    'https://personalnote-37151-default-rtdb.firebaseio.com';

/// Max file size. 5 MB is about 6.7 MB once encrypted and base64'd, under
/// the database's 10 MB per-value limit.
const int kMaxFileBytes = 5 * 1024 * 1024;

// ═════════════════════════════════════════════════════════════════════════
// 2. DATA MODELS
// Typed versions of database entries. fromSnapshot uses safe defaults, so
// a broken entry never crashes the app.
// ═════════════════════════════════════════════════════════════════════════

/// Result of [ChatRepository.checkKeys].
enum KeyStatus {
  /// Key pair loaded; the app can be used.
  ready,

  /// The account has a public key but this device lacks the private key.
  /// The user must restore it or make a new pair.
  missing,
}

/// An error whose message can be shown to the user as-is.
class AppError implements Exception {
  AppError(this.message);

  /// User-facing text, e.g. "No user has the code ABCD2345."
  final String message;

  /// So `'error: $e'` prints just the message.
  @override
  String toString() => message;
}

/// An accepted contact. Stored at contacts/{myUid}/{theirUid}.
class Contact {
  const Contact({required this.uid, required this.code, required this.since});

  /// Their Firebase uid.
  final String uid;

  /// Their 8-char code (shown instead of their email).
  final String code;

  /// When you became contacts (ms since epoch).
  final int since;

  /// From one entry of contacts/{myUid}. Missing code -> "????????".
  factory Contact.fromSnapshot(DataSnapshot s) {
    final m = asMap(s.value);
    return Contact(
      uid: s.key ?? '',
      code: (m['code'] ?? '????????').toString(),
      since: asInt(m['since']),
    );
  }
}

/// An unanswered contact request. Stored at requests/{myUid}/{fromUid}.
class ContactRequest {
  const ContactRequest({
    required this.fromUid,
    required this.fromCode,
    required this.createdAt,
  });

  /// Sender's uid.
  final String fromUid;

  /// Sender's 8-char code.
  final String fromCode;

  /// When it was sent (ms since epoch); oldest is shown first.
  final int createdAt;

  /// From one entry of requests/{myUid}.
  factory ContactRequest.fromSnapshot(DataSnapshot s) {
    final m = asMap(s.value);
    return ContactRequest(
      fromUid: s.key ?? '',
      fromCode: (m['fromCode'] ?? '????????').toString(),
      createdAt: asInt(m['createdAt']),
    );
  }
}

/// One chat message. Stored at rooms/{roomId}/messages/{id}.
class ChatMessage {
  const ChatMessage({
    required this.id,
    required this.senderId,
    required this.type,
    required this.text,
    required this.fileId,
    required this.fileSize,
    required this.timestamp,
  });

  /// Database key (sorts by time).
  final String id;

  /// Sender's uid.
  final String senderId;

  /// 'text' or 'file'.
  final String type;

  /// Message text, or the file name for a file.
  final String text;

  /// For files: key under files/{roomId}/. Null for text.
  final String? fileId;

  /// For files: size in bytes. 0 for text.
  final int fileSize;

  /// When it was sent (ms since epoch).
  final int timestamp;

  /// True for a file message.
  bool get isFile => type == 'file';

  /// From one entry of rooms/{roomId}/messages, still encrypted
  /// (messagesStream decrypts it).
  factory ChatMessage.fromSnapshot(DataSnapshot s) {
    final m = asMap(s.value);
    return ChatMessage(
      id: s.key ?? '',
      senderId: (m['senderId'] ?? '').toString(),
      type: (m['type'] ?? 'text').toString(),
      // Older messages stored the text in packet.body.
      text: (m['text'] ?? asMap(m['packet'])['body'] ?? '').toString(),
      fileId: m['fileId']?.toString(),
      fileSize: asInt(m['fileSize']),
      timestamp: asInt(m['timestamp']),
    );
  }
}

// ═════════════════════════════════════════════════════════════════════════
// 3. FIREBASE CONNECTION
// ChatRepository is the app's only access to Firebase. Sections 4-9 are
// its methods.
// ═════════════════════════════════════════════════════════════════════════

/// The repository the whole UI uses (main Firebase app).
final ChatRepository repo = ChatRepository();

/// Wraps Firebase Auth and the Realtime Database.
class ChatRepository {
  /// [app] defaults to the main Firebase app. Tests pass other apps to sign
  /// in several users at once.
  ChatRepository([FirebaseApp? app])
    : auth = FirebaseAuth.instanceFor(app: app ?? Firebase.app()),
      db = FirebaseDatabase.instanceFor(
        app: app ?? Firebase.app(),
        databaseURL: kDatabaseUrl,
      );

  /// Firebase Auth.
  final FirebaseAuth auth;

  /// Realtime Database.
  final FirebaseDatabase db;

  // No 0/O or 1/I, so codes are easy to read and type.
  static const String _codeChars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

  // Secure random, so codes can't be predicted.
  final Random _rng = Random.secure();

  // Cached ensureProfile() result (runs once per sign-in).
  Future<String>? _profileFuture;

  // Cached checkKeys() result, plus the loaded keys. Kept separate from the
  // profile so a key problem doesn't block loading your code.
  Future<KeyStatus>? _keysFuture;
  RsaKeyPair? _keyPair;
  String? _unsavedPrivateKey;

  /// True once the key pair is loaded. The request pop-up waits for it.
  final ValueNotifier<bool> keysReady = ValueNotifier(false);

  /// Signed-in user's uid. Throws if nobody is signed in.
  String get uid => auth.currentUser!.uid;

  /// A database reference; no path = the root.
  DatabaseReference ref([String? path]) => db.ref(path);

  /// The shared room id of two users: roomIdFor('b', 'a') == 'a_b'.
  static String roomIdFor(String a, String b) {
    final pair = [a, b]..sort();
    return '${pair[0]}_${pair[1]}';
  }

  // ───────────────────────────────────────────────────────────────────────
  // 4. ACCOUNTS
  // Email + password with Firebase Auth. Failures throw
  // FirebaseAuthException, which the login screen turns into a message.
  // ───────────────────────────────────────────────────────────────────────

  /// Creates an account and signs in.
  Future<void> register(String email, String password) =>
      auth.createUserWithEmailAndPassword(email: email, password: password);

  /// Signs in.
  Future<void> login(String email, String password) =>
      auth.signInWithEmailAndPassword(email: email, password: password);

  /// Signs out and clears the cached code and keys.
  Future<void> logout() async {
    _profileFuture = null;
    _keysFuture = null;
    _keyPair = null;
    _unsavedPrivateKey = null;
    keysReady.value = false;
    KeyManager.forgetRoomKeys();
    await auth.signOut();
  }

  // ───────────────────────────────────────────────────────────────────────
  // 5. PROFILE & PERSONAL CODE
  // Each user gets a random 8-char code on first sign-in. Friends add each
  // other by code, so emails stay hidden. codes/{code} reserves it.
  // ───────────────────────────────────────────────────────────────────────

  /// Makes sure you have a profile and a unique code; returns the code.
  /// Runs once per session.
  Future<String> ensureProfile() => _profileFuture ??= _ensureProfileOnce();

  /// Loads your code, or on first sign-in reserves one and saves your
  /// profile. Clears the cache on failure so it can be retried.
  Future<String> _ensureProfileOnce() async {
    try {
      final user = auth.currentUser;
      if (user == null) throw AppError('Not signed in.');

      final existing = await ref('users/${user.uid}/code').get();
      final String code;
      if (existing.value is String) {
        // Returning user: keep their code.
        code = existing.value as String;
      } else {
        // First sign-in: reserve a code, then save the profile.
        code = await _claimUniqueCode(user.uid);
        await ref('users/${user.uid}').update({
          'email': user.email,
          'code': code,
          'createdAt': ServerValue.timestamp,
        });
      }
      return code;
    } catch (_) {
      _profileFuture = null; // allow a retry
      rethrow;
    }
  }

  /// 8 random characters from [_codeChars] (32^8 ≈ 1.1 trillion codes).
  String _randomCode() => List.generate(
    8,
    (_) => _codeChars[_rng.nextInt(_codeChars.length)],
  ).join();

  /// Reserves a code with a transaction that only commits if nobody owns
  /// it yet. Gives up after 8 tries.
  Future<String> _claimUniqueCode(String forUid) async {
    for (var attempt = 0; attempt < 8; attempt++) {
      final code = _randomCode();
      try {
        final result = await ref('codes/$code').runTransaction(
          (current) => current == null
              ? Transaction.success(forUid)
              : Transaction.abort(),
        );
        if (result.committed) return code;
      } catch (_) {
        // Taken or rejected: try another code.
      }
    }
    throw AppError('Could not generate a unique code. Try again.');
  }

  // ───────────────────────────────────────────────────────────────────────
  // 6. YOUR ENCRYPTION KEYS (RSA)
  // Public key -> users/{uid}/publicKey. Private key -> this device only.
  //   new account  -> make a pair, show the private key to save
  //   same device  -> load the saved pair
  //   new device   -> restore the saved private key, or make a new pair
  //                   (which wipes your chats, see replaceKeys)
  // ───────────────────────────────────────────────────────────────────────

  /// Your key pair. Available once checkKeys() returned ready.
  RsaKeyPair get keyPair =>
      _keyPair ?? (throw AppError('Your keys are not loaded yet.'));

  /// Checks (once per sign-in) whether this device has your private key:
  ///   saved pair matches the published key    -> ready
  ///   brand-new account (no keys anywhere)    -> ready, after making a
  ///                                              pair ([unsavedPrivateKey]
  ///                                              is set)
  ///   published key, no matching private key -> missing
  Future<KeyStatus> checkKeys() => _keysFuture ??= _checkKeysOnce();

  /// Compares the device's saved pair with the published public key.
  /// Clears the cache on failure so it can be retried.
  Future<KeyStatus> _checkKeysOnce() async {
    try {
      final user = auth.currentUser;
      if (user == null) throw AppError('Not signed in.');
      final local = await KeyManager.loadKeyPair(user.uid);
      final published = await _publishedKey(user.uid);

      if (local != null &&
          (published == null || published.n == local.publicKey.n)) {
        // Older accounts may not have published their key yet.
        if (published == null) await _publish(user.uid, local.publicKey);
        _useKeys(local);
        return KeyStatus.ready;
      }
      if (local == null && published == null) {
        await _startNewKeyPair(user.uid);
        return KeyStatus.ready;
      }
      return KeyStatus.missing;
    } catch (_) {
      _keysFuture = null; // allow a retry
      rethrow;
    }
  }

  /// Your key pair. Throws if this device still needs your private key.
  Future<RsaKeyPair> ensureKeys() async {
    if (await checkKeys() == KeyStatus.missing) {
      throw AppError('Enter your private key first, or generate a new one.');
    }
    return keyPair;
  }

  /// A newly made private key the user hasn't confirmed saving, else null.
  String? get unsavedPrivateKey => _unsavedPrivateKey;

  /// Marks [unsavedPrivateKey] as saved by the user.
  void confirmPrivateKeySaved() => _unsavedPrivateKey = null;

  /// Your private key as text, for the user to save.
  String exportPrivateKey() => KeyManager.exportPrivateKey(keyPair.privateKey);

  /// Restores your key pair from a saved private key. Throws AppError if it
  /// doesn't match your published public key.
  Future<void> restorePrivateKey(String text) async {
    final published = await _publishedKey(uid);
    if (published == null) throw AppError('Your account has no public key.');
    final RsaKeyPair pair;
    try {
      pair = KeyManager.importPrivateKey(text, published);
    } on FormatException catch (e) {
      throw AppError('${e.message} Check it and try again.');
    }
    await KeyManager.saveKeyPair(uid, pair);
    _useKeys(pair);
    _keysFuture = Future.value(KeyStatus.ready);
  }

  /// Makes a new key pair when the old private key is lost.
  ///
  /// Old messages can't be read any more, so in ONE atomic write it
  /// publishes the new public key and, for every contact, deletes the
  /// room's messages and files and gives the room a new signed AES key.
  /// Contacts are kept. The app switches to the new pair only after that
  /// write succeeds; if it fails, nothing changes and the user can retry.
  Future<void> replaceKeys() async {
    final pair = KeyManager.generate();
    // Save first, so a public key is never live without its private key.
    // If the write below fails, this pair just won't match the published one.
    await KeyManager.saveKeyPair(uid, pair);

    final changes = <String, Object?>{
      'users/$uid/publicKey': pair.publicKey.toJson(),
    };
    final contacts = await ref('contacts/$uid').get();
    for (final contact in contacts.children) {
      final peerUid = contact.key!;
      final roomId = roomIdFor(uid, peerUid);
      final peerKey = await _publishedKey(peerUid);
      final copies = KeyManager.createRoomKey({
        uid: pair.publicKey,
        peerUid: ?peerKey, // skipped if they have no public key
      });
      changes['rooms/$roomId/messages'] = null;
      changes['files/$roomId'] = null;
      changes['rooms/$roomId/keys'] = copies;
      changes['rooms/$roomId/keySig'] = _signRoomKey(
        roomId,
        copies,
        pair.privateKey,
      );
    }
    await ref().update(changes);

    // Saved: switch to the new pair.
    _useKeys(pair);
    _unsavedPrivateKey = KeyManager.exportPrivateKey(pair.privateKey);
    _keysFuture = Future.value(KeyStatus.ready);
  }

  /// First key pair of a new account: save it, publish the public key, and
  /// set [unsavedPrivateKey] so the user is shown it.
  Future<RsaKeyPair> _startNewKeyPair(String forUid) async {
    final pair = KeyManager.generate();
    await KeyManager.saveKeyPair(forUid, pair);
    await _publish(forUid, pair.publicKey);
    _useKeys(pair);
    _unsavedPrivateKey = KeyManager.exportPrivateKey(pair.privateKey);
    return pair;
  }

  /// Uses [pair] and marks the keys as ready.
  void _useKeys(RsaKeyPair pair) {
    _keyPair = pair;
    keysReady.value = true;
  }

  /// Writes [publicKey] to users/{uid}/publicKey.
  Future<void> _publish(String forUid, RsaPublicKey publicKey) =>
      ref('users/$forUid/publicKey').set(publicKey.toJson());

  /// The published public key of [userUid], or null.
  Future<RsaPublicKey?> _publishedKey(String userUid) async {
    final snap = await ref('users/$userUid/publicKey').get();
    return snap.exists ? RsaPublicKey.fromJson(asMap(snap.value)) : null;
  }

  /// Another user's public key. Throws AppError if they have none yet.
  Future<RsaPublicKey> publicKeyOf(String userUid) async {
    final key = await _publishedKey(userUid);
    if (key == null) {
      throw AppError(
        "They don't have encryption keys yet. Ask them to open the app, "
        'then try again.',
      );
    }
    return key;
  }

  // ───────────────────────────────────────────────────────────────────────
  // 7. ROOM KEYS (AES)
  // Each room's AES key is stored only as RSA-wrapped copies, one per
  // member (rooms/{roomId}/keys/{uid}), signed by its creator (keySig).
  // Before use, the signature is checked and your copy is unwrapped. The
  // real key only exists in memory.
  // ───────────────────────────────────────────────────────────────────────

  /// Your wrapped copy of a room's AES key, as stored in the database.
  Future<String> lockedRoomKey(String roomId) async {
    final snap = await ref('rooms/$roomId/keys/$uid').get();
    if (snap.value is! String) {
      throw AppError(
        'This chat has no key. Remove the contact and add them '
        'again.',
      );
    }
    return snap.value as String;
  }

  /// The room's real AES key: signature checked, then your copy unwrapped
  /// with your private key.
  Future<Uint8List> roomKey(String roomId) async {
    final keys = await ensureKeys();
    final locked = await _verifiedRoomKey(roomId);
    try {
      return MessageCipher.unlockRoomKey(locked, keys.privateKey);
    } on FormatException {
      throw AppError("This chat's key can't be unlocked on this device.");
    }
  }

  /// Checks that a room member signed exactly the stored copies, then
  /// returns your copy. Throws AppError if the signature is missing, from
  /// an outsider, or invalid.
  Future<String> _verifiedRoomKey(String roomId) async {
    final copies = {
      for (final e in asMap((await ref('rooms/$roomId/keys').get()).value)
          .entries)
        e.key: e.value.toString(),
    };
    final mine = copies[uid];
    if (mine == null) {
      throw AppError(
        'This chat has no key. Remove the contact and add them again.',
      );
    }

    final keySig = asMap((await ref('rooms/$roomId/keySig').get()).value);
    final signer = keySig['by'];
    final signature = keySig['sig'];
    // The signer must be one of the room's two members.
    if (signer is! String ||
        signature is! String ||
        !roomId.split('_').contains(signer)) {
      throw AppError(
        "This chat's key isn't signed by a member. Remove the contact and "
        'add them again.',
      );
    }
    // Your own public key is taken from this device, not the server.
    final signerKey = signer == uid
        ? keyPair.publicKey
        : await publicKeyOf(signer);
    if (!KeyManager.verifyRoomKey(roomId, copies, signature, signerKey)) {
      throw AppError(
        "This chat's key failed its security check: it may have been "
        'replaced. Remove the contact and add them again.',
      );
    }
    return mine;
  }

  /// The keySig entry: {by: your uid, sig: signature over the copies}.
  Map<String, String> _signRoomKey(
    String roomId,
    Map<String, String> copies,
    RsaPrivateKey privateKey,
  ) => {
    'by': uid,
    'sig': KeyManager.signRoomKey(roomId, copies, privateKey),
  };

  /// Safety number for your chat with [peerUid]: a hash of your public key
  /// (from this device) and theirs (from Firebase). Both sides should match.
  Future<Uint8List> safetyNumber(String peerUid) async {
    final mine = (await ensureKeys()).publicKey;
    final theirs = await publicKeyOf(peerUid);
    return KeyManager.safetyNumber({uid: mine, peerUid: theirs});
  }

  // ───────────────────────────────────────────────────────────────────────
  // 8. CONTACTS & REQUESTS
  //   1. Alice enters Bob's code -> request at requests/{bobUid}/{aliceUid}.
  //   2. Bob accepts -> contacts, room and signed room key in one write.
  // Removing a contact deletes it on both sides along with the whole room.
  // ───────────────────────────────────────────────────────────────────────

  /// Your contacts, live, sorted by code.
  Stream<List<Contact>> contactsStream() => ref('contacts/$uid').onValue.map(
    (e) =>
        e.snapshot.children.map(Contact.fromSnapshot).toList()
          ..sort((a, b) => a.code.compareTo(b.code)),
  );

  /// Whether [peerUid] is still your contact (lets the chat screen close
  /// when they remove you).
  Stream<bool> contactExists(String peerUid) =>
      ref('contacts/$uid/$peerUid').onValue.map((e) => e.snapshot.exists);

  /// Pending requests to [forUid], live, oldest first.
  Stream<List<ContactRequest>> requestsStream(String forUid) =>
      ref('requests/$forUid').onValue.map(
        (e) =>
            e.snapshot.children.map(ContactRequest.fromSnapshot).toList()
              ..sort((a, b) => a.createdAt.compareTo(b.createdAt)),
      );

  /// Sends a contact request to the owner of [rawCode]. Returns the
  /// normalized code.
  Future<String> sendRequest(String rawCode) async {
    final code = rawCode.trim().toUpperCase();
    if (code.length != 8) throw AppError('Codes are 8 characters long.');

    // Who owns the code?
    final lookup = await ref('codes/$code').get();
    if (lookup.value is! String) throw AppError('No user has the code $code.');
    final targetUid = lookup.value as String;

    if (targetUid == uid) throw AppError("That's your own code.");
    if ((await ref('contacts/$uid/$targetUid').get()).exists) {
      throw AppError('$code is already in your contacts.');
    }
    // They already sent you a request.
    if ((await ref('requests/$uid/$targetUid').get()).exists) {
      throw AppError('$code already sent you a request. Answer it first.');
    }

    // Your public key must exist: accepting wraps the room key with it.
    await ensureKeys();

    // Keyed by your uid, so sending again overwrites instead of duplicating.
    final myCode = await ensureProfile();
    await ref('requests/$targetUid/$uid')
        .set({'fromCode': myCode, 'createdAt': ServerValue.timestamp});
    return code;
  }

  /// Accepts [r] in ONE atomic write: both contact entries, the room, its
  /// new AES key wrapped for each member, and your signature over it.
  Future<void> acceptRequest(ContactRequest r) async {
    final myCode = await ensureProfile();
    final myKeys = await ensureKeys();
    final roomId = roomIdFor(uid, r.fromUid);
    final peerPublicKey = await publicKeyOf(r.fromUid);
    // New AES key, wrapped once per member.
    final copies = KeyManager.createRoomKey({
      uid: myKeys.publicKey,
      r.fromUid: peerPublicKey,
    });
    // Multi-path update: all or nothing. null deletes a path.
    await ref().update({
      'contacts/$uid/${r.fromUid}': {
        'code': r.fromCode,
        'roomId': roomId,
        'since': ServerValue.timestamp,
      },
      'contacts/${r.fromUid}/$uid': {
        'code': myCode,
        'roomId': roomId,
        'since': ServerValue.timestamp,
      },
      'rooms/$roomId/meta': {
        'members': {uid: true, r.fromUid: true},
        'createdAt': ServerValue.timestamp,
      },
      'rooms/$roomId/keys': copies,
      // Signed by you, so the peer can verify it came from a member.
      'rooms/$roomId/keySig': _signRoomKey(
        roomId,
        copies,
        myKeys.privateKey,
      ),
      'requests/$uid/${r.fromUid}': null,
      'requests/${r.fromUid}/$uid': null, // in case both sent requests
    });
  }

  /// Deletes the request. The sender isn't notified.
  Future<void> declineRequest(ContactRequest r) =>
      ref('requests/$uid/${r.fromUid}').remove();

  /// Removes the contact on both sides and deletes the whole room (messages,
  /// files, keys) in one atomic write.
  Future<void> removeContact(String peerUid) async {
    final roomId = roomIdFor(uid, peerUid);
    await ref().update({
      'contacts/$uid/$peerUid': null,
      'contacts/$peerUid/$uid': null,
      'rooms/$roomId': null,
      'files/$roomId': null,
      'requests/$uid/$peerUid': null,
      'requests/$peerUid/$uid': null,
    });
  }

  // ───────────────────────────────────────────────────────────────────────
  // 9. MESSAGES & FILES
  // Message text, file names and file bytes are AES-encrypted with the
  // room key before saving and decrypted after reading.
  //   messages: rooms/{roomId}/messages/{id}
  //   files:    files/{roomId}/{fileId}  (separate, so the message list
  //                                       stays small)
  // ───────────────────────────────────────────────────────────────────────

  /// The newest 500 messages, oldest first, decrypted. push() keys sort by
  /// time, so ordering by key orders by time.
  Stream<List<ChatMessage>> messagesStream(String roomId) =>
      ref('rooms/$roomId/messages')
          .orderByKey()
          .limitToLast(500)
          .onValue
          .asyncMap((e) async {
            final key = await roomKey(roomId);
            return [
              for (final child in e.snapshot.children)
                await _decrypted(ChatMessage.fromSnapshot(child), key),
            ];
          });

  /// [m] with its text (or file name) decrypted.
  Future<ChatMessage> _decrypted(ChatMessage m, Uint8List key) async {
    String text;
    try {
      text = await MessageCipher.decryptText(m.text, key);
    } catch (_) {
      // e.g. a message saved before encryption was added.
      text = '[could not decrypt]';
    }
    return ChatMessage(
      id: m.id,
      senderId: m.senderId,
      type: m.type,
      text: text,
      fileId: m.fileId,
      fileSize: m.fileSize,
      timestamp: m.timestamp,
    );
  }

  /// Sends an encrypted text message.
  Future<void> sendText(String roomId, String text) async {
    final key = await roomKey(roomId);
    await ref('rooms/$roomId/messages').push().set({
      'senderId': uid,
      'type': 'text',
      'text': await MessageCipher.encryptText(text, key),
      'timestamp': ServerValue.timestamp,
    });
  }

  /// Sends a file: encrypted bytes go to files/{roomId}/{fileId}, and a
  /// message with the encrypted file name points to it. Written atomically.
  Future<void> sendFile(String roomId, String fileName, Uint8List bytes) async {
    final key = await roomKey(roomId);
    // push().key only makes unique ids locally; nothing is written yet.
    final fileId = ref('files/$roomId').push().key!;
    final msgId = ref('rooms/$roomId/messages').push().key!;

    await ref().update({
      'files/$roomId/$fileId': {
        'data': await MessageCipher.encryptBytes(bytes, key),
      },
      'rooms/$roomId/messages/$msgId': {
        'senderId': uid,
        'type': 'file',
        'text': await MessageCipher.encryptText(fileName, key),
        'fileId': fileId,
        'fileSize': bytes.length,
        'timestamp': ServerValue.timestamp,
      },
    });
  }

  /// Downloads and decrypts a file. Throws AppError if it was deleted or
  /// can't be decrypted.
  Future<Uint8List> downloadFile(String roomId, String fileId) async {
    final snap = await ref('files/$roomId/$fileId').get();
    if (!snap.exists) throw AppError('This file no longer exists.');
    final key = await roomKey(roomId);
    final m = asMap(snap.value);
    // Older files stored the data under "body".
    final data = (m['data'] ?? m['body'] ?? '').toString();
    try {
      return await MessageCipher.decryptBytes(data, key);
    } catch (_) {
      throw AppError("This file can't be decrypted.");
    }
  }
}

// ═════════════════════════════════════════════════════════════════════════
// 10. HELPERS
// ═════════════════════════════════════════════════════════════════════════

/// A database value as a String-keyed map (empty if it isn't a map).
Map<String, dynamic> asMap(Object? v) => v is Map
    ? v.map<String, dynamic>((k, val) => MapEntry(k.toString(), val))
    : <String, dynamic>{};

/// A database value as an int (0 if it isn't a number).
int asInt(Object? v) => v is num ? v.toInt() : 0;
