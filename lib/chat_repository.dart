// Data layer of Secret Chat: the models and every read/write to Firebase
// (Auth for accounts, Realtime Database for everything else). The screens
// in main.dart only talk to the database through the [repo] defined here.
// The crypto itself lives in crypto/; this file only stores and fetches
// its results.
//
// Sections in this file:
//    1. CONFIG               fixed settings (database address, file limit)
//    2. DATA MODELS          Contact, ContactRequest, ChatMessage, ...
//    3. FIREBASE CONNECTION  the repo object and small shared tools
//    4. ACCOUNTS             register, log in, log out
//    5. PROFILE & CODE       your profile and personal 8-character code
//    6. YOUR KEYS (RSA)      your key pair: create, check, restore, replace
//    7. ROOM KEYS (AES)      unlocking each chat's secret AES key
//    8. CONTACTS & REQUESTS  add, accept, decline and remove contacts
//    9. MESSAGES & FILES     send and read messages and files (encrypted)
//   10. HELPERS              small functions for reading database values
//
// Database layout:
//   users/{uid}                   {email, code, createdAt,  your profile
//                                  publicKey: {n, e}}       + RSA public key
//   codes/{code}                  uid                       who owns a code
//   requests/{toUid}/{fromUid}    {fromCode, createdAt}     pending requests
//   contacts/{uid}/{peerUid}      {code, roomId, since}     one entry per side
//   rooms/{roomId}/meta           {members, createdAt}
//   rooms/{roomId}/messages/{id}  {senderId, type, text, fileId, fileSize,
//                                  timestamp}
//   files/{roomId}/{fileId}       {data}                    base64 file bytes
//   rooms/{roomId}/keys/{uid}     base64                    the room's AES key,
//                                                           RSA-wrapped for uid
//
// Each user's RSA private key is kept only on their device (see
// KeyManager.saveKeyPair), never in the database. The user saves a copy
// themselves, to restore it on a new device (see checkKeys).
//
// A roomId is the two user ids sorted and joined with "_", so both people
// work out the same id without storing or looking it up.

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
// Fixed settings used by the whole data layer.
// ═════════════════════════════════════════════════════════════════════════

/// Address of the Firebase Realtime Database that holds all app data.
const String kDatabaseUrl =
    'https://personalnote-37151-default-rtdb.firebaseio.com';

/// Files are stored inside the Realtime Database as base64 (see sendFile).
/// 5 MB raw ≈ 6.7 MB base64, safely under the database's 10 MB per-value limit.
const int kMaxFileBytes = 5 * 1024 * 1024;

// ═════════════════════════════════════════════════════════════════════════
// 2. DATA MODELS
// Plain data classes that the screens work with. Each fromSnapshot factory
// turns a raw database entry into a typed object, and uses safe defaults
// when a field is missing, so a broken entry never crashes the app.
// ═════════════════════════════════════════════════════════════════════════

/// What [ChatRepository.checkKeys] found on this device.
enum KeyStatus {
  /// Your key pair is loaded; the app can be used.
  ready,

  /// Your account has a public key, but this device doesn't have the
  /// matching private key. The user must restore it or make a new pair.
  missing,
}

/// An error whose message is written to be shown to the user as-is.
class AppError implements Exception {
  AppError(this.message);

  /// The text shown to the user, e.g. "No user has the code ABCD2345."
  final String message;

  /// Makes `'error: $e'` print just the message.
  @override
  String toString() => message;
}

/// Someone you have accepted as a contact.
/// Stored at contacts/{myUid}/{theirUid}.
class Contact {
  const Contact({required this.uid, required this.code, required this.since});

  /// Their Firebase user id (the key of the database node).
  final String uid;

  /// Their 8-char code. The UI shows only this, never their email.
  final String code;

  /// When you became contacts (server time, ms since epoch).
  final int since;

  /// Builds a Contact from one entry of contacts/{myUid}.
  /// A missing code shows as "????????".
  factory Contact.fromSnapshot(DataSnapshot s) {
    final m = asMap(s.value);
    return Contact(
      uid: s.key ?? '',
      code: (m['code'] ?? '????????').toString(),
      since: asInt(m['since']),
    );
  }
}

/// A contact request someone sent you that you have not answered yet.
/// Stored at requests/{myUid}/{fromUid}.
class ContactRequest {
  const ContactRequest({
    required this.fromUid,
    required this.fromCode,
    required this.createdAt,
  });

  /// The Firebase user id of the person who sent it.
  final String fromUid;

  /// Their 8-char code, shown in the pop-up ("from ABCD2345").
  final String fromCode;

  /// When it was sent (server time, ms since epoch). Used to show the
  /// oldest request first.
  final int createdAt;

  /// Builds a ContactRequest from one entry of requests/{myUid}.
  factory ContactRequest.fromSnapshot(DataSnapshot s) {
    final m = asMap(s.value);
    return ContactRequest(
      fromUid: s.key ?? '',
      fromCode: (m['fromCode'] ?? '????????').toString(),
      createdAt: asInt(m['createdAt']),
    );
  }
}

/// One message in a chat room. Stored at rooms/{roomId}/messages/{id}.
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

  /// The message's database key. Keys sort by time, oldest first.
  final String id;

  /// The user id of whoever sent it (used to show "[you]" or their code).
  final String senderId;

  /// 'text' for a normal message, 'file' for a file.
  final String type;

  /// For 'text': the message. For 'file': the file name.
  final String text;

  /// For 'file': the key of its bytes under files/{roomId}/. Null for text.
  final String? fileId;

  /// For 'file': size in bytes. 0 for text.
  final int fileSize;

  /// When it was sent (server time, ms since epoch).
  final int timestamp;

  /// True if this message is a file rather than text.
  bool get isFile => type == 'file';

  /// Builds a ChatMessage from one entry of rooms/{roomId}/messages, exactly
  /// as stored (still encrypted; messagesStream decrypts it afterwards).
  factory ChatMessage.fromSnapshot(DataSnapshot s) {
    final m = asMap(s.value);
    return ChatMessage(
      id: s.key ?? '',
      senderId: (m['senderId'] ?? '').toString(),
      type: (m['type'] ?? 'text').toString(),
      // Older messages kept the text inside packet.body.
      text: (m['text'] ?? asMap(m['packet'])['body'] ?? '').toString(),
      fileId: m['fileId']?.toString(),
      fileSize: asInt(m['fileSize']),
      timestamp: asInt(m['timestamp']),
    );
  }
}

// ═════════════════════════════════════════════════════════════════════════
// 3. FIREBASE CONNECTION
// The ChatRepository object is the app's only door to Firebase. It holds
// the connection to Firebase Auth (accounts) and the Realtime Database
// (everything else), plus small tools every other section uses.
// Sections 4-9 are all methods of this same class.
// ═════════════════════════════════════════════════════════════════════════

/// The single repository the whole UI uses (main Firebase app).
final ChatRepository repo = ChatRepository();

/// Wraps Firebase Auth and the Realtime Database. Screens call these
/// methods instead of reading or writing database paths themselves.
class ChatRepository {
  /// [app] defaults to the main Firebase app. Tests pass a second app so two
  /// users can be signed in at the same time.
  ChatRepository([FirebaseApp? app])
    : auth = FirebaseAuth.instanceFor(app: app ?? Firebase.app()),
      db = FirebaseDatabase.instanceFor(
        app: app ?? Firebase.app(),
        databaseURL: kDatabaseUrl,
      );

  /// Firebase Auth: who is signed in.
  final FirebaseAuth auth;

  /// The Realtime Database that stores profiles, contacts, rooms and files.
  final FirebaseDatabase db;

  // No 0/O or 1/I so codes are easy to read aloud and type.
  static const String _codeChars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

  // Cryptographically secure, so codes can't be predicted from earlier ones.
  final Random _rng = Random.secure();

  // Cached result of ensureProfile(), so the work runs once per sign-in.
  Future<String>? _profileFuture;

  // Cached result of checkKeys(). Separate from the profile, so a key
  // problem never stops your code from loading.
  Future<KeyStatus>? _keysFuture;
  RsaKeyPair? _keyPair;
  String? _unsavedPrivateKey;

  /// True once your key pair is loaded on this device. The incoming-request
  /// pop-up waits for this.
  final ValueNotifier<bool> keysReady = ValueNotifier(false);

  /// The signed-in user's id. Throws if nobody is signed in.
  String get uid => auth.currentUser!.uid;

  /// Shortcut for a database reference. No path means the database root.
  DatabaseReference ref([String? path]) => db.ref(path);

  /// The room id two users share. Sorting the ids first gives the same
  /// result whichever user calls it: roomIdFor('b', 'a') == 'a_b'.
  static String roomIdFor(String a, String b) {
    final pair = [a, b]..sort();
    return '${pair[0]}_${pair[1]}';
  }

  // ───────────────────────────────────────────────────────────────────────
  // 4. ACCOUNTS (Firebase Auth)
  // Register, log in and log out with email + password. Firebase checks the
  // password; these methods throw FirebaseAuthException on failure, which
  // the login screen turns into a readable message.
  // ───────────────────────────────────────────────────────────────────────

  /// Creates a new account and signs it in.
  Future<void> register(String email, String password) =>
      auth.createUserWithEmailAndPassword(email: email, password: password);

  /// Signs in to an existing account.
  Future<void> login(String email, String password) =>
      auth.signInWithEmailAndPassword(email: email, password: password);

  /// Signs out and forgets the cached code and keys, so the next user who
  /// signs in on this device loads their own.
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
  // Every user gets a random 8-character code (like K7QM2XPA) the first time
  // they sign in. Friends add each other by code, so nobody ever sees
  // anyone's email. The code is saved in users/{uid} and reserved in
  // codes/{code} so two users can never share one.
  // ───────────────────────────────────────────────────────────────────────

  /// Makes sure the signed-in user has a profile and a unique 8-char code.
  /// Safe to call many times; it only does the work once per session.
  /// The code is random and has nothing to do with the RSA keys
  /// (see ensureKeys).
  Future<String> ensureProfile() => _profileFuture ??= _ensureProfileOnce();

  /// The real work of [ensureProfile]: loads your code, or on first sign-in
  /// reserves a new one and saves your profile. Clears the cache on failure
  /// so the "tap to retry" button can try again.
  Future<String> _ensureProfileOnce() async {
    try {
      final user = auth.currentUser;
      if (user == null) throw AppError('Not signed in.');

      final existing = await ref('users/${user.uid}/code').get();
      final String code;
      if (existing.value is String) {
        // Returning user: keep the code they already have.
        code = existing.value as String;
      } else {
        // First sign-in: reserve a fresh code, then save the profile.
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

  /// 8 random characters from [_codeChars] (32^8, about 1.1 trillion codes).
  String _randomCode() => List.generate(
    8,
    (_) => _codeChars[_rng.nextInt(_codeChars.length)],
  ).join();

  /// Reserves a code by writing codes/{code} = uid inside a transaction.
  /// The transaction only commits if nobody owns the code yet, so two users
  /// can never end up with the same one. Gives up after 8 tries.
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
        // Collision or rule rejection: try another code.
      }
    }
    throw AppError('Could not generate a unique code. Try again.');
  }

  // ───────────────────────────────────────────────────────────────────────
  // 6. YOUR ENCRYPTION KEYS (RSA key pair)
  // Every user has one RSA key pair. The PUBLIC key is saved in
  // users/{uid}/publicKey so friends can lock room keys for you. The
  // PRIVATE key stays on your device only (and in the backup you saved).
  // This section decides what the key setup screens show:
  //   new account  -> make a pair, show the private key to save
  //   same device  -> load the pair, nothing to show
  //   new device   -> ask for the saved private key, or make a new pair
  //                   (which wipes your chats, see replaceKeys)
  // The RSA math itself is in crypto/key_manager.dart.
  // ───────────────────────────────────────────────────────────────────────

  /// Your RSA key pair. Available once checkKeys() returned ready.
  RsaKeyPair get keyPair =>
      _keyPair ?? (throw AppError('Your keys are not loaded yet.'));

  /// Finds out, once per sign-in, whether this device has your private key:
  ///
  ///   key on this device (matches the published one)  -> ready
  ///   no key anywhere (a brand-new account)            -> ready, after
  ///       making a new pair; [unsavedPrivateKey] is then set so the app
  ///       shows it to the user to save
  ///   public key published, but no matching private key on this device
  ///       (new phone, reinstall, or a new pair made on another device)
  ///                                                    -> missing: the user
  ///       must [restorePrivateKey] or [replaceKeys] before anything else
  Future<KeyStatus> checkKeys() => _keysFuture ??= _checkKeysOnce();

  /// The real work of [checkKeys]: compares the key pair saved on this
  /// device with the public key in Firebase and picks one of the three
  /// cases above. Clears the cache on failure so it can be retried.
  Future<KeyStatus> _checkKeysOnce() async {
    try {
      final user = auth.currentUser;
      if (user == null) throw AppError('Not signed in.');
      final local = await KeyManager.loadKeyPair(user.uid);
      final published = await _publishedKey(user.uid);

      if (local != null &&
          (published == null || published.n == local.publicKey.n)) {
        // Accounts from before keys were published still need it written.
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

  /// Your key pair, for code that needs it (requests, opening a room).
  /// Throws if this device is still waiting for your private key.
  Future<RsaKeyPair> ensureKeys() async {
    if (await checkKeys() == KeyStatus.missing) {
      throw AppError('Enter your private key first, or generate a new one.');
    }
    return keyPair;
  }

  /// The private key of a key pair made in this session (new account or
  /// [replaceKeys]) that the user hasn't confirmed saving yet, else null.
  String? get unsavedPrivateKey => _unsavedPrivateKey;

  /// Call when the user confirmed they saved [unsavedPrivateKey].
  void confirmPrivateKeySaved() => _unsavedPrivateKey = null;

  /// Your private key as text, to show the user so they can save it.
  String exportPrivateKey() => KeyManager.exportPrivateKey(keyPair.privateKey);

  /// Restores your key pair on this device from the private key you saved.
  /// Throws AppError if it isn't the key for your published public key.
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

  /// Gives you a new key pair when the old private key is lost.
  ///
  /// Messages locked with the old key can never be read again, so for every
  /// contact, in ONE atomic write: the room's messages and files are
  /// deleted, and the room gets a new AES key locked with the contact's
  /// public key and your new one. Contacts are kept. Your new public key is
  /// published in the same write. [unsavedPrivateKey] is set afterwards.
  Future<void> replaceKeys() async {
    final pair = await _startNewKeyPair(uid, publish: false);
    final changes = <String, Object?>{
      'users/$uid/publicKey': pair.publicKey.toJson(),
    };
    final contacts = await ref('contacts/$uid').get();
    for (final contact in contacts.children) {
      final peerUid = contact.key!;
      final roomId = roomIdFor(uid, peerUid);
      final peerKey = await _publishedKey(peerUid);
      changes['rooms/$roomId/messages'] = null;
      changes['files/$roomId'] = null;
      changes['rooms/$roomId/keys'] = KeyManager.createRoomKey({
        uid: pair.publicKey,
        peerUid: ?peerKey, // skipped if they have no public key
      });
    }
    await ref().update(changes);
    _keysFuture = Future.value(KeyStatus.ready);
  }

  /// Makes a new key pair, saves it on this device, and (unless [publish]
  /// is false) publishes its public key. The pair is saved before it's
  /// published, so a public key is never live without its private key.
  Future<RsaKeyPair> _startNewKeyPair(
    String forUid, {
    bool publish = true,
  }) async {
    final pair = KeyManager.generate();
    await KeyManager.saveKeyPair(forUid, pair);
    if (publish) await _publish(forUid, pair.publicKey);
    _useKeys(pair);
    _unsavedPrivateKey = KeyManager.exportPrivateKey(pair.privateKey);
    return pair;
  }

  /// Makes [pair] the key pair in use and tells the app the keys are ready
  /// (this unblocks the incoming-request pop-up).
  void _useKeys(RsaKeyPair pair) {
    _keyPair = pair;
    keysReady.value = true;
  }

  /// Saves [publicKey] to users/{uid}/publicKey so others can find it.
  Future<void> _publish(String forUid, RsaPublicKey publicKey) =>
      ref('users/$forUid/publicKey').set(publicKey.toJson());

  /// The public key in users/{uid}/publicKey, or null if there is none.
  Future<RsaPublicKey?> _publishedKey(String userUid) async {
    final snap = await ref('users/$userUid/publicKey').get();
    return snap.exists ? RsaPublicKey.fromJson(asMap(snap.value)) : null;
  }

  /// Another user's published RSA public key.
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
  // Each chat room has ONE secret AES key, shared by its two members. It is
  // never stored as-is: Firebase only keeps two LOCKED copies, one per
  // member, at rooms/{roomId}/keys/{uid} (each locked with that member's
  // RSA public key). To use it, a member reads their own locked copy and
  // unlocks it with their private key. The real key only lives in memory.
  // ───────────────────────────────────────────────────────────────────────

  /// Your locked copy of a room's AES key, as stored in
  /// rooms/{roomId}/keys/{uid} (RSA-encrypted with your public key).
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

  /// The real AES key of a room: [lockedRoomKey] decrypted with your RSA
  /// private key by MessageCipher.unlockRoomKey. Section 9 passes it as
  /// `key` to the encrypt/decrypt functions in cipher.dart.
  Future<Uint8List> roomKey(String roomId) async {
    final keys = await ensureKeys();
    final locked = await lockedRoomKey(roomId);
    try {
      return MessageCipher.unlockRoomKey(locked, keys.privateKey);
    } on FormatException {
      throw AppError("This chat's key can't be unlocked on this device.");
    }
  }

  // ───────────────────────────────────────────────────────────────────────
  // 8. CONTACTS & REQUESTS
  // How two people become contacts:
  //   1. Alice types Bob's code -> a request lands in requests/{bobUid}.
  //   2. Bob sees a pop-up and accepts -> both contact entries, the chat
  //      room and its locked AES keys are created in one atomic write.
  // Removing a contact deletes it on both sides together with the whole
  // chat. The *Stream methods send a new value every time the data
  // changes, so the screens update live without refreshing.
  // ───────────────────────────────────────────────────────────────────────

  /// Your contacts, sorted by code.
  Stream<List<Contact>> contactsStream() => ref('contacts/$uid').onValue.map(
    (e) =>
        e.snapshot.children.map(Contact.fromSnapshot).toList()
          ..sort((a, b) => a.code.compareTo(b.code)),
  );

  /// Whether [peerUid] is still your contact. The chat screen uses this to
  /// notice when the other person removes you.
  Stream<bool> contactExists(String peerUid) =>
      ref('contacts/$uid/$peerUid').onValue.map((e) => e.snapshot.exists);

  /// Pending requests sent to [forUid], oldest first.
  Stream<List<ContactRequest>> requestsStream(String forUid) =>
      ref('requests/$forUid').onValue.map(
        (e) =>
            e.snapshot.children.map(ContactRequest.fromSnapshot).toList()
              ..sort((a, b) => a.createdAt.compareTo(b.createdAt)),
      );

  /// Sends a contact request to the user who owns [rawCode].
  /// Returns the normalized code on success.
  Future<String> sendRequest(String rawCode) async {
    final code = rawCode.trim().toUpperCase();
    if (code.length != 8) throw AppError('Codes are 8 characters long.');

    // Find out who owns the code.
    final lookup = await ref('codes/$code').get();
    if (lookup.value is! String) throw AppError('No user has the code $code.');
    final targetUid = lookup.value as String;

    if (targetUid == uid) throw AppError("That's your own code.");
    if ((await ref('contacts/$uid/$targetUid').get()).exists) {
      throw AppError('$code is already in your contacts.');
    }
    // A request from them is already in YOUR inbox.
    if ((await ref('requests/$uid/$targetUid').get()).exists) {
      throw AppError('$code already sent you a request. Answer it first.');
    }

    // Your public key must be published before they can accept, because
    // accepting wraps the room key with it.
    await ensureKeys();

    // Put the request in THEIR inbox. Keyed by your uid, so sending again
    // overwrites the old request instead of adding a duplicate.
    final myCode = await ensureProfile();
    await ref('requests/$targetUid/$uid')
        .set({'fromCode': myCode, 'createdAt': ServerValue.timestamp});
    return code;
  }

  /// Accepting creates both contact entries + the room in ONE atomic write.
  ///
  /// It also creates the room's AES key and stores it twice, each copy
  /// wrapped with one member's RSA public key, so each member can unwrap
  /// only their own copy. The plain AES key is never written anywhere.
  Future<void> acceptRequest(ContactRequest r) async {
    final myCode = await ensureProfile();
    final myKeys = await ensureKeys();
    final roomId = roomIdFor(uid, r.fromUid);
    final peerPublicKey = await publicKeyOf(r.fromUid);
    // A multi-path update: every path below is written, or none is.
    // Setting a path to null deletes it.
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
      // A new AES key, locked once with each member's public key.
      'rooms/$roomId/keys': KeyManager.createRoomKey({
        uid: myKeys.publicKey,
        r.fromUid: peerPublicKey,
      }),
      'requests/$uid/${r.fromUid}': null,
      'requests/${r.fromUid}/$uid': null, // in case both sent requests
    });
  }

  /// Declining just deletes the request. The sender is not notified.
  Future<void> declineRequest(ContactRequest r) =>
      ref('requests/$uid/${r.fromUid}').remove();

  /// Removes the contact on BOTH sides and wipes every message and file of
  /// that pair, atomically. Nothing of the room remains in the database.
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
  // Sending and reading a room's messages and files. Every message text,
  // file name and file is passed through the room's real AES key
  // (roomKey) before it's saved and after it's read. The encrypt/decrypt
  // functions themselves are in crypto/cipher.dart (placeholders until
  // AES is written: right now text is saved as typed).
  //   messages: rooms/{roomId}/messages/{id}
  //   files:    files/{roomId}/{fileId}  (kept apart so the message list
  //                                       stays small and fast)
  // ───────────────────────────────────────────────────────────────────────

  /// The newest 500 messages of a room, oldest first, decrypted. push()
  /// keys sort by creation time, so ordering by key orders by time.
  Stream<List<ChatMessage>> messagesStream(String roomId) =>
      ref('rooms/$roomId/messages')
          .orderByKey()
          .limitToLast(500)
          .onValue
          .asyncMap((e) async {
            final key = await roomKey(roomId); // real AES key
            return [
              for (final child in e.snapshot.children)
                await _decrypted(ChatMessage.fromSnapshot(child), key),
            ];
          });

  /// The same message with its text (or file name) decrypted.
  Future<ChatMessage> _decrypted(ChatMessage m, Uint8List key) async {
    String text;
    try {
      text = await MessageCipher.decryptText(m.text, key);
    } catch (_) {
      // e.g. a message saved before encryption existed.
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

  /// Adds a text message, encrypted, under a new push() key.
  Future<void> sendText(String roomId, String text) async {
    final key = await roomKey(roomId); // real AES key
    await ref('rooms/$roomId/messages').push().set({
      'senderId': uid,
      'type': 'text',
      'text': await MessageCipher.encryptText(text, key),
      'timestamp': ServerValue.timestamp,
    });
  }

  /// File bytes go to files/{roomId}/{fileId}; the chat message only holds
  /// a pointer + the file name. Both are encrypted and written atomically.
  Future<void> sendFile(String roomId, String fileName, Uint8List bytes) async {
    final key = await roomKey(roomId); // real AES key
    // push().key only creates unique ids on the device; nothing is written
    // until the update() below.
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

  /// Fetches a file's bytes and decrypts them. Throws if the chat was wiped
  /// in the meantime, or the file can't be decrypted.
  Future<Uint8List> downloadFile(String roomId, String fileId) async {
    final snap = await ref('files/$roomId/$fileId').get();
    if (!snap.exists) throw AppError('This file no longer exists.');
    final key = await roomKey(roomId); // real AES key
    final m = asMap(snap.value);
    // Older files kept the data under "body".
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
// Small functions for reading raw database values safely.
// ═════════════════════════════════════════════════════════════════════════

/// Realtime Database returns `Map<Object?, Object?>`; normalize to String keys.
Map<String, dynamic> asMap(Object? v) => v is Map
    ? v.map<String, dynamic>((k, val) => MapEntry(k.toString(), val))
    : <String, dynamic>{};

/// Reads a number from the database. Anything else (null, text) becomes 0.
int asInt(Object? v) => v is num ? v.toInt() : 0;
