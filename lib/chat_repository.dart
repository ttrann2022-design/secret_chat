// Data layer of Secret Chat: the models and every read/write to Firebase
// (Auth for accounts, Realtime Database for everything else). The screens
// in main.dart only talk to the database through the [repo] defined here.
// The crypto itself lives in crypto/; this file only stores and fetches
// its results.
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
// KeyManager.loadOrCreateKeyPair), never in the database.
//
// A roomId is the two user ids sorted and joined with "_", so both people
// work out the same id without storing or looking it up.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:firebase_auth/firebase_auth.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_database/firebase_database.dart';

import 'crypto/key_manager.dart';

//  CONFIG

/// Address of the Firebase Realtime Database that holds all app data.
const String kDatabaseUrl =
    'https://personalnote-37151-default-rtdb.firebaseio.com';

/// Files are stored inside the Realtime Database as base64 (see sendFile).
/// 5 MB raw ≈ 6.7 MB base64, safely under the database's 10 MB per-value limit.
const int kMaxFileBytes = 5 * 1024 * 1024;

//  MODELS
//
// Plain data classes. Each fromSnapshot factory turns a raw database node
// into a typed object and falls back to safe defaults for missing fields.

/// An error whose message is written to be shown to the user as-is.
class AppError implements Exception {
  AppError(this.message);
  final String message;

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

  final String fromUid;
  final String fromCode;
  final int createdAt;

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

  final String id;
  final String senderId;
  final String type; // 'text' | 'file'

  /// For 'text': the message. For 'file': the file name.
  final String text;

  /// For 'file': the key of its bytes under files/{roomId}/. Null for text.
  final String? fileId;

  /// For 'file': size in bytes. 0 for text.
  final int fileSize;

  /// When it was sent (server time, ms since epoch).
  final int timestamp;

  bool get isFile => type == 'file';

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

//  REPOSITORY — all Firebase access

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

  final FirebaseAuth auth;
  final FirebaseDatabase db;

  // No 0/O or 1/I so codes are easy to read aloud and type.
  static const String _codeChars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

  // Cryptographically secure, so codes can't be predicted from earlier ones.
  final Random _rng = Random.secure();

  // Cached result of ensureProfile(), so the work runs once per sign-in.
  Future<String>? _profileFuture;

  // Cached result of ensureKeys(). Separate from the profile, so a key
  // problem never stops your code from loading.
  Future<RsaKeyPair>? _keysFuture;
  RsaKeyPair? _keyPair;

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

  //  auth
  // These throw FirebaseAuthException on failure (see AuthScreen).

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
    KeyManager.forgetRoomKeys();
    await auth.signOut();
  }

  //  profile + unique code

  /// Makes sure the signed-in user has a profile and a unique 8-char code.
  /// Safe to call many times; it only does the work once per session.
  /// The code is random and has nothing to do with the RSA keys
  /// (see ensureKeys).
  Future<String> ensureProfile() => _profileFuture ??= _ensureProfileOnce();

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

  //  keys (hybrid scheme: RSA wraps one AES key per room)

  /// Your RSA key pair. Available once ensureKeys() has finished.
  RsaKeyPair get keyPair =>
      _keyPair ?? (throw AppError('Your keys are not loaded yet.'));

  /// Makes sure the signed-in user has an RSA key pair and that its public
  /// key is published. Right after registering, this is what creates the
  /// keys. Safe to call many times; it only does the work once per session.
  Future<RsaKeyPair> ensureKeys() => _keysFuture ??= _ensureKeysOnce();

  Future<RsaKeyPair> _ensureKeysOnce() async {
    try {
      final user = auth.currentUser;
      if (user == null) throw AppError('Not signed in.');
      // The pair is saved on the device before the public key is published,
      // so a public key is never live without its private key.
      final pair = await KeyManager.loadOrCreateKeyPair(user.uid);
      await _publishPublicKey(user.uid, pair.publicKey);
      return _keyPair = pair;
    } catch (_) {
      _keysFuture = null; // allow a retry
      rethrow;
    }
  }

  /// Writes [publicKey] to users/{uid}/publicKey, unless it's already there.
  Future<void> _publishPublicKey(String forUid, RsaPublicKey publicKey) async {
    final publicJson = publicKey.toJson();
    final published = await ref('users/$forUid/publicKey').get();
    if (asMap(published.value)['n'] != publicJson['n']) {
      await ref('users/$forUid/publicKey').set(publicJson);
    }
  }

  /// Another user's published RSA public key.
  Future<RsaPublicKey> publicKeyOf(String userUid) async {
    final snap = await ref('users/$userUid/publicKey').get();
    if (!snap.exists) {
      throw AppError(
        "They don't have encryption keys yet. Ask them to open the app, "
        'then try again.',
      );
    }
    return RsaPublicKey.fromJson(asMap(snap.value));
  }

  /// The AES key of a room: your wrapped copy from rooms/{roomId}/keys,
  /// unwrapped with your RSA private key. Use it to encrypt and decrypt
  /// the room's messages and files.
  Future<Uint8List> roomKey(String roomId) async {
    final keys = await ensureKeys();
    final snap = await ref('rooms/$roomId/keys/$uid').get();
    if (snap.value is! String) {
      throw AppError('This chat has no key. Remove the contact and add them '
          'again.');
    }
    try {
      return KeyManager.unwrapRoomKey(snap.value as String, keys.privateKey);
    } on FormatException {
      throw AppError("This chat's key can't be unlocked on this device.");
    }
  }

  //  contacts
  // The *Stream methods emit a new value every time the data changes, so
  // the UI updates live without refreshing.

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

  //  messages

  /// The newest 500 messages of a room, oldest first. push() keys sort by
  /// creation time, so ordering by key orders by time.
  Stream<List<ChatMessage>> messagesStream(String roomId) =>
      ref('rooms/$roomId/messages')
          .orderByKey()
          .limitToLast(500)
          .onValue
          .map(
            (e) => e.snapshot.children.map(ChatMessage.fromSnapshot).toList(),
          );

  /// Adds a text message under a new push() key.
  Future<void> sendText(String roomId, String text) =>
      ref('rooms/$roomId/messages').push().set({
        'senderId': uid,
        'type': 'text',
        'text': text,
        'timestamp': ServerValue.timestamp,
      });

  /// File bytes go to files/{roomId}/{fileId} as base64; the chat message
  /// only holds a pointer + the file name. Both are written atomically.
  Future<void> sendFile(String roomId, String fileName, Uint8List bytes) async {
    // push().key only creates unique ids on the device; nothing is written
    // until the update() below.
    final fileId = ref('files/$roomId').push().key!;
    final msgId = ref('rooms/$roomId/messages').push().key!;

    await ref().update({
      'files/$roomId/$fileId': {'data': base64Encode(bytes)},
      'rooms/$roomId/messages/$msgId': {
        'senderId': uid,
        'type': 'file',
        'text': fileName,
        'fileId': fileId,
        'fileSize': bytes.length,
        'timestamp': ServerValue.timestamp,
      },
    });
  }

  /// Fetches a file's bytes. Throws if the chat was wiped in the meantime.
  Future<Uint8List> downloadFile(String roomId, String fileId) async {
    final snap = await ref('files/$roomId/$fileId').get();
    if (!snap.exists) throw AppError('This file no longer exists.');
    final m = asMap(snap.value);
    // Older files kept the data under "body".
    return base64Decode((m['data'] ?? m['body'] ?? '').toString());
  }
}

//  HELPERS

/// Realtime Database returns `Map<Object?, Object?>`; normalize to String keys.
Map<String, dynamic> asMap(Object? v) => v is Map
    ? v.map<String, dynamic>((k, val) => MapEntry(k.toString(), val))
    : <String, dynamic>{};

/// Reads a number from the database. Anything else (null, text) becomes 0.
int asInt(Object? v) => v is num ? v.toInt() : 0;
