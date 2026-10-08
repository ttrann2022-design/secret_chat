import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_database/firebase_database.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'firebase_options.dart';

//before start please make sure you seperate security stuff in to 2 different file
// put it in crypto folder.
//  0. CONFIG

const String kDatabaseUrl =
    'https://personalnote-37151-default-rtdb.firebaseio.com';

/// Files are stored inside the Realtime Database as base64 (see sendFile).
/// 5 MB raw ≈ 6.7 MB base64, safely under the database's 10 MB per-value limit.
const int kMaxFileBytes = 5 * 1024 * 1024;

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await Firebase.initializeApp(options: DefaultFirebaseOptions.currentPlatform);
  runApp(const SecretChatApp());
}

//  1. MODELS

class AppError implements Exception {
  AppError(this.message);
  final String message;

  @override
  String toString() => message;
}

class Contact {
  const Contact({
    required this.uid,
    required this.code,
    required this.email,
    required this.since,
  });

  final String uid;
  final String code;
  final String email;
  final int since;

  factory Contact.fromSnapshot(DataSnapshot s) {
    final m = asMap(s.value);
    return Contact(
      uid: s.key ?? '',
      code: (m['code'] ?? '????????').toString(),
      email: (m['email'] ?? '').toString(),
      since: asInt(m['since']),
    );
  }
}

class ContactRequest {
  const ContactRequest({
    required this.fromUid,
    required this.fromCode,
    required this.fromEmail,
    required this.createdAt,
  });

  final String fromUid;
  final String fromCode;
  final String fromEmail;
  final int createdAt;

  factory ContactRequest.fromSnapshot(DataSnapshot s) {
    final m = asMap(s.value);
    return ContactRequest(
      fromUid: s.key ?? '',
      fromCode: (m['fromCode'] ?? '????????').toString(),
      fromEmail: (m['fromEmail'] ?? '').toString(),
      createdAt: asInt(m['createdAt']),
    );
  }
}

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
  final String? fileId;
  final int fileSize;
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

//  2. REPOSITORY — all Firebase access

final ChatRepository repo = ChatRepository();

class ChatRepository {
  final FirebaseAuth auth = FirebaseAuth.instance;
  final FirebaseDatabase db = FirebaseDatabase.instanceFor(
    app: Firebase.app(),
    databaseURL: kDatabaseUrl,
  );

  // No 0/O or 1/I so codes are easy to read aloud and type.
  static const String _codeChars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  final Random _rng = Random.secure();
  Future<String>? _profileFuture;

  String get uid => auth.currentUser!.uid;

  DatabaseReference ref([String? path]) => db.ref(path);

  static String roomIdFor(String a, String b) {
    final pair = [a, b]..sort();
    return '${pair[0]}_${pair[1]}';
  }

  //  auth

  Future<void> register(String email, String password) =>
      auth.createUserWithEmailAndPassword(email: email, password: password);

  Future<void> login(String email, String password) =>
      auth.signInWithEmailAndPassword(email: email, password: password);

  Future<void> logout() async {
    _profileFuture = null;
    await auth.signOut();
  }

  //  profile + unique code

  /// Makes sure the signed-in user has a profile and a unique 8-char code.
  /// Safe to call many times; it only does the work once per session.
  Future<String> ensureProfile() => _profileFuture ??= _ensureProfileOnce();

  Future<String> _ensureProfileOnce() async {
    try {
      final user = auth.currentUser;
      if (user == null) throw AppError('Not signed in.');

      final existing = await ref('users/${user.uid}/code').get();
      final String code;
      if (existing.value is String) {
        code = existing.value as String;
      } else {
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

  String _randomCode() => List.generate(
    8,
    (_) => _codeChars[_rng.nextInt(_codeChars.length)],
  ).join();

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

  //  contacts

  Stream<List<Contact>> contactsStream() => ref('contacts/$uid').onValue.map(
    (e) =>
        e.snapshot.children.map(Contact.fromSnapshot).toList()
          ..sort((a, b) => a.code.compareTo(b.code)),
  );

  Stream<bool> contactExists(String peerUid) =>
      ref('contacts/$uid/$peerUid').onValue.map((e) => e.snapshot.exists);

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

    final lookup = await ref('codes/$code').get();
    if (lookup.value is! String) throw AppError('No user has the code $code.');
    final targetUid = lookup.value as String;

    if (targetUid == uid) throw AppError("That's your own code.");
    if ((await ref('contacts/$uid/$targetUid').get()).exists) {
      throw AppError('$code is already in your contacts.');
    }
    if ((await ref('requests/$uid/$targetUid').get()).exists) {
      throw AppError('$code already sent you a request. Answer it first.');
    }

    final myCode = await ensureProfile();
    await ref('requests/$targetUid/$uid').set({
      'fromCode': myCode,
      'fromEmail': auth.currentUser?.email ?? '',
      'createdAt': ServerValue.timestamp,
    });
    return code;
  }

  /// Accepting creates both contact entries + the room in ONE atomic write.
  Future<void> acceptRequest(ContactRequest r) async {
    final myCode = await ensureProfile();
    final roomId = roomIdFor(uid, r.fromUid);
    await ref().update({
      'contacts/$uid/${r.fromUid}': {
        'code': r.fromCode,
        'email': r.fromEmail,
        'roomId': roomId,
        'since': ServerValue.timestamp,
      },
      'contacts/${r.fromUid}/$uid': {
        'code': myCode,
        'email': auth.currentUser?.email ?? '',
        'roomId': roomId,
        'since': ServerValue.timestamp,
      },
      'rooms/$roomId/meta': {
        'members': {uid: true, r.fromUid: true},
        'createdAt': ServerValue.timestamp,
      },
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

  Stream<List<ChatMessage>> messagesStream(String roomId) =>
      ref('rooms/$roomId/messages')
          .orderByKey()
          .limitToLast(500)
          .onValue
          .map(
            (e) => e.snapshot.children.map(ChatMessage.fromSnapshot).toList(),
          );

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

  Future<Uint8List> downloadFile(String roomId, String fileId) async {
    final snap = await ref('files/$roomId/$fileId').get();
    if (!snap.exists) throw AppError('This file no longer exists.');
    final m = asMap(snap.value);
    // Older files kept the data under "body".
    return base64Decode((m['data'] ?? m['body'] ?? '').toString());
  }
}

//  3. THEME + SHARED WIDGETS

class Term {
  static const bg = Color(0xFF060A08);
  static const panel = Color(0xFF0D1410);
  static const panel2 = Color(0xFF121C16);
  static const line = Color(0xFF1E3227);
  static const green = Color(0xFF39FF88);
  static const greenDim = Color(0xFF1B6A42);
  static const mine = Color(0xFF0E2618);
  static const text = Color(0xFFD9F7E6);
  static const muted = Color(0xFF6E8C7B);
  static const red = Color(0xFFFF5D6E);
  static const amber = Color(0xFFFFC857);
  static const glow = Color(0x3339FF88);
  static const scrim = Color(0xD9020403);

  static const font = 'monospace';
  static const fontFallback = ['Menlo', 'Courier New', 'Courier', 'RobotoMono'];
}

ThemeData buildTheme() {
  OutlineInputBorder border(Color c) => OutlineInputBorder(
    borderRadius: BorderRadius.circular(12),
    borderSide: BorderSide(color: c, width: 1.2),
  );

  const buttonText = TextStyle(
    fontFamily: Term.font,
    fontFamilyFallback: Term.fontFallback,
    fontWeight: FontWeight.bold,
    letterSpacing: 1,
  );

  return ThemeData(
    useMaterial3: true,
    brightness: Brightness.dark,
    fontFamily: Term.font,
    fontFamilyFallback: Term.fontFallback,
    scaffoldBackgroundColor: Term.bg,
    colorScheme: const ColorScheme.dark(
      primary: Term.green,
      onPrimary: Term.bg,
      secondary: Term.green,
      onSecondary: Term.bg,
      surface: Term.panel,
      onSurface: Term.text,
      error: Term.red,
    ),
    appBarTheme: const AppBarTheme(
      backgroundColor: Term.bg,
      foregroundColor: Term.text,
      elevation: 0,
      scrolledUnderElevation: 0,
      centerTitle: true,
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: Term.bg,
      labelStyle: const TextStyle(color: Term.muted),
      hintStyle: const TextStyle(color: Term.muted),
      contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
      border: border(Term.line),
      enabledBorder: border(Term.line),
      focusedBorder: border(Term.green),
    ),
    elevatedButtonTheme: ElevatedButtonThemeData(
      style: ElevatedButton.styleFrom(
        backgroundColor: Term.green,
        foregroundColor: Term.bg,
        disabledBackgroundColor: Term.greenDim,
        padding: const EdgeInsets.symmetric(vertical: 14, horizontal: 18),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        textStyle: buttonText,
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        padding: const EdgeInsets.symmetric(vertical: 14, horizontal: 18),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        textStyle: buttonText,
      ),
    ),
    textButtonTheme: TextButtonThemeData(
      style: TextButton.styleFrom(foregroundColor: Term.green),
    ),
    floatingActionButtonTheme: const FloatingActionButtonThemeData(
      backgroundColor: Term.green,
      foregroundColor: Term.bg,
    ),
    snackBarTheme: const SnackBarThemeData(
      backgroundColor: Term.panel2,
      contentTextStyle: TextStyle(
        color: Term.text,
        fontFamily: Term.font,
        fontFamilyFallback: Term.fontFallback,
      ),
      behavior: SnackBarBehavior.floating,
    ),
    textSelectionTheme: const TextSelectionThemeData(cursorColor: Term.green),
  );
}

class BlinkingCursor extends StatefulWidget {
  const BlinkingCursor({super.key, this.height = 18});
  final double height;

  @override
  State<BlinkingCursor> createState() => _BlinkingCursorState();
}

class _BlinkingCursorState extends State<BlinkingCursor> {
  bool _on = true;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _timer = Timer.periodic(
      const Duration(milliseconds: 530),
      (_) => setState(() => _on = !_on),
    );
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => Opacity(
    opacity: _on ? 1 : 0,
    child: Container(
      width: widget.height * 0.55,
      height: widget.height,
      color: Term.green,
    ),
  );
}

class TerminalTitle extends StatelessWidget {
  const TerminalTitle({super.key, this.size = 22});
  final double size;

  @override
  Widget build(BuildContext context) => Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      Text(
        '> ',
        style: TextStyle(
          color: Term.green,
          fontSize: size,
          fontWeight: FontWeight.bold,
        ),
      ),
      Text(
        'Secret Chat',
        style: TextStyle(
          color: Term.text,
          fontSize: size,
          fontWeight: FontWeight.bold,
          letterSpacing: 0.5,
        ),
      ),
      const SizedBox(width: 4),
      BlinkingCursor(height: size),
    ],
  );
}

/// A rounded "terminal window" with the three traffic-light dots.
class TerminalPanel extends StatelessWidget {
  const TerminalPanel({
    super.key,
    required this.title,
    required this.child,
    this.padding = const EdgeInsets.all(18),
  });

  final String title;
  final Widget child;
  final EdgeInsets padding;

  Widget _dot(Color c) => Container(
    width: 10,
    height: 10,
    decoration: BoxDecoration(color: c, shape: BoxShape.circle),
  );

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        color: Term.panel,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: Term.line),
        boxShadow: const [
          BoxShadow(color: Term.glow, blurRadius: 28, spreadRadius: -8),
        ],
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(15),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Container(
              color: Term.panel2,
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
              child: Row(
                children: [
                  _dot(Term.red),
                  const SizedBox(width: 6),
                  _dot(Term.amber),
                  const SizedBox(width: 6),
                  _dot(Term.green),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      title,
                      overflow: TextOverflow.ellipsis,
                      style: const TextStyle(color: Term.muted, fontSize: 12),
                    ),
                  ),
                ],
              ),
            ),
            Container(height: 1, color: Term.line),
            Padding(padding: padding, child: child),
          ],
        ),
      ),
    );
  }
}

class CodeBadge extends StatelessWidget {
  const CodeBadge({super.key, required this.code});
  final String code;

  @override
  Widget build(BuildContext context) {
    return InkWell(
      borderRadius: BorderRadius.circular(10),
      onTap: () {
        Clipboard.setData(ClipboardData(text: code));
        toast(context, 'Your code $code was copied.');
      },
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
        decoration: BoxDecoration(
          color: Term.panel,
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: Term.greenDim),
          boxShadow: const [
            BoxShadow(color: Term.glow, blurRadius: 16, spreadRadius: -4),
          ],
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text(
              'id ',
              style: TextStyle(color: Term.muted, fontSize: 12),
            ),
            Text(
              code,
              style: const TextStyle(
                color: Term.green,
                fontSize: 18,
                fontWeight: FontWeight.bold,
                letterSpacing: 4,
              ),
            ),
            const SizedBox(width: 8),
            const Icon(Icons.copy_rounded, size: 14, color: Term.muted),
          ],
        ),
      ),
    );
  }
}

class EmptyState extends StatelessWidget {
  const EmptyState({super.key, required this.command, required this.hint});
  final String command;
  final String hint;

  @override
  Widget build(BuildContext context) => Center(
    child: Padding(
      padding: const EdgeInsets.all(32),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            command,
            style: const TextStyle(color: Term.green, fontSize: 14),
          ),
          const SizedBox(height: 8),
          Text(
            hint,
            textAlign: TextAlign.center,
            style: const TextStyle(
              color: Term.muted,
              fontSize: 13,
              height: 1.4,
            ),
          ),
        ],
      ),
    ),
  );
}

Future<bool> confirmWipe(BuildContext context, Contact c) async {
  final ok = await showDialog<bool>(
    context: context,
    builder: (ctx) => AlertDialog(
      backgroundColor: Term.panel,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: const BorderSide(color: Term.line),
      ),
      title: Text(
        'rm -rf ${c.code}',
        style: const TextStyle(color: Term.red, fontSize: 16),
      ),
      content: Text(
        'This removes ${c.code} from both contact lists and permanently '
        'deletes your whole chat room, every message and file, for both '
        'of you.\n\nThis cannot be undone.',
        style: const TextStyle(color: Term.text, fontSize: 13.5, height: 1.4),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(ctx, false),
          child: const Text('Cancel'),
        ),
        ElevatedButton(
          style: ElevatedButton.styleFrom(
            backgroundColor: Term.red,
            foregroundColor: Term.bg,
          ),
          onPressed: () => Navigator.pop(ctx, true),
          child: const Text('Wipe chat'),
        ),
      ],
    ),
  );
  return ok ?? false;
}

//  4. APP SHELL + INCOMING-REQUEST POP-UP

class SecretChatApp extends StatelessWidget {
  const SecretChatApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Secret Chat',
      debugShowCheckedModeBanner: false,
      theme: buildTheme(),
      home: const AuthGate(),
      // The request pop-up sits ABOVE every screen, so it shows up no matter
      // where the user is, and stays until they accept or decline.
      builder: (context, child) =>
          RequestOverlayHost(child: child ?? const SizedBox.shrink()),
    );
  }
}

class AuthGate extends StatefulWidget {
  const AuthGate({super.key});

  @override
  State<AuthGate> createState() => _AuthGateState();
}

class _AuthGateState extends State<AuthGate> {
  late final Stream<User?> _auth = FirebaseAuth.instance.authStateChanges();

  @override
  Widget build(BuildContext context) {
    return StreamBuilder<User?>(
      stream: _auth,
      builder: (context, snap) {
        if (snap.connectionState == ConnectionState.waiting) {
          return const Scaffold(
            body: Center(child: CircularProgressIndicator(color: Term.green)),
          );
        }
        final user = snap.data;
        if (user == null) return const AuthScreen();
        return HomeScreen(key: ValueKey(user.uid));
      },
    );
  }
}

class RequestOverlayHost extends StatefulWidget {
  const RequestOverlayHost({super.key, required this.child});
  final Widget child;

  @override
  State<RequestOverlayHost> createState() => _RequestOverlayHostState();
}

class _RequestOverlayHostState extends State<RequestOverlayHost> {
  late final Stream<User?> _auth = FirebaseAuth.instance.authStateChanges();

  @override
  Widget build(BuildContext context) {
    return StreamBuilder<User?>(
      stream: _auth,
      builder: (context, snap) {
        final user = snap.data;
        return Stack(
          fit: StackFit.expand,
          children: [
            widget.child,
            if (user != null)
              _RequestLayer(key: ValueKey(user.uid), uid: user.uid),
          ],
        );
      },
    );
  }
}

class _RequestLayer extends StatefulWidget {
  const _RequestLayer({super.key, required this.uid});
  final String uid;

  @override
  State<_RequestLayer> createState() => _RequestLayerState();
}

class _RequestLayerState extends State<_RequestLayer> {
  late final Stream<List<ContactRequest>> _requests = repo.requestsStream(
    widget.uid,
  );

  @override
  Widget build(BuildContext context) {
    return StreamBuilder<List<ContactRequest>>(
      stream: _requests,
      builder: (context, snap) {
        final reqs = snap.data ?? const <ContactRequest>[];
        if (snap.hasError || reqs.isEmpty) return const SizedBox.shrink();
        return RequestPopup(
          key: ValueKey(reqs.first.fromUid),
          request: reqs.first,
          pendingCount: reqs.length - 1,
        );
      },
    );
  }
}

class RequestPopup extends StatefulWidget {
  const RequestPopup({
    super.key,
    required this.request,
    required this.pendingCount,
  });

  final ContactRequest request;
  final int pendingCount;

  @override
  State<RequestPopup> createState() => _RequestPopupState();
}

class _RequestPopupState extends State<RequestPopup> {
  bool _busy = false;
  String? _error;

  Future<void> _decide(bool accept) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      if (accept) {
        await repo.acceptRequest(widget.request);
      } else {
        await repo.declineRequest(widget.request);
      }
      // On success the request disappears and this pop-up is removed.
    } catch (e) {
      if (mounted) {
        setState(() {
          _busy = false;
          _error = e.toString();
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final r = widget.request;
    return Material(
      color: Term.scrim,
      child: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 400),
              child: TerminalPanel(
                title: 'incoming_request',
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    const Text(
                      'Someone wants to chat with you',
                      style: TextStyle(
                        color: Term.amber,
                        fontWeight: FontWeight.bold,
                        fontSize: 15,
                      ),
                    ),
                    const SizedBox(height: 16),
                    const Text(
                      'from',
                      style: TextStyle(color: Term.muted, fontSize: 12),
                    ),
                    const SizedBox(height: 2),
                    Text(
                      r.fromCode,
                      style: const TextStyle(
                        color: Term.green,
                        fontSize: 28,
                        fontWeight: FontWeight.bold,
                        letterSpacing: 4,
                      ),
                    ),
                    if (r.fromEmail.isNotEmpty)
                      Text(
                        r.fromEmail,
                        style: const TextStyle(color: Term.muted, fontSize: 12),
                      ),
                    const SizedBox(height: 14),
                    const Text(
                      'Accept to open a private chat room with them. '
                      'Decline and nothing happens; they are not told.',
                      style: TextStyle(
                        color: Term.text,
                        fontSize: 13,
                        height: 1.4,
                      ),
                    ),
                    if (widget.pendingCount > 0) ...[
                      const SizedBox(height: 8),
                      Text(
                        '${widget.pendingCount} more waiting after this one',
                        style: const TextStyle(color: Term.amber, fontSize: 12),
                      ),
                    ],
                    if (_error != null) ...[
                      const SizedBox(height: 10),
                      Text(
                        'error: $_error',
                        style: const TextStyle(color: Term.red, fontSize: 12.5),
                      ),
                    ],
                    const SizedBox(height: 20),
                    if (_busy)
                      const Center(
                        child: CircularProgressIndicator(color: Term.green),
                      )
                    else
                      Row(
                        children: [
                          Expanded(
                            child: OutlinedButton(
                              onPressed: () => _decide(false),
                              style: OutlinedButton.styleFrom(
                                foregroundColor: Term.red,
                                side: const BorderSide(color: Term.red),
                              ),
                              child: const Text('Decline'),
                            ),
                          ),
                          const SizedBox(width: 12),
                          Expanded(
                            child: ElevatedButton(
                              onPressed: () => _decide(true),
                              child: const Text('Accept'),
                            ),
                          ),
                        ],
                      ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

//  5. AUTH SCREEN

class AuthScreen extends StatefulWidget {
  const AuthScreen({super.key});

  @override
  State<AuthScreen> createState() => _AuthScreenState();
}

class _AuthScreenState extends State<AuthScreen> {
  final _email = TextEditingController();
  final _pass = TextEditingController();
  final _confirm = TextEditingController();
  bool _register = false;
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _email.dispose();
    _pass.dispose();
    _confirm.dispose();
    super.dispose();
  }

  String _authMessage(FirebaseAuthException e) {
    switch (e.code) {
      case 'invalid-email':
        return 'That email address is not valid.';
      case 'user-not-found':
      case 'wrong-password':
      case 'invalid-credential':
        return 'Wrong email or password.';
      case 'email-already-in-use':
        return 'An account with this email already exists. Log in instead.';
      case 'weak-password':
        return 'Password is too weak. Use at least 6 characters.';
      case 'too-many-requests':
        return 'Too many attempts. Wait a moment and try again.';
      case 'operation-not-allowed':
        return 'Email/password sign-in is disabled. Enable it in Firebase '
            'Console → Authentication → Sign-in method.';
      default:
        return e.message ?? e.code;
    }
  }

  Future<void> _submit() async {
    final email = _email.text.trim();
    final pass = _pass.text;
    if (email.isEmpty || pass.isEmpty) {
      setState(() => _error = 'Enter your email and password.');
      return;
    }
    if (_register && pass.length < 6) {
      setState(() => _error = 'Password needs at least 6 characters.');
      return;
    }
    if (_register && pass != _confirm.text) {
      setState(() => _error = "Passwords don't match.");
      return;
    }

    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      if (_register) {
        await repo.register(email, pass);
      } else {
        await repo.login(email, pass);
      }
      // AuthGate switches to HomeScreen automatically.
    } on FirebaseAuthException catch (e) {
      if (mounted) setState(() => _error = _authMessage(e));
    } catch (e) {
      if (mounted) setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Widget _field(
    TextEditingController c,
    String label, {
    String? hint,
    bool obscure = false,
    TextInputType? type,
  }) {
    return TextField(
      controller: c,
      obscureText: obscure,
      keyboardType: type,
      autocorrect: false,
      enableSuggestions: !obscure,
      style: const TextStyle(color: Term.text),
      decoration: InputDecoration(labelText: label, hintText: hint),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 420),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const TerminalTitle(size: 30),
                  const SizedBox(height: 8),
                  const Text(
                    'Private rooms for two. Nothing shared beyond the pair.',
                    style: TextStyle(color: Term.muted, fontSize: 12.5),
                  ),
                  const SizedBox(height: 28),
                  TerminalPanel(
                    title: _register ? 'register' : 'login',
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        Text(
                          _register
                              ? '\$ secretchat --register'
                              : '\$ secretchat --login',
                          style: const TextStyle(color: Term.green),
                        ),
                        const SizedBox(height: 16),
                        _field(
                          _email,
                          'email',
                          hint: 'you@example.com',
                          type: TextInputType.emailAddress,
                        ),
                        const SizedBox(height: 12),
                        _field(_pass, 'password', obscure: true),
                        if (_register) ...[
                          const SizedBox(height: 12),
                          _field(_confirm, 'confirm password', obscure: true),
                        ],
                        if (_error != null) ...[
                          const SizedBox(height: 14),
                          Text(
                            'error: $_error',
                            style: const TextStyle(
                              color: Term.red,
                              fontSize: 13,
                              height: 1.35,
                            ),
                          ),
                        ],
                        const SizedBox(height: 20),
                        ElevatedButton(
                          onPressed: _busy ? null : _submit,
                          child: _busy
                              ? const SizedBox(
                                  width: 18,
                                  height: 18,
                                  child: CircularProgressIndicator(
                                    strokeWidth: 2,
                                    color: Term.green,
                                  ),
                                )
                              : Text(_register ? 'Create account' : 'Log in'),
                        ),
                        const SizedBox(height: 6),
                        TextButton(
                          onPressed: _busy
                              ? null
                              : () => setState(() {
                                  _register = !_register;
                                  _error = null;
                                }),
                          child: Text(
                            _register
                                ? 'Already have an account? Log in'
                                : 'New here? Create an account',
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

//  6. HOME SCREEN — your code on top, contacts below

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  late Future<String> _profile;
  late final Stream<List<Contact>> _contacts = repo.contactsStream();

  @override
  void initState() {
    super.initState();
    _profile = repo.ensureProfile();
  }

  Future<void> _addContact() async {
    final code = await showDialog<String>(
      context: context,
      builder: (_) => const AddContactDialog(),
    );
    if (code != null && mounted) {
      toast(context, 'Request sent to $code. Waiting for them to accept.');
    }
  }

  Future<void> _remove(Contact c) async {
    if (!await confirmWipe(context, c)) return;
    try {
      await repo.removeContact(c.uid);
      if (mounted) toast(context, 'Chat with ${c.code} wiped.');
    } catch (e) {
      if (mounted) toast(context, 'Could not remove ${c.code}: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        toolbarHeight: 92,
        automaticallyImplyLeading: false,
        title: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const TerminalTitle(size: 15),
            const SizedBox(height: 8),
            FutureBuilder<String>(
              future: _profile,
              builder: (context, snap) {
                if (snap.hasError) {
                  return TextButton(
                    onPressed: () =>
                        setState(() => _profile = repo.ensureProfile()),
                    child: const Text(
                      'Code failed to load. Tap to retry.',
                      style: TextStyle(color: Term.red, fontSize: 12),
                    ),
                  );
                }
                if (!snap.hasData) {
                  return const Text(
                    'generating your code…',
                    style: TextStyle(color: Term.muted, fontSize: 12),
                  );
                }
                return CodeBadge(code: snap.data!);
              },
            ),
          ],
        ),
        actions: [
          IconButton(
            tooltip: 'Log out',
            icon: const Icon(Icons.logout_rounded, color: Term.muted),
            onPressed: repo.logout,
          ),
        ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(1),
          child: Container(height: 1, color: Term.line),
        ),
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _addContact,
        icon: const Icon(Icons.person_add_alt_1_rounded),
        label: const Text(
          'Add contact',
          style: TextStyle(fontWeight: FontWeight.bold),
        ),
      ),
      body: StreamBuilder<List<Contact>>(
        stream: _contacts,
        builder: (context, snap) {
          if (snap.hasError) {
            return EmptyState(
              command: 'error',
              hint: 'Could not load contacts: ${snap.error}',
            );
          }
          if (!snap.hasData) {
            return const Center(
              child: CircularProgressIndicator(color: Term.green),
            );
          }
          final contacts = snap.data!;
          if (contacts.isEmpty) {
            return const EmptyState(
              command: '\$ ls ~/contacts\n(empty)',
              hint:
                  'Share your code with a friend, or tap "Add contact" '
                  'and enter theirs.',
            );
          }
          return ListView.builder(
            padding: const EdgeInsets.fromLTRB(0, 12, 0, 96),
            itemCount: contacts.length + 1,
            itemBuilder: (context, i) {
              if (i == 0) {
                return Padding(
                  padding: const EdgeInsets.fromLTRB(20, 0, 20, 8),
                  child: Text(
                    '\$ ls ~/contacts  (${contacts.length})',
                    style: const TextStyle(color: Term.green, fontSize: 13),
                  ),
                );
              }
              final c = contacts[i - 1];
              return ContactTile(
                contact: c,
                onOpen: () => Navigator.of(context).push(
                  MaterialPageRoute(builder: (_) => ChatScreen(contact: c)),
                ),
                onRemove: () => _remove(c),
              );
            },
          );
        },
      ),
    );
  }
}

class ContactTile extends StatelessWidget {
  const ContactTile({
    super.key,
    required this.contact,
    required this.onOpen,
    required this.onRemove,
  });

  final Contact contact;
  final VoidCallback onOpen;
  final VoidCallback onRemove;

  @override
  Widget build(BuildContext context) {
    final c = contact;
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 5),
      child: Material(
        color: Term.panel,
        borderRadius: BorderRadius.circular(14),
        child: InkWell(
          borderRadius: BorderRadius.circular(14),
          onTap: onOpen,
          child: Container(
            padding: const EdgeInsets.fromLTRB(14, 12, 6, 12),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(14),
              border: Border.all(color: Term.line),
            ),
            child: Row(
              children: [
                Container(
                  width: 44,
                  height: 44,
                  alignment: Alignment.center,
                  decoration: BoxDecoration(
                    color: Term.panel2,
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: Term.greenDim),
                  ),
                  child: Text(
                    c.code.length >= 2 ? c.code.substring(0, 2) : c.code,
                    style: const TextStyle(
                      color: Term.green,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
                const SizedBox(width: 14),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        c.code,
                        style: const TextStyle(
                          color: Term.text,
                          fontWeight: FontWeight.bold,
                          letterSpacing: 2.5,
                          fontSize: 15,
                        ),
                      ),
                      const SizedBox(height: 3),
                      Text(
                        c.email,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(color: Term.muted, fontSize: 12),
                      ),
                    ],
                  ),
                ),
                IconButton(
                  tooltip: 'Remove and wipe chat',
                  icon: const Icon(
                    Icons.delete_outline_rounded,
                    color: Term.red,
                  ),
                  onPressed: onRemove,
                ),
                const Icon(Icons.chevron_right_rounded, color: Term.muted),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class AddContactDialog extends StatefulWidget {
  const AddContactDialog({super.key});

  @override
  State<AddContactDialog> createState() => _AddContactDialogState();
}

class _AddContactDialogState extends State<AddContactDialog> {
  final _ctrl = TextEditingController();
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  Future<void> _send() async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final code = await repo.sendRequest(_ctrl.text);
      if (mounted) Navigator.of(context).pop(code);
    } catch (e) {
      if (mounted) {
        setState(() {
          _busy = false;
          _error = e.toString();
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      backgroundColor: Term.panel,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: const BorderSide(color: Term.line),
      ),
      title: const Text(
        '\$ add --code',
        style: TextStyle(color: Term.green, fontSize: 16),
      ),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Enter the 8-character code shown at the top of their screen.',
            style: TextStyle(color: Term.muted, fontSize: 12.5, height: 1.4),
          ),
          const SizedBox(height: 14),
          TextField(
            controller: _ctrl,
            autofocus: true,
            maxLength: 8,
            textAlign: TextAlign.center,
            textCapitalization: TextCapitalization.characters,
            inputFormatters: [
              FilteringTextInputFormatter.allow(RegExp(r'[A-Za-z0-9]')),
              UpperCaseFormatter(),
            ],
            style: const TextStyle(
              color: Term.green,
              fontSize: 22,
              fontWeight: FontWeight.bold,
              letterSpacing: 6,
            ),
            decoration: const InputDecoration(
              hintText: 'XXXXXXXX',
              counterText: '',
            ),
            onSubmitted: (_) => _send(),
          ),
          if (_error != null) ...[
            const SizedBox(height: 10),
            Text(
              'error: $_error',
              style: const TextStyle(color: Term.red, fontSize: 12.5),
            ),
          ],
        ],
      ),
      actions: [
        TextButton(
          onPressed: _busy ? null : () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        ElevatedButton(
          onPressed: _busy ? null : _send,
          child: _busy
              ? const SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    color: Term.green,
                  ),
                )
              : const Text('Send request'),
        ),
      ],
    );
  }
}

//  7. CHAT SCREEN

class ChatScreen extends StatefulWidget {
  const ChatScreen({super.key, required this.contact});
  final Contact contact;

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  late final String roomId = ChatRepository.roomIdFor(
    repo.uid,
    widget.contact.uid,
  );
  late final Stream<List<ChatMessage>> _messages = repo.messagesStream(roomId);

  final _input = TextEditingController();

  StreamSubscription<bool>? _contactSub;
  bool _sending = false;
  bool _leaving = false;

  @override
  void initState() {
    super.initState();
    // If the OTHER person removes you, the room is wiped: leave the screen.
    _contactSub = repo.contactExists(widget.contact.uid).listen((exists) {
      if (exists || _leaving || !mounted) return;
      _leaving = true;
      final messenger = ScaffoldMessenger.of(context);
      Navigator.of(context).popUntil((route) => route.isFirst);
      messenger.showSnackBar(
        SnackBar(
          content: Text('The chat with ${widget.contact.code} was removed.'),
        ),
      );
    });
  }

  @override
  void dispose() {
    _contactSub?.cancel();
    _input.dispose();
    super.dispose();
  }

  Future<void> _sendText() async {
    final text = _input.text.trim();
    if (text.isEmpty) return;
    _input.clear();
    try {
      await repo.sendText(roomId, text);
    } catch (e) {
      if (!mounted) return;
      _input.text = text; // give the text back so nothing is lost
      toast(context, 'Message not sent: $e');
    }
  }

  Future<void> _pickAndSend() async {
    final file = await FilePicker.pickFile();
    if (file == null || !mounted) return;

    setState(() => _sending = true);
    try {
      final bytes = await file.readAsBytes();
      if (bytes.length > kMaxFileBytes) {
        if (mounted) {
          toast(
            context,
            'File is ${formatSize(bytes.length)}. The limit is ${formatSize(kMaxFileBytes)}.',
          );
        }
        return;
      }
      await repo.sendFile(roomId, file.name, bytes);
    } catch (e) {
      if (mounted) toast(context, 'File not sent: $e');
    } finally {
      if (mounted) setState(() => _sending = false);
    }
  }

  Future<void> _download(ChatMessage m) async {
    final fileId = m.fileId;
    if (fileId == null) return;
    final name = m.text;
    toast(context, 'Downloading $name…');
    try {
      final bytes = await repo.downloadFile(roomId, fileId);
      final path = await FilePicker.saveFile(fileName: name, bytes: bytes);
      if (path != null && mounted) toast(context, 'Saved $name.');
    } catch (e) {
      if (mounted) toast(context, 'Download failed: $e');
    }
  }

  Future<void> _wipe() async {
    if (!await confirmWipe(context, widget.contact)) return;
    if (!mounted) return;
    _leaving = true;
    final messenger = ScaffoldMessenger.of(context);
    final nav = Navigator.of(context);
    try {
      await repo.removeContact(widget.contact.uid);
      nav.popUntil((route) => route.isFirst);
      messenger.showSnackBar(
        SnackBar(content: Text('Chat with ${widget.contact.code} wiped.')),
      );
    } catch (e) {
      _leaving = false;
      messenger.showSnackBar(SnackBar(content: Text('Wipe failed: $e')));
    }
  }

  //  UI

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        toolbarHeight: 64,
        title: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              widget.contact.code,
              style: const TextStyle(
                color: Term.green,
                fontWeight: FontWeight.bold,
                letterSpacing: 3,
                fontSize: 17,
              ),
            ),
            const SizedBox(height: 2),
            Text(
              widget.contact.email,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(color: Term.muted, fontSize: 11),
            ),
          ],
        ),
        actions: [
          IconButton(
            tooltip: 'Remove contact and wipe chat',
            icon: const Icon(Icons.delete_forever_outlined, color: Term.red),
            onPressed: _wipe,
          ),
        ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(1),
          child: Container(height: 1, color: Term.line),
        ),
      ),
      body: Column(
        children: [
          Expanded(
            child: StreamBuilder<List<ChatMessage>>(
              stream: _messages,
              builder: (context, snap) {
                if (snap.hasError) {
                  return EmptyState(
                    command: 'error',
                    hint: 'Could not load: ${snap.error}',
                  );
                }
                if (!snap.hasData) {
                  return const Center(
                    child: CircularProgressIndicator(color: Term.green),
                  );
                }
                final msgs = snap.data!;
                if (msgs.isEmpty) {
                  return EmptyState(
                    command: '\$ connect ${widget.contact.code}\nconnected.',
                    hint:
                        'This room is only visible to the two of you. '
                        'Say hello.',
                  );
                }
                return ListView.builder(
                  reverse: true, // newest at the bottom, auto-sticks to it
                  padding: const EdgeInsets.fromLTRB(12, 12, 12, 12),
                  itemCount: msgs.length,
                  itemBuilder: (context, i) =>
                      _bubble(msgs[msgs.length - 1 - i]),
                );
              },
            ),
          ),
          _composer(),
        ],
      ),
    );
  }

  Widget _bubble(ChatMessage m) {
    final mine = m.senderId == repo.uid;
    final time = Text(
      formatTime(m.timestamp),
      style: const TextStyle(color: Term.muted, fontSize: 10.5),
    );

    final bubble = Container(
      padding: const EdgeInsets.fromLTRB(12, 8, 12, 10),
      decoration: BoxDecoration(
        color: mine ? Term.mine : Term.panel,
        border: Border.all(color: mine ? Term.greenDim : Term.line),
        borderRadius: BorderRadius.only(
          topLeft: const Radius.circular(14),
          topRight: const Radius.circular(14),
          bottomLeft: Radius.circular(mine ? 14 : 3),
          bottomRight: Radius.circular(mine ? 3 : 14),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            mine ? 'you' : widget.contact.code,
            style: TextStyle(
              color: mine ? Term.green : Term.amber,
              fontSize: 10.5,
            ),
          ),
          const SizedBox(height: 4),
          m.isFile ? _fileBody(m) : _textBody(m),
        ],
      ),
    );

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        mainAxisAlignment: mine
            ? MainAxisAlignment.end
            : MainAxisAlignment.start,
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          if (mine) ...[time, const SizedBox(width: 8)],
          Flexible(
            child: ConstrainedBox(
              constraints: BoxConstraints(
                maxWidth: MediaQuery.sizeOf(context).width * 0.72,
              ),
              child: bubble,
            ),
          ),
          if (!mine) ...[const SizedBox(width: 8), time],
        ],
      ),
    );
  }

  Widget _textBody(ChatMessage m) => Text(
    m.text,
    style: const TextStyle(color: Term.text, fontSize: 14.5, height: 1.35),
  );

  Widget _fileBody(ChatMessage m) => InkWell(
    borderRadius: BorderRadius.circular(8),
    onTap: () => _download(m),
    child: Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        const Icon(
          Icons.insert_drive_file_outlined,
          color: Term.green,
          size: 28,
        ),
        const SizedBox(width: 10),
        Flexible(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                m.text,
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(
                  color: Term.text,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 2),
              Text(
                '${formatSize(m.fileSize)} · tap to save',
                style: const TextStyle(color: Term.muted, fontSize: 11),
              ),
            ],
          ),
        ),
        const SizedBox(width: 8),
        const Icon(Icons.download_rounded, color: Term.muted, size: 20),
      ],
    ),
  );

  Widget _composer() {
    return Container(
      decoration: const BoxDecoration(
        color: Term.panel,
        border: Border(top: BorderSide(color: Term.line)),
      ),
      padding: const EdgeInsets.fromLTRB(6, 8, 10, 8),
      child: SafeArea(
        top: false,
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.end,
          children: [
            if (_sending)
              const Padding(
                padding: EdgeInsets.all(12),
                child: SizedBox(
                  width: 22,
                  height: 22,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    color: Term.green,
                  ),
                ),
              )
            else
              IconButton(
                tooltip: 'Attach a file',
                icon: const Icon(Icons.attach_file_rounded, color: Term.green),
                onPressed: _pickAndSend,
              ),
            Expanded(
              child: TextField(
                controller: _input,
                minLines: 1,
                maxLines: 5,
                keyboardType: TextInputType.text,
                textInputAction: TextInputAction.send,
                onSubmitted: (_) => _sendText(),
                style: const TextStyle(color: Term.text),
                decoration: const InputDecoration(
                  isDense: true,
                  hintText: 'type a message',
                  prefixIcon: Padding(
                    padding: EdgeInsets.only(left: 12, right: 6),
                    child: Text(
                      '>',
                      style: TextStyle(
                        color: Term.green,
                        fontWeight: FontWeight.bold,
                        fontSize: 16,
                      ),
                    ),
                  ),
                  prefixIconConstraints: BoxConstraints(
                    minWidth: 0,
                    minHeight: 0,
                  ),
                ),
              ),
            ),
            const SizedBox(width: 6),
            IconButton.filled(
              tooltip: 'Send',
              onPressed: _sendText,
              style: IconButton.styleFrom(
                backgroundColor: Term.green,
                foregroundColor: Term.bg,
              ),
              icon: const Icon(Icons.send_rounded),
            ),
          ],
        ),
      ),
    );
  }
}

//  8. HELPERS

/// Realtime Database returns Map<Object?, Object?>; normalize to String keys.
Map<String, dynamic> asMap(Object? v) => v is Map
    ? v.map<String, dynamic>((k, val) => MapEntry(k.toString(), val))
    : <String, dynamic>{};

int asInt(Object? v) => v is num ? v.toInt() : 0;

String formatTime(int ms) {
  if (ms <= 0) return '--:--';
  final d = DateTime.fromMillisecondsSinceEpoch(ms);
  final now = DateTime.now();
  String two(int n) => n.toString().padLeft(2, '0');
  final hm = '${two(d.hour)}:${two(d.minute)}';
  final sameDay =
      d.year == now.year && d.month == now.month && d.day == now.day;
  return sameDay ? hm : '${two(d.day)}/${two(d.month)} $hm';
}

String formatSize(int bytes) {
  if (bytes < 1024) return '$bytes B';
  if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
  return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
}

void toast(BuildContext context, String message) {
  ScaffoldMessenger.of(context)
    ..hideCurrentSnackBar()
    ..showSnackBar(SnackBar(content: Text(message)));
}

class UpperCaseFormatter extends TextInputFormatter {
  @override
  TextEditingValue formatEditUpdate(
    TextEditingValue oldValue,
    TextEditingValue newValue,
  ) => newValue.copyWith(text: newValue.text.toUpperCase());
}
