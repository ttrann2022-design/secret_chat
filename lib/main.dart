// Secret Chat: a private chat app for pairs of people, built on Flutter and
// Firebase. This file holds the app's screens; the rest lives in:
//   chat_repository.dart     models + every read/write to Firebase ([repo])
//   crypto/key_manager.dart  RSA: key pairs, wrapping the room's AES key
//   crypto/cipher.dart       AES: room keys, encrypting messages and files
//
// Sections:
//   0. ENTRY POINT
//   1. THEME        the green-on-black "terminal" look + reusable widgets
//   2. APP SHELL    MaterialApp, the login gate, the incoming-request pop-up
//   3. AUTH SCREEN  login / register form
//   4. HOME SCREEN  your code + contact list
//   5. CHAT SCREEN  messages, sending/saving files, wiping a chat
//   6. HELPERS      small formatting functions

import 'dart:async';

import 'package:file_picker/file_picker.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'chat_repository.dart';
import 'firebase_options.dart';

//before start please make sure you seperate security stuff in to 2 different file
// put it in crypto folder.
//  0. ENTRY POINT

/// App entry point: connect to Firebase, then show the app.
Future<void> main() async {
  // Plugins (like Firebase) need the Flutter engine ready before runApp.
  WidgetsFlutterBinding.ensureInitialized();
  await Firebase.initializeApp(options: DefaultFirebaseOptions.currentPlatform);
  runApp(const SecretChatApp());
}

//  1. THEME + SHARED WIDGETS

/// Colors and style constants for the retro green-on-black terminal look.
class Term {
  static const bg = Color(0xFF020403);
  static const panel = Color(0xFF07100B);
  static const panel2 = Color(0xFF0B1711);
  static const line = Color(0xFF15301F);
  static const green = Color(0xFF39FF88);
  static const greenDim = Color(0xFF1B6A42);
  static const mine = Color(0xFF081C11);
  static const text = Color(0xFFC6F2D8);
  static const muted = Color(0xFF557A65);
  static const red = Color(0xFFFF4D5E);
  static const amber = Color(0xFFFFC857);
  static const glow = Color(0x3339FF88);
  static const scrim = Color(0xE6010201);

  /// Corners stay nearly square, like a terminal window.
  static const radius = 3.0;

  /// Phosphor glow for important green text.
  static const textGlow = [Shadow(color: Color(0x9939FF88), blurRadius: 10)];

  static const font = 'monospace';
  static const fontFallback = ['Menlo', 'Courier New', 'Courier', 'RobotoMono'];
}

/// The app-wide Material theme: dark, monospace, square corners, green
/// accents. Buttons, fields and snack bars pick it up automatically, so most
/// widgets below don't set their own colors.
ThemeData buildTheme() {
  // Same outline for every text field state; only the color changes.
  OutlineInputBorder border(Color c) => OutlineInputBorder(
    borderRadius: BorderRadius.circular(Term.radius),
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
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(Term.radius),
        ),
        textStyle: buttonText,
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        padding: const EdgeInsets.symmetric(vertical: 14, horizontal: 18),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(Term.radius),
        ),
        textStyle: buttonText,
      ),
    ),
    textButtonTheme: TextButtonThemeData(
      style: TextButton.styleFrom(foregroundColor: Term.green),
    ),
    floatingActionButtonTheme: FloatingActionButtonThemeData(
      backgroundColor: Term.green,
      foregroundColor: Term.bg,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(Term.radius),
      ),
    ),
    snackBarTheme: SnackBarThemeData(
      backgroundColor: Term.panel2,
      contentTextStyle: const TextStyle(
        color: Term.text,
        fontFamily: Term.font,
        fontFamilyFallback: Term.fontFallback,
      ),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(Term.radius),
        side: const BorderSide(color: Term.greenDim),
      ),
      behavior: SnackBarBehavior.floating,
    ),
    textSelectionTheme: const TextSelectionThemeData(cursorColor: Term.green),
  );
}

/// A solid green block that blinks on and off, like a terminal cursor.
/// It never stops, which is why tests use pump() instead of pumpAndSettle().
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

/// The "> Secret Chat" logo followed by a blinking cursor.
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
          shadows: Term.textGlow,
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

/// Spinning `| / - \` in place of a Material progress circle.
class TermSpinner extends StatefulWidget {
  const TermSpinner({super.key, this.size = 18});
  final double size;

  @override
  State<TermSpinner> createState() => _TermSpinnerState();
}

class _TermSpinnerState extends State<TermSpinner> {
  static const _frames = ['|', '/', '-', '\\'];
  int _i = 0;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _timer = Timer.periodic(
      const Duration(milliseconds: 110),
      (_) => setState(() => _i = (_i + 1) % _frames.length),
    );
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => Text(
    '[${_frames[_i]}]',
    style: TextStyle(
      color: Term.green,
      fontSize: widget.size,
      fontWeight: FontWeight.bold,
      shadows: Term.textGlow,
    ),
  );
}

/// Types [text] out one character at a time, then leaves it on screen.
class TypewriterText extends StatefulWidget {
  const TypewriterText(this.text, {super.key, this.style});
  final String text;
  final TextStyle? style;

  @override
  State<TypewriterText> createState() => _TypewriterTextState();
}

class _TypewriterTextState extends State<TypewriterText> {
  int _shown = 0;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _timer = Timer.periodic(const Duration(milliseconds: 35), (t) {
      if (_shown >= widget.text.length) return t.cancel();
      setState(() => _shown++);
    });
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => Text(
    // The full-width text keeps the layout from jumping while typing.
    widget.text.substring(0, _shown).padRight(widget.text.length),
    style: widget.style,
  );
}

/// Faint CRT scanlines and dark corners drawn over the whole app.
class CrtOverlay extends StatelessWidget {
  const CrtOverlay({super.key, required this.child});
  final Widget child;

  @override
  Widget build(BuildContext context) => Stack(
    fit: StackFit.expand,
    children: [
      child,
      const IgnorePointer(
        child: RepaintBoundary(child: CustomPaint(painter: _CrtPainter())),
      ),
    ],
  );
}

class _CrtPainter extends CustomPainter {
  const _CrtPainter();

  @override
  void paint(Canvas canvas, Size size) {
    final rect = Offset.zero & size;
    // A 1px dark line every 3px...
    final lines = Paint()..color = const Color(0x2E000000);
    for (double y = 0; y < size.height; y += 3) {
      canvas.drawRect(Rect.fromLTWH(0, y, size.width, 1), lines);
    }
    // ...then a gradient that is clear in the middle and darkens the edges.
    canvas.drawRect(
      rect,
      Paint()
        ..shader = const RadialGradient(
          radius: 1.1,
          colors: [Color(0x00000000), Color(0x99000000)],
          stops: [0.55, 1.0],
        ).createShader(rect),
    );
  }

  // Nothing in it changes, so there is never a reason to redraw it.
  @override
  bool shouldRepaint(_CrtPainter oldDelegate) => false;
}

/// A square-cornered terminal window with a `>_ title` header bar.
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

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        color: Term.panel,
        borderRadius: BorderRadius.circular(Term.radius),
        border: Border.all(color: Term.line),
        boxShadow: const [
          BoxShadow(color: Term.glow, blurRadius: 28, spreadRadius: -8),
        ],
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(Term.radius),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Container(
              color: Term.panel2,
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
              child: Row(
                children: [
                  const Text(
                    '>_',
                    style: TextStyle(
                      color: Term.green,
                      fontSize: 12,
                      fontWeight: FontWeight.bold,
                      shadows: Term.textGlow,
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      title,
                      overflow: TextOverflow.ellipsis,
                      style: const TextStyle(
                        color: Term.muted,
                        fontSize: 12,
                        letterSpacing: 1.5,
                      ),
                    ),
                  ),
                  const Text(
                    '─ □ ×',
                    style: TextStyle(color: Term.muted, fontSize: 12),
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

/// Your own 8-char code at the top of the home screen. Tap to copy it.
class CodeBadge extends StatelessWidget {
  const CodeBadge({super.key, required this.code});
  final String code;

  @override
  Widget build(BuildContext context) {
    return InkWell(
      borderRadius: BorderRadius.circular(Term.radius),
      onTap: () {
        Clipboard.setData(ClipboardData(text: code));
        toast(context, 'Your code $code was copied.');
      },
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
        decoration: BoxDecoration(
          color: Term.panel,
          borderRadius: BorderRadius.circular(Term.radius),
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
                shadows: Term.textGlow,
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

/// Centered placeholder for empty lists and errors: a fake command in green
/// with a short hint below it.
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

/// Asks before removing a contact and wiping the chat. Returns true only if
/// the user taps "Wipe chat"; closing the dialog any other way returns false.
Future<bool> confirmWipe(BuildContext context, Contact c) async {
  final ok = await showDialog<bool>(
    context: context,
    builder: (ctx) => AlertDialog(
      backgroundColor: Term.panel,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(Term.radius),
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

//  2. APP SHELL + INCOMING-REQUEST POP-UP

/// The root widget.
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
      // where the user is, and stays until they accept or decline. The CRT
      // overlay goes on top of everything, pop-up included.
      builder: (context, child) => CrtOverlay(
        child: RequestOverlayHost(child: child ?? const SizedBox.shrink()),
      ),
    );
  }
}

/// Shows the login screen when signed out and the home screen when signed
/// in, switching by itself whenever the sign-in state changes.
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
          return const Scaffold(body: Center(child: TermSpinner()));
        }
        final user = snap.data;
        if (user == null) return const AuthScreen();
        // Keyed by uid so a different user gets a fresh HomeScreen with
        // their own streams and code, not the previous user's.
        return HomeScreen(key: ValueKey(user.uid));
      },
    );
  }
}

/// Wraps every screen. While someone is signed in, it stacks the
/// request pop-up layer on top of the current screen.
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

/// Watches your incoming requests and shows the oldest one as a pop-up.
/// Shows nothing when there are none.
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
          // A new key per request resets the pop-up's busy/error state.
          key: ValueKey(reqs.first.fromUid),
          request: reqs.first,
          pendingCount: reqs.length - 1,
        );
      },
    );
  }
}

/// Full-screen pop-up for one contact request, with Accept and Decline.
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

  /// Accepts or declines. Both delete the request from the database, which
  /// makes the stream in _RequestLayer drop this pop-up.
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
                        shadows: Term.textGlow,
                      ),
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
                      const Center(child: TermSpinner())
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

//  3. AUTH SCREEN

/// Email + password form. The same screen switches between log in and
/// register.
class AuthScreen extends StatefulWidget {
  const AuthScreen({super.key});

  @override
  State<AuthScreen> createState() => _AuthScreenState();
}

class _AuthScreenState extends State<AuthScreen> {
  final _email = TextEditingController();
  final _pass = TextEditingController();
  final _confirm = TextEditingController();
  bool _register = false; // true = register mode (adds the confirm field)
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _email.dispose();
    _pass.dispose();
    _confirm.dispose();
    super.dispose();
  }

  /// Turns Firebase error codes into plain-English messages.
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

  /// Checks the input on the device first, then calls Firebase.
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

  /// One labeled text field. Suggestions are off for passwords.
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
                  const TypewriterText(
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
                              ? const TermSpinner(size: 14)
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

//  4. HOME SCREEN — your code on top, contacts below

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  // Your code. Not final: the retry button assigns a new attempt.
  late Future<String> _profile;
  late final Stream<List<Contact>> _contacts = repo.contactsStream();

  @override
  void initState() {
    super.initState();
    _profile = repo.ensureProfile();
    // Separate from the code: if the keys fail, the code still shows.
    repo.ensureKeys().then<void>(
      (_) {},
      onError: (Object e) {
        if (mounted) toast(context, 'Encryption keys failed to load: $e');
      },
    );
  }

  /// Opens the add-contact dialog. It returns the code only if a request
  /// was actually sent.
  Future<void> _addContact() async {
    final code = await showDialog<String>(
      context: context,
      builder: (_) => const AddContactDialog(),
    );
    if (code != null && mounted) {
      toast(context, 'Request sent to $code. Waiting for them to accept.');
    }
  }

  /// Confirms, then removes the contact and wipes the chat for both users.
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
                    child: Text(
                      'Code failed to load. Tap to retry.\n${snap.error}',
                      textAlign: TextAlign.center,
                      maxLines: 3,
                      overflow: TextOverflow.ellipsis,
                      style: const TextStyle(color: Term.red, fontSize: 12),
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
            return const Center(child: TermSpinner());
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
            // Row 0 is the "$ ls ~/contacts" header, so contacts start at 1.
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

/// One row of the contact list: the first two letters of the code, the
/// full code, and a delete button. Tapping the row opens the chat.
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
        borderRadius: BorderRadius.circular(Term.radius),
        child: InkWell(
          borderRadius: BorderRadius.circular(Term.radius),
          onTap: onOpen,
          child: Container(
            padding: const EdgeInsets.fromLTRB(14, 12, 6, 12),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(Term.radius),
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
                    borderRadius: BorderRadius.circular(Term.radius),
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
                  child: Text(
                    c.code,
                    style: const TextStyle(
                      color: Term.text,
                      fontWeight: FontWeight.bold,
                      letterSpacing: 2.5,
                      fontSize: 15,
                    ),
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

/// Dialog for typing a friend's code and sending them a request. Closes
/// and returns the code on success; stays open and shows the error if not.
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
    if (_busy) return; // ignore double taps while a request is in flight
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
        borderRadius: BorderRadius.circular(Term.radius),
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
            // Letters and digits only, uppercased as you type.
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
              ? const TermSpinner(size: 14)
              : const Text('Send request'),
        ),
      ],
    );
  }
}

//  5. CHAT SCREEN

/// The conversation with one contact: message list, text box, file
/// send/save, and a button to wipe the chat.
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
  final _inputFocus = FocusNode();

  StreamSubscription<bool>? _contactSub;
  bool _sending = false; // a file is uploading: show a spinner, not the clip
  bool _leaving = false; // already closing this screen: don't pop twice

  @override
  void initState() {
    super.initState();
    // If the OTHER person removes you, the room is wiped: leave the screen.
    _contactSub = repo.contactExists(widget.contact.uid).listen((exists) {
      if (exists || _leaving || !mounted) return;
      _leaving = true;
      // Get the messenger before popping; this screen's context goes away.
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
    _inputFocus.dispose();
    super.dispose();
  }

  /// Sends the typed text. The box clears right away so typing feels
  /// instant; the text comes back if sending fails.
  Future<void> _sendText() async {
    final text = _input.text.trim();
    if (text.isEmpty) return;
    _input.clear();
    _inputFocus.requestFocus(); // keep the keyboard up for the next message
    try {
      await repo.sendText(roomId, text);
    } catch (e) {
      if (!mounted) return;
      _input.text = text; // give the text back so nothing is lost
      toast(context, 'Message not sent: $e');
    }
  }

  /// Lets the user pick a file, checks the size limit, then uploads it.
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

  /// Downloads a file message, then opens the system "save as" dialog.
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

  /// Removes the contact and wipes the chat, then goes back home.
  Future<void> _wipe() async {
    if (!await confirmWipe(context, widget.contact)) return;
    if (!mounted) return;
    // Set before deleting, so the contactExists listener in initState
    // doesn't also try to close the screen.
    _leaving = true;
    // Get these before the await; this context is gone after popping.
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
        title: Text(
          widget.contact.code,
          style: const TextStyle(
            color: Term.green,
            fontWeight: FontWeight.bold,
            letterSpacing: 3,
            fontSize: 17,
            shadows: Term.textGlow,
          ),
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
                  return const Center(child: TermSpinner());
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
                  // In a reversed list, index 0 is at the bottom, so it
                  // gets the newest (last) message.
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

  /// One message row. Yours: right side, green. Theirs: left side, amber.
  /// The time sits next to the bubble on the outer side.
  Widget _bubble(ChatMessage m) {
    final mine = m.senderId == repo.uid;
    final time = Text(
      formatTime(m.timestamp),
      style: const TextStyle(color: Term.muted, fontSize: 10.5),
    );

    final accent = mine ? Term.green : Term.amber;
    const edge = BorderSide(color: Term.line);
    final accentEdge = BorderSide(color: accent, width: 2);

    // Square box with a colored edge on the sender's side.
    final bubble = Container(
      padding: const EdgeInsets.fromLTRB(12, 8, 12, 10),
      decoration: BoxDecoration(
        color: mine ? Term.mine : Term.panel,
        border: Border(
          top: edge,
          bottom: edge,
          left: mine ? edge : accentEdge,
          right: mine ? accentEdge : edge,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            mine ? '[you]' : '[${widget.contact.code}]',
            style: TextStyle(color: accent, fontSize: 10.5, letterSpacing: 1),
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

  /// File name, size and download icon. Tap to save the file.
  Widget _fileBody(ChatMessage m) => InkWell(
    borderRadius: BorderRadius.circular(Term.radius),
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

  /// The bar at the bottom: attach button, text box, send button.
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
                child: TermSpinner(size: 14),
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
                focusNode: _inputFocus,
                minLines: 1,
                maxLines: 5,
                keyboardType: TextInputType.text,
                textInputAction: TextInputAction.send,
                // Handling the keyboard's send key here (instead of
                // onSubmitted) stops the field from losing focus.
                onEditingComplete: _sendText,
                // Terminal-style block cursor.
                cursorWidth: 9,
                cursorRadius: Radius.zero,
                cursorOpacityAnimates: false,
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

//  6. HELPERS

/// "HH:mm" for today, "dd/MM HH:mm" for other days, "--:--" if missing.
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

/// Readable file size: "512 B", "3.4 KB", "1.2 MB".
String formatSize(int bytes) {
  if (bytes < 1024) return '$bytes B';
  if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
  return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
}

/// Shows a short message at the bottom, replacing any that is showing.
void toast(BuildContext context, String message) {
  ScaffoldMessenger.of(context)
    ..hideCurrentSnackBar()
    ..showSnackBar(SnackBar(content: Text(message)));
}

/// Uppercases whatever is typed into a text field.
class UpperCaseFormatter extends TextInputFormatter {
  @override
  TextEditingValue formatEditUpdate(
    TextEditingValue oldValue,
    TextEditingValue newValue,
  ) => newValue.copyWith(text: newValue.text.toUpperCase());
}
