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
//   4. KEY SETUP    save / restore / replace the private key on this device
//   5. HOME SCREEN  your code + contact list
//   6. CHAT SCREEN  messages, sending/saving files, the AES key, wiping
//   7. HELPERS      small formatting functions

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
// ═════════════════════════════════════════════════════════════════════════
// 0. ENTRY POINT
// Where the app starts: connect to Firebase, then show SecretChatApp.
// ═════════════════════════════════════════════════════════════════════════

/// App entry point: connect to Firebase, then show the app.
Future<void> main() async {
  // Plugins (like Firebase) need the Flutter engine ready before runApp.
  WidgetsFlutterBinding.ensureInitialized();
  await Firebase.initializeApp(options: DefaultFirebaseOptions.currentPlatform);
  runApp(const SecretChatApp());
}

// ═════════════════════════════════════════════════════════════════════════
// 1. THEME + SHARED WIDGETS
// The green-on-black "terminal" look (colors, font, button styles) and
// small widgets reused by many screens: the blinking-cursor logo, the
// spinner, typewriter text, CRT scanlines, the terminal-window panel, your
// code badge, the empty-list message and the "wipe chat" confirm dialog.
// ═════════════════════════════════════════════════════════════════════════

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

// Holds the blink timer and whether the cursor is visible right now.
class _BlinkingCursorState extends State<BlinkingCursor> {
  bool _on = true;
  Timer? _timer;

  /// Starts a timer that turns the cursor on/off every 530 ms.
  @override
  void initState() {
    super.initState();
    _timer = Timer.periodic(
      const Duration(milliseconds: 530),
      (_) => setState(() => _on = !_on),
    );
  }

  /// Stops the timer when the cursor leaves the screen.
  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  /// A green block, either fully visible or hidden.
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

  /// "> Secret Chat" followed by the blinking cursor.
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

// Holds the spin timer and which frame (| / - \) is showing.
class _TermSpinnerState extends State<TermSpinner> {
  static const _frames = ['|', '/', '-', '\\'];
  int _i = 0;
  Timer? _timer;

  /// Starts a timer that moves to the next frame every 110 ms.
  @override
  void initState() {
    super.initState();
    _timer = Timer.periodic(
      const Duration(milliseconds: 110),
      (_) => setState(() => _i = (_i + 1) % _frames.length),
    );
  }

  /// Stops the timer when the spinner leaves the screen.
  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  /// The current frame in brackets, e.g. "[/]".
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

// Holds the typing timer and how many characters are shown so far.
class _TypewriterTextState extends State<TypewriterText> {
  int _shown = 0;
  Timer? _timer;

  /// Starts a timer that shows one more character every 35 ms and stops
  /// itself at the end.
  @override
  void initState() {
    super.initState();
    _timer = Timer.periodic(const Duration(milliseconds: 35), (t) {
      if (_shown >= widget.text.length) return t.cancel();
      setState(() => _shown++);
    });
  }

  /// Stops the timer if the screen closes before typing has finished.
  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  /// The part typed so far.
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

  /// Draws the scanlines on top of [child]. IgnorePointer lets taps pass
  /// through to the app underneath.
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

/// Paints the CRT effect: thin dark lines across the screen and darker
/// corners.
class _CrtPainter extends CustomPainter {
  const _CrtPainter();

  /// Draws the whole effect for the given screen size.
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

  /// A bordered box: a header bar (">_ title" and fake window buttons),
  /// a thin line, then [child].
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

  /// "id ABCD2345" with a copy icon. Tapping copies the code.
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

  /// The command in green with the hint in grey below it, centered.
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

// ═════════════════════════════════════════════════════════════════════════
// 2. APP SHELL + INCOMING-REQUEST POP-UP
// The frame around every screen. SecretChatApp sets up the theme; AuthGate
// shows the login screen, or (after login) key setup and the home screen.
// Above every screen, a pop-up appears whenever someone sends you a
// contact request, and stays until you accept or decline it.
// ═════════════════════════════════════════════════════════════════════════

/// The root widget.
class SecretChatApp extends StatelessWidget {
  const SecretChatApp({super.key});

  /// Sets up the app: title, theme, the first screen (AuthGate), and the
  /// layers drawn above every screen (request pop-up, then CRT effect).
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

// Listens to Firebase sign-in changes for as long as the app runs.
class _AuthGateState extends State<AuthGate> {
  late final Stream<User?> _auth = FirebaseAuth.instance.authStateChanges();

  /// A spinner while Firebase starts, the login screen when signed out, or
  /// key setup + home screen when signed in.
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
        // Keyed by uid so a different user gets a fresh KeyGate and
        // HomeScreen with their own keys, streams and code.
        return KeyGate(
          key: ValueKey(user.uid),
          child: HomeScreen(key: ValueKey(user.uid)),
        );
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

// Listens to sign-in changes to know whose requests to watch.
class _RequestOverlayHostState extends State<RequestOverlayHost> {
  late final Stream<User?> _auth = FirebaseAuth.instance.authStateChanges();

  /// The current screen, plus the request layer on top while someone is
  /// signed in.
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
/// Shows nothing when there are none, or while this device is still
/// waiting for your private key (KeyGate comes first).
class _RequestLayer extends StatefulWidget {
  const _RequestLayer({super.key, required this.uid});
  final String uid;

  @override
  State<_RequestLayer> createState() => _RequestLayerState();
}

// The live list of requests sent to this user.
class _RequestLayerState extends State<_RequestLayer> {
  late final Stream<List<ContactRequest>> _requests = repo.requestsStream(
    widget.uid,
  );

  /// Nothing until this device's keys are ready; then the oldest request
  /// as a pop-up (it also says how many more are waiting).
  @override
  Widget build(BuildContext context) {
    return ValueListenableBuilder<bool>(
      valueListenable: repo.keysReady,
      builder: (context, ready, _) => !ready
          ? const SizedBox.shrink()
          : StreamBuilder<List<ContactRequest>>(
              stream: _requests,
              builder: (context, snap) {
                final reqs = snap.data ?? const <ContactRequest>[];
                if (snap.hasError || reqs.isEmpty) {
                  return const SizedBox.shrink();
                }
                return RequestPopup(
                  // A new key per request resets the pop-up's busy/error state.
                  key: ValueKey(reqs.first.fromUid),
                  request: reqs.first,
                  pendingCount: reqs.length - 1,
                );
              },
            ),
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

// Whether Accept/Decline is running, and the error to show if it failed.
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

  /// A dark full-screen background with a terminal panel: who sent the
  /// request, what accepting means, and Decline / Accept (or a spinner).
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

// ═════════════════════════════════════════════════════════════════════════
// 3. AUTH SCREEN (log in / register)
// One form for both. The input is checked first (empty fields, short
// password, passwords that don't match), then sent to Firebase. Firebase
// error codes are turned into plain-English messages.
// ═════════════════════════════════════════════════════════════════════════

/// Email + password form. The same screen switches between log in and
/// register.
class AuthScreen extends StatefulWidget {
  const AuthScreen({super.key});

  @override
  State<AuthScreen> createState() => _AuthScreenState();
}

// The three text fields, login-or-register mode, the busy flag and the
// error shown under the form.
class _AuthScreenState extends State<AuthScreen> {
  final _email = TextEditingController();
  final _pass = TextEditingController();
  final _confirm = TextEditingController();
  bool _register = false; // true = register mode (adds the confirm field)
  bool _busy = false;
  String? _error;

  /// Frees the text fields' controllers when the screen closes.
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

  /// The logo, a tagline that types itself, and a terminal panel with the
  /// form. Register mode adds the confirm-password field.
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

// ═════════════════════════════════════════════════════════════════════════
// 4. KEY SETUP (your private key on this device)
// Runs right after login, before the home screen. Makes sure this device
// has your RSA private key: a new account sees its key to save, a new
// device asks for the saved key (or to generate a new pair, which wipes
// all chats). Nothing else in the app can be used until this is done.
// ═════════════════════════════════════════════════════════════════════════

/// Sits between logging in and the home screen, and blocks the app until
/// this device has the user's private key:
///   new account     -> a key pair is made; shows the private key to save
///   new device      -> asks for the saved private key, or to generate a
///                      new pair (which clears all chats), then shows it
///   normal sign-in  -> goes straight to [child]
class KeyGate extends StatefulWidget {
  const KeyGate({super.key, required this.child});
  final Widget child;

  @override
  State<KeyGate> createState() => _KeyGateState();
}

// What checkKeys() found (null while still checking) and any error.
class _KeyGateState extends State<KeyGate> {
  KeyStatus? _status; // null while checking
  Object? _error;

  /// Starts checking this device's keys as soon as the gate appears.
  @override
  void initState() {
    super.initState();
    _check();
  }

  /// Asks the repository for the key status, then shows the matching
  /// screen (or the error).
  Future<void> _check() async {
    try {
      final status = await repo.checkKeys();
      if (mounted) setState(() => _status = status);
    } catch (e) {
      if (mounted) setState(() => _error = e);
    }
  }

  /// "Try again" after an error: back to the spinner and check again.
  void _retry() {
    setState(() {
      _error = null;
      _status = null;
    });
    _check();
  }

  /// Restores the key pair from the pasted private key, then opens the
  /// app. A wrong key throws; RestoreKeyScreen shows the error.
  Future<void> _restore(String privateKey) async {
    await repo.restorePrivateKey(privateKey);
    if (mounted) setState(() => _status = KeyStatus.ready);
  }

  /// Makes a new key pair (this wipes the chats). Afterwards build() shows
  /// the new private key to save.
  Future<void> _generate() async {
    await repo.replaceKeys();
    if (mounted) setState(() => _status = KeyStatus.ready);
  }

  /// Picks what to show: error, spinner, restore screen, "save your
  /// private key" screen, or finally the real app ([child]).
  @override
  Widget build(BuildContext context) {
    if (_error != null) {
      return _KeySetupLayout(
        title: 'keys',
        children: [
          Text(
            'error: $_error',
            style: const TextStyle(color: Term.red, fontSize: 13),
          ),
          const SizedBox(height: 16),
          ElevatedButton(onPressed: _retry, child: const Text('Try again')),
          TextButton(onPressed: repo.logout, child: const Text('Log out')),
        ],
      );
    }
    final status = _status;
    if (status == null) {
      return const Scaffold(body: Center(child: TermSpinner()));
    }
    if (status == KeyStatus.missing) {
      return RestoreKeyScreen(
        onRestore: _restore,
        onGenerate: _generate,
        onLogout: repo.logout,
      );
    }
    // A key pair made just now (new account or new pair) must be saved
    // by the user before going on.
    final unsaved = repo.unsavedPrivateKey;
    if (unsaved != null) {
      return PrivateKeyBackupScreen(
        privateKey: unsaved,
        onSaved: () => setState(repo.confirmPrivateKeySaved),
      );
    }
    return widget.child;
  }
}

/// Shows a newly made private key and makes the user confirm they saved
/// it. It's their only way to read their chats on a new device.
class PrivateKeyBackupScreen extends StatefulWidget {
  const PrivateKeyBackupScreen({
    super.key,
    required this.privateKey,
    required this.onSaved,
  });

  final String privateKey;
  final VoidCallback onSaved;

  @override
  State<PrivateKeyBackupScreen> createState() => _PrivateKeyBackupScreenState();
}

// Whether the "I saved my private key" box is ticked.
class _PrivateKeyBackupScreenState extends State<PrivateKeyBackupScreen> {
  bool _confirmed = false;

  /// The warning, the key in a box with a Copy button, the checkbox, and
  /// Continue (only enabled once the box is ticked).
  @override
  Widget build(BuildContext context) {
    return _KeySetupLayout(
      title: 'private_key',
      children: [
        const Text(
          'Save your private key',
          style: TextStyle(
            color: Term.amber,
            fontWeight: FontWeight.bold,
            fontSize: 15,
          ),
        ),
        const SizedBox(height: 10),
        const Text(
          'This is your private key. You need it to read your chats on a '
          'new phone or after reinstalling the app. Nobody can recover it '
          'for you.',
          style: TextStyle(color: Term.text, fontSize: 13, height: 1.4),
        ),
        const SizedBox(height: 14),
        _KeyBox(
          child: SelectableText(
            widget.privateKey,
            style: const TextStyle(color: Term.green, fontSize: 12.5),
          ),
        ),
        const SizedBox(height: 10),
        OutlinedButton.icon(
          onPressed: () {
            Clipboard.setData(ClipboardData(text: widget.privateKey));
            toast(context, 'Private key copied.');
          },
          icon: const Icon(Icons.copy_rounded, size: 16),
          label: const Text('Copy private key'),
        ),
        const SizedBox(height: 12),
        const Text(
          'Keep it somewhere safe and private, like a password manager. '
          'Anyone who has it can read your chats.',
          style: TextStyle(color: Term.red, fontSize: 12.5, height: 1.4),
        ),
        const SizedBox(height: 6),
        // Its own Material: the panel's background would hide the tile's
        // ink otherwise (Flutter asserts on that).
        Material(
          type: MaterialType.transparency,
          child: CheckboxListTile(
            value: _confirmed,
            onChanged: (v) => setState(() => _confirmed = v ?? false),
            title: const Text(
              'I saved my private key',
              style: TextStyle(color: Term.text, fontSize: 13),
            ),
            controlAffinity: ListTileControlAffinity.leading,
            contentPadding: EdgeInsets.zero,
            activeColor: Term.green,
            checkColor: Term.bg,
          ),
        ),
        const SizedBox(height: 6),
        ElevatedButton(
          onPressed: _confirmed ? widget.onSaved : null,
          child: const Text('Continue'),
        ),
      ],
    );
  }
}

/// Shown on a new device: asks for the saved private key, or offers to
/// generate a new key pair (which clears every chat).
class RestoreKeyScreen extends StatefulWidget {
  const RestoreKeyScreen({
    super.key,
    required this.onRestore,
    required this.onGenerate,
    required this.onLogout,
  });

  final Future<void> Function(String privateKey) onRestore;
  final Future<void> Function() onGenerate;
  final VoidCallback onLogout;

  @override
  State<RestoreKeyScreen> createState() => _RestoreKeyScreenState();
}

// The paste field, the busy flag and the error shown under the field.
class _RestoreKeyScreenState extends State<RestoreKeyScreen> {
  final _input = TextEditingController();
  bool _busy = false;
  String? _error;

  /// Frees the text field's controller when the screen closes.
  @override
  void dispose() {
    _input.dispose();
    super.dispose();
  }

  /// Runs [action] with the spinner on, showing any error under the field.
  Future<void> _run(Future<void> Function() action) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await action();
    } catch (e) {
      if (mounted) setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  /// Restore button: makes sure something was pasted, then tries it.
  Future<void> _restore() async {
    final text = _input.text.trim();
    if (text.isEmpty) {
      setState(() => _error = 'Paste your private key first.');
      return;
    }
    await _run(() => widget.onRestore(text));
  }

  /// "Generate new key pair" button: asks first, then makes the new pair.
  Future<void> _generate() async {
    if (!await confirmNewKeyPair(context)) return;
    await _run(widget.onGenerate);
  }

  /// The explanation, the paste field, Restore, and the red "Generate new
  /// key pair" button. Log out is always available at the bottom.
  @override
  Widget build(BuildContext context) {
    return _KeySetupLayout(
      title: 'restore_key',
      children: [
        const Text(
          'Cannot find your private key',
          style: TextStyle(
            color: Term.amber,
            fontWeight: FontWeight.bold,
            fontSize: 15,
          ),
        ),
        const SizedBox(height: 10),
        const Text(
          "This device doesn't have your private key, so your chats can't "
          'be opened here. Enter the private key you saved, or generate a '
          'new key pair.',
          style: TextStyle(color: Term.text, fontSize: 13, height: 1.4),
        ),
        const SizedBox(height: 16),
        TextField(
          controller: _input,
          minLines: 3,
          maxLines: 5,
          autocorrect: false,
          enableSuggestions: false,
          style: const TextStyle(color: Term.green, fontSize: 12.5),
          decoration: const InputDecoration(
            labelText: 'private key',
            hintText: 'paste it here',
          ),
        ),
        if (_error != null) ...[
          const SizedBox(height: 10),
          Text(
            'error: $_error',
            style: const TextStyle(color: Term.red, fontSize: 12.5),
          ),
        ],
        const SizedBox(height: 16),
        if (_busy)
          const Center(child: TermSpinner())
        else ...[
          ElevatedButton(onPressed: _restore, child: const Text('Restore')),
          const SizedBox(height: 18),
          const Text(
            'Lost your private key?',
            textAlign: TextAlign.center,
            style: TextStyle(color: Term.muted, fontSize: 12),
          ),
          const SizedBox(height: 6),
          OutlinedButton(
            onPressed: _generate,
            style: OutlinedButton.styleFrom(
              foregroundColor: Term.red,
              side: const BorderSide(color: Term.red),
            ),
            child: const Text('Generate new key pair'),
          ),
        ],
        const SizedBox(height: 6),
        TextButton(
          onPressed: _busy ? null : widget.onLogout,
          child: const Text('Log out'),
        ),
      ],
    );
  }
}

/// Asks before replacing a lost key pair, which deletes every chat.
Future<bool> confirmNewKeyPair(BuildContext context) async {
  final ok = await showDialog<bool>(
    context: context,
    builder: (ctx) => AlertDialog(
      backgroundColor: Term.panel,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(Term.radius),
        side: const BorderSide(color: Term.line),
      ),
      title: const Text(
        'Generate a new key pair?',
        style: TextStyle(color: Term.red, fontSize: 16),
      ),
      content: const Text(
        'Without your old private key, your old messages can never be read '
        'again. A new key pair permanently deletes every message and file '
        'in all your chats, for you and your contacts. Your contacts stay.'
        '\n\nThis cannot be undone.',
        style: TextStyle(color: Term.text, fontSize: 13.5, height: 1.4),
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
          child: const Text('Delete chats & generate'),
        ),
      ],
    ),
  );
  return ok ?? false;
}

/// The centered logo + terminal window shared by the key setup screens.
class _KeySetupLayout extends StatelessWidget {
  const _KeySetupLayout({required this.title, required this.children});
  final String title;
  final List<Widget> children;

  /// The logo at the top, then a terminal panel holding [children].
  /// Scrolls on small screens.
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 460),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const TerminalTitle(size: 22),
                  const SizedBox(height: 20),
                  TerminalPanel(
                    title: title,
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: children,
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

/// A dark bordered box for showing a key.
class _KeyBox extends StatelessWidget {
  const _KeyBox({required this.child});
  final Widget child;

  /// A full-width dark box with a green border around [child].
  @override
  Widget build(BuildContext context) => Container(
    width: double.infinity,
    padding: const EdgeInsets.all(12),
    decoration: BoxDecoration(
      color: Term.bg,
      borderRadius: BorderRadius.circular(Term.radius),
      border: Border.all(color: Term.greenDim),
    ),
    child: child,
  );
}

// ═════════════════════════════════════════════════════════════════════════
// 5. HOME SCREEN
// Your code at the top (tap to copy), your contacts below, and the Add
// contact button. Tapping a contact opens the chat; the red bin removes
// the contact and wipes the chat for both of you.
// ═════════════════════════════════════════════════════════════════════════

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

// Your code (loaded once, can be retried) and the live contact list.
class _HomeScreenState extends State<HomeScreen> {
  // Your code. Not final: the retry button assigns a new attempt.
  late Future<String> _profile;
  late final Stream<List<Contact>> _contacts = repo.contactsStream();

  /// Starts loading your code as soon as the home screen opens.
  @override
  void initState() {
    super.initState();
    // The keys are already sorted out by KeyGate before this screen shows.
    _profile = repo.ensureProfile();
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

  /// Top bar with the logo, your code and Log out; the contact list (or an
  /// empty / error message); and the Add contact button.
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

  /// A bordered row: the code's first two letters, the full code, a red
  /// delete button and an arrow. Tapping the row opens the chat.
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

// The code field, the busy flag and the error shown under the field.
class _AddContactDialogState extends State<AddContactDialog> {
  final _ctrl = TextEditingController();
  bool _busy = false;
  String? _error;

  /// Frees the text field's controller when the dialog closes.
  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  /// Sends a request for the typed code. Closes the dialog (returning the
  /// code) on success, or shows the error and stays open.
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

  /// Instructions, a big code field (letters and digits only, uppercased,
  /// max 8), and Cancel / Send request.
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

// ═════════════════════════════════════════════════════════════════════════
// 6. CHAT SCREEN
// One conversation: the live message list (newest at the bottom), the
// text box with Send and Attach, saving received files, the key button
// that reveals the room's AES key, the shield button that shows the
// safety number, and wiping the chat. The screen closes by itself if the
// other person removes you.
// ═════════════════════════════════════════════════════════════════════════

/// The conversation with one contact: message list, text box, file
/// send/save, and a button to wipe the chat.
class ChatScreen extends StatefulWidget {
  const ChatScreen({super.key, required this.contact});
  final Contact contact;

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

// This chat's room id, the live message list, the text box, and the
// listener that notices if the other person removes you.
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

  /// Starts watching whether you are still contacts. If the other person
  /// removes you, the chat closes and a message explains why.
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

  /// Stops watching, and frees the text box and its focus.
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

  /// Shows this room's AES key: your locked copy from the database, and the
  /// real key after decrypting it with your private key.
  void _revealKey() {
    showDialog<void>(
      context: context,
      builder: (_) => AesKeyDialog(
        contactCode: widget.contact.code,
        load: () async => (
          locked: await repo.lockedRoomKey(roomId),
          key: await repo.roomKey(roomId),
        ),
      ),
    );
  }

  /// Shows the safety number of this chat, so both people can check in
  /// person that nobody swapped their public keys.
  void _showSafetyNumber() {
    showDialog<void>(
      context: context,
      builder: (_) => SafetyNumberDialog(
        contactCode: widget.contact.code,
        load: () => repo.safetyNumber(widget.contact.uid),
      ),
    );
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
            tooltip: 'Safety number',
            icon: const Icon(Icons.verified_user_outlined, color: Term.green),
            onPressed: _showSafetyNumber,
          ),
          IconButton(
            tooltip: 'Reveal AES key',
            icon: const Icon(Icons.key_rounded, color: Term.amber),
            onPressed: _revealKey,
          ),
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

  /// The content of a text message.
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

/// Shows a room's AES key: your locked copy stored in the database, and the
/// real key after it was decrypted with your private key.
class AesKeyDialog extends StatefulWidget {
  const AesKeyDialog({
    super.key,
    required this.contactCode,
    required this.load,
  });

  final String contactCode;
  final Future<({String locked, Uint8List key})> Function() load;

  @override
  State<AesKeyDialog> createState() => _AesKeyDialogState();
}

// Loads the key once, when the dialog opens.
class _AesKeyDialogState extends State<AesKeyDialog> {
  late final Future<({String locked, Uint8List key})> _data = widget.load();

  static const _label = TextStyle(
    color: Term.text,
    fontSize: 12.5,
    fontWeight: FontWeight.bold,
  );
  static const _note = TextStyle(color: Term.muted, fontSize: 11);

  /// The title, then (once loaded) the locked copy and the real key in hex
  /// with a Copy button, or the error.
  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      backgroundColor: Term.panel,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(Term.radius),
        side: const BorderSide(color: Term.line),
      ),
      title: const Text(
        '\$ reveal --aes-key',
        style: TextStyle(color: Term.green, fontSize: 16),
      ),
      content: SizedBox(
        width: double.maxFinite,
        child: FutureBuilder<({String locked, Uint8List key})>(
          future: _data,
          builder: (context, snap) {
            if (snap.hasError) {
              return Text(
                'error: ${snap.error}',
                style: const TextStyle(color: Term.red, fontSize: 12.5),
              );
            }
            if (!snap.hasData) {
              return const SizedBox(
                height: 80,
                child: Center(child: TermSpinner()),
              );
            }
            final data = snap.data!;
            return SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('chat with ${widget.contactCode}', style: _note),
                  const SizedBox(height: 14),
                  const Text('Locked copy in the database', style: _label),
                  const Text(
                    'RSA-encrypted with your public key',
                    style: _note,
                  ),
                  const SizedBox(height: 6),
                  _KeyBox(
                    child: SelectableText(
                      data.locked,
                      style: const TextStyle(color: Term.muted, fontSize: 11),
                    ),
                  ),
                  const SizedBox(height: 16),
                  const Text('Real AES-256 key', style: _label),
                  Text(
                    'decrypted with your private key · '
                    '${data.key.length} bytes',
                    style: _note,
                  ),
                  const SizedBox(height: 6),
                  _KeyBox(
                    child: SelectableText(
                      formatHex(data.key),
                      style: const TextStyle(
                        color: Term.green,
                        fontSize: 13,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
                  const SizedBox(height: 8),
                  TextButton.icon(
                    onPressed: () {
                      Clipboard.setData(
                        ClipboardData(text: formatHex(data.key, groups: false)),
                      );
                      toast(context, 'AES key copied.');
                    },
                    icon: const Icon(Icons.copy_rounded, size: 16),
                    label: const Text('Copy AES key'),
                  ),
                  const SizedBox(height: 4),
                  const Text(
                    'Anyone with this key can read this chat.',
                    style: TextStyle(color: Term.red, fontSize: 12),
                  ),
                ],
              ),
            );
          },
        ),
      ),
      actions: [
        ElevatedButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('Close'),
        ),
      ],
    );
  }
}

/// Shows a chat's safety number: a hash of both people's public keys.
/// Both phones show the same number unless a public key was swapped on the
/// server, so comparing it in person proves nobody is in the middle.
class SafetyNumberDialog extends StatefulWidget {
  const SafetyNumberDialog({
    super.key,
    required this.contactCode,
    required this.load,
  });

  final String contactCode;
  final Future<Uint8List> Function() load;

  @override
  State<SafetyNumberDialog> createState() => _SafetyNumberDialogState();
}

class _SafetyNumberDialogState extends State<SafetyNumberDialog> {
  // Loads the number once, when the dialog opens.
  late final Future<Uint8List> _number = widget.load();

  /// The title, then (once loaded) the first 16 bytes of the safety number
  /// in hex and how to use it, or the error.
  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      backgroundColor: Term.panel,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(Term.radius),
        side: const BorderSide(color: Term.line),
      ),
      title: const Text(
        '\$ verify --safety-number',
        style: TextStyle(color: Term.green, fontSize: 16),
      ),
      content: SizedBox(
        width: double.maxFinite,
        child: FutureBuilder<Uint8List>(
          future: _number,
          builder: (context, snap) {
            if (snap.hasError) {
              return Text(
                'error: ${snap.error}',
                style: const TextStyle(color: Term.red, fontSize: 12.5),
              );
            }
            if (!snap.hasData) {
              return const SizedBox(
                height: 80,
                child: Center(child: TermSpinner()),
              );
            }
            return Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'chat with ${widget.contactCode}',
                  style: const TextStyle(color: Term.muted, fontSize: 11),
                ),
                const SizedBox(height: 12),
                _KeyBox(
                  child: SelectableText(
                    formatHex(snap.data!.sublist(0, 16)),
                    textAlign: TextAlign.center,
                    style: const TextStyle(
                      color: Term.green,
                      fontSize: 15,
                      fontWeight: FontWeight.bold,
                      letterSpacing: 1,
                    ),
                  ),
                ),
                const SizedBox(height: 12),
                Text(
                  'Compare this number with ${widget.contactCode}, in person '
                  'or on a call. If both phones show the same number, your '
                  'chat keys are really each other\'s.',
                  style: const TextStyle(
                    color: Term.text,
                    fontSize: 12.5,
                    height: 1.4,
                  ),
                ),
                const SizedBox(height: 8),
                const Text(
                  'If the numbers are different, someone may be in the '
                  'middle. Don\'t trust this chat.',
                  style: TextStyle(color: Term.red, fontSize: 12),
                ),
              ],
            );
          },
        ),
      ),
      actions: [
        ElevatedButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('Close'),
        ),
      ],
    );
  }
}

// ═════════════════════════════════════════════════════════════════════════
// 7. HELPERS
// Small formatting functions used by the screens: time, file size, hex,
// pop-up messages, and an uppercase filter for text fields.
// ═════════════════════════════════════════════════════════════════════════

/// Bytes as hex, in groups of 4 bytes: "b7075cf0 1a2b3c4d ...".
/// With [groups] false, one unbroken string.
String formatHex(List<int> bytes, {bool groups = true}) {
  final hex = [for (final b in bytes) b.toRadixString(16).padLeft(2, '0')]
      .join();
  if (!groups) return hex;
  return [
    for (var i = 0; i < hex.length; i += 8)
      hex.substring(i, i + 8 > hex.length ? hex.length : i + 8),
  ].join(' ');
}

/// "HH:mm" for today, "dd/MM HH:mm" for other days, "--:--" if missing.
String formatTime(int ms) {
  if (ms <= 0) return '--:--';
  final d = DateTime.fromMillisecondsSinceEpoch(ms);
  final now = DateTime.now();
  // Two digits: 7 -> "07".
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
