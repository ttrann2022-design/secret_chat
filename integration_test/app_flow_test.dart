// End-to-end tests against the Firebase Emulator Suite (never the real
// database). Two users are signed in at once: Alice drives the real app UI,
// Bob acts through a second Firebase app instance.
//
// Run everything with:  powershell -ExecutionPolicy Bypass -File .\run_tests.ps1
//
// Option (add with --dart-define):
//   EMULATOR_HOST=192.168.1.20  host running the emulators (defaults to
//                               10.0.2.2 on Android emulator, else localhost)
//
// Expected to FAIL until done:
//   - "Encryption at rest": messages and files must be encrypted before they
//     are written to the database.
//   - "an outsider cannot read...": needs database.rules.json loaded into the
//     emulator (list it under "database" in firebase.json).

import 'dart:convert';
import 'dart:io' show Platform;
import 'dart:typed_data';

import 'package:firebase_auth/firebase_auth.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_database/firebase_database.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:security_app/firebase_options.dart';
import 'package:security_app/main.dart';

const kHost = String.fromEnvironment('EMULATOR_HOST');
const kPass = 'secret123';

late ChatRepository bob;
late ChatRepository carol;

final _run = DateTime.now().millisecondsSinceEpoch;
var _userCount = 0;

class TestUser {
  TestUser(this.email, this.uid, this.code);
  final String email;
  final String uid;
  final String code;
}

String newEmail(String who) => '$who${_userCount++}.$_run@test.dev';

Future<FirebaseApp> connect([String? name]) async {
  final options = DefaultFirebaseOptions.currentPlatform;
  final app = name == null
      ? await Firebase.initializeApp(options: options)
      : await Firebase.initializeApp(name: name, options: options);
  final host = kHost.isNotEmpty
      ? kHost
      : (Platform.isAndroid ? '10.0.2.2' : 'localhost');
  await FirebaseAuth.instanceFor(app: app).useAuthEmulator(host, 9099);
  FirebaseDatabase.instanceFor(
    app: app,
    databaseURL: kDatabaseUrl,
  ).useDatabaseEmulator(host, 9000);
  return app;
}

/// Registers a fresh account on [r] and returns it signed in.
Future<TestUser> signUp(ChatRepository r, String who) async {
  await r.logout();
  final email = newEmail(who);
  await r.register(email, kPass);
  return TestUser(email, r.uid, await r.ensureProfile());
}

/// Bob sends a request to Alice and Alice accepts. Returns the room id.
Future<String> befriend(TestUser a, TestUser b) async {
  await bob.sendRequest(a.code);
  final reqs = await waitFor(repo.requestsStream(a.uid), (l) => l.isNotEmpty);
  await repo.acceptRequest(reqs.single);
  return ChatRepository.roomIdFor(a.uid, b.uid);
}

Future<T> waitFor<T>(Stream<T> s, bool Function(T) ok) =>
    s.firstWhere(ok).timeout(const Duration(seconds: 10));

/// pumpAndSettle() never returns here (the cursor blinks forever), so pump
/// until [finder] shows up instead.
Future<void> pumpUntil(
  WidgetTester t,
  Finder finder, {
  Duration timeout = const Duration(seconds: 15),
}) async {
  final end = DateTime.now().add(timeout);
  while (DateTime.now().isBefore(end)) {
    await t.pump(const Duration(milliseconds: 100));
    if (finder.evaluate().isNotEmpty) return;
  }
  throw TestFailure('Timed out waiting for $finder');
}

Future<void> pumpGone(WidgetTester t, Finder finder) async {
  final end = DateTime.now().add(const Duration(seconds: 15));
  while (DateTime.now().isBefore(end)) {
    await t.pump(const Duration(milliseconds: 100));
    if (finder.evaluate().isEmpty) return;
  }
  throw TestFailure('Still showing $finder');
}

Future<void> openApp(WidgetTester t) async {
  await t.pumpWidget(const SecretChatApp());
  await t.pump(const Duration(milliseconds: 300));
}

Finder field(String label) => find.widgetWithText(TextField, label);

/// Every string stored anywhere under a database value.
List<String> stringLeaves(Object? v) => switch (v) {
  String s => [s],
  Map m => m.values.expand(stringLeaves).toList(),
  List l => l.expand(stringLeaves).toList(),
  _ => const [],
};

/// True if nothing is left at [path]. With real rules a deleted room can't be
/// read at all (its member list is gone too), which also means it is gone.
Future<bool> isGone(ChatRepository r, String path) async {
  try {
    return !(await r.ref(path).get()).exists;
  } on FirebaseException catch (e) {
    return e.code == 'permission-denied';
  }
}

Matcher appError(String text) =>
    throwsA(isA<AppError>().having((e) => e.message, 'message', contains(text)));

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  setUpAll(() async {
    await connect();
    bob = ChatRepository(await connect('bob'));
    carol = ChatRepository(await connect('carol'));
  });

  // ─────────────────────────────────────────────────────────────────────────
  group('Register and login', () {
    testWidgets('a new user can register and lands on the home screen', (
      t,
    ) async {
      await repo.logout();
      await openApp(t);
      await t.tap(find.text('New here? Create an account'));
      await t.pump();
      await t.enterText(field('email'), newEmail('reg'));
      await t.enterText(field('password'), kPass);
      await t.enterText(field('confirm password'), kPass);
      await t.tap(find.text('Create account'));

      await pumpUntil(t, find.byType(CodeBadge));
      expect(find.text('Add contact'), findsOneWidget);
      expect(find.text(await repo.ensureProfile()), findsOneWidget);
    });

    testWidgets('registering an email that already exists shows an error', (
      t,
    ) async {
      final a = await signUp(repo, 'dup');
      await repo.logout();
      await openApp(t);
      await t.tap(find.text('New here? Create an account'));
      await t.pump();
      await t.enterText(field('email'), a.email);
      await t.enterText(field('password'), kPass);
      await t.enterText(field('confirm password'), kPass);
      await t.tap(find.text('Create account'));

      await pumpUntil(t, find.textContaining('already exists'));
    });

    testWidgets('an existing user can log in and log out', (t) async {
      final a = await signUp(repo, 'login');
      await repo.logout();
      await openApp(t);
      await t.enterText(field('email'), a.email);
      await t.enterText(field('password'), kPass);
      await t.tap(find.text('Log in'));

      await pumpUntil(t, find.text(a.code)); // same code as at sign-up

      await t.tap(find.byTooltip('Log out'));
      await pumpUntil(t, find.text('Log in'));
      expect(FirebaseAuth.instance.currentUser, isNull);
    });

    testWidgets('a wrong password is rejected', (t) async {
      final a = await signUp(repo, 'wrongpw');
      await repo.logout();
      await openApp(t);
      await t.enterText(field('email'), a.email);
      await t.enterText(field('password'), 'not-the-password');
      await t.tap(find.text('Log in'));

      await pumpUntil(t, find.text('error: Wrong email or password.'));
      expect(find.byType(HomeScreen), findsNothing);
    });

    testWidgets('an unknown email is rejected', (t) async {
      await repo.logout();
      await openApp(t);
      await t.enterText(field('email'), newEmail('nobody'));
      await t.enterText(field('password'), kPass);
      await t.tap(find.text('Log in'));

      await pumpUntil(t, find.text('error: Wrong email or password.'));
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  group('Personal code', () {
    test('every user gets a readable 8-character code', () async {
      final a = await signUp(repo, 'code');
      expect(a.code, matches(RegExp(r'^[A-HJ-NP-Z2-9]{8}$')));
    });

    test('the code stays the same after logging in again', () async {
      final a = await signUp(repo, 'stable');
      await repo.logout();
      await repo.login(a.email, kPass);
      expect(await repo.ensureProfile(), a.code);
    });

    test('two users never share a code', () async {
      final a = await signUp(repo, 'u');
      final b = await signUp(bob, 'u');
      expect(a.code, isNot(b.code));
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  group('Add contact by code', () {
    testWidgets('A adds B by code; they are contacts only after B accepts', (
      t,
    ) async {
      final a = await signUp(repo, 'alice');
      final b = await signUp(bob, 'bob');
      await openApp(t);
      await pumpUntil(t, find.byType(CodeBadge));

      await t.tap(find.text('Add contact'));
      await pumpUntil(t, find.byType(AddContactDialog));
      await t.enterText(
        find.descendant(
          of: find.byType(AddContactDialog),
          matching: find.byType(TextField),
        ),
        b.code,
      );
      await t.tap(find.text('Send request'));
      await pumpUntil(t, find.textContaining('Request sent to ${b.code}'));

      // Not contacts yet.
      expect(await repo.contactsStream().first, isEmpty);
      expect(await bob.contactsStream().first, isEmpty);

      final reqs = await waitFor(bob.requestsStream(b.uid), (l) => l.isNotEmpty);
      expect(reqs.single.fromCode, a.code);
      await bob.acceptRequest(reqs.single);

      await pumpUntil(t, find.widgetWithText(ContactTile, b.code));
      final bobsContacts = await bob.contactsStream().first;
      expect(bobsContacts.single.code, a.code);
    });

    testWidgets('an incoming request pops up and can be accepted', (t) async {
      final a = await signUp(repo, 'alice');
      final b = await signUp(bob, 'bob');
      await openApp(t);
      await pumpUntil(t, find.byType(CodeBadge));

      await bob.sendRequest(a.code);
      await pumpUntil(t, find.text('Someone wants to chat with you'));
      expect(find.text(b.code), findsOneWidget);

      await t.tap(find.text('Accept'));
      await pumpGone(t, find.byType(RequestPopup));
      await pumpUntil(t, find.widgetWithText(ContactTile, b.code));
      expect((await bob.contactsStream().first).single.uid, a.uid);
    });

    testWidgets('a declined request adds no one', (t) async {
      final a = await signUp(repo, 'alice');
      await signUp(bob, 'bob');
      await openApp(t);
      await pumpUntil(t, find.byType(CodeBadge));

      await bob.sendRequest(a.code);
      await pumpUntil(t, find.text('Decline'));
      await t.tap(find.text('Decline'));
      await pumpGone(t, find.byType(RequestPopup));

      expect(await repo.contactsStream().first, isEmpty);
      expect(await bob.contactsStream().first, isEmpty);
      expect(await repo.requestsStream(a.uid).first, isEmpty);
    });

    test('codes are accepted in lowercase and with spaces', () async {
      await signUp(repo, 'alice');
      final b = await signUp(bob, 'bob');
      expect(await repo.sendRequest('  ${b.code.toLowerCase()} '), b.code);
    });

    test('you cannot add your own code', () async {
      final a = await signUp(repo, 'self');
      expect(repo.sendRequest(a.code), appError('your own code'));
    });

    test('an unknown code is rejected', () async {
      await signUp(repo, 'alice');
      expect(repo.sendRequest('ZZZZ2222'), appError('No user has the code'));
    });

    test('a code with the wrong length is rejected', () async {
      await signUp(repo, 'alice');
      expect(repo.sendRequest('ABC123'), appError('8 characters'));
    });

    test('an existing contact cannot be added twice', () async {
      final a = await signUp(repo, 'alice');
      final b = await signUp(bob, 'bob');
      await befriend(a, b);
      expect(repo.sendRequest(b.code), appError('already in your contacts'));
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  group('Chat', () {
    testWidgets('both users read each other\'s messages', (t) async {
      final a = await signUp(repo, 'alice');
      final b = await signUp(bob, 'bob');
      final room = await befriend(a, b);

      await openApp(t);
      await pumpUntil(t, find.widgetWithText(ContactTile, b.code));
      await t.tap(find.widgetWithText(ContactTile, b.code));
      await pumpUntil(t, find.byType(ChatScreen));

      // Alice -> Bob through the UI.
      await t.enterText(field('type a message'), 'hello bob');
      await t.tap(find.byTooltip('Send'));
      final bobSees = await waitFor(
        bob.messagesStream(room),
        (l) => l.isNotEmpty,
      );
      expect(bobSees.single.text, 'hello bob');
      expect(bobSees.single.senderId, a.uid);

      // Bob -> Alice shows up on Alice's screen.
      await bob.sendText(room, 'hi alice');
      await pumpUntil(t, find.text('hi alice'));

      // Same history, same order, on both sides.
      final mine = await waitFor(repo.messagesStream(room), (l) => l.length == 2);
      final theirs = await waitFor(bob.messagesStream(room), (l) => l.length == 2);
      expect(mine.map((m) => m.text), ['hello bob', 'hi alice']);
      expect(theirs.map((m) => m.text), ['hello bob', 'hi alice']);
    });

    testWidgets('an empty message is not sent', (t) async {
      final a = await signUp(repo, 'alice');
      final b = await signUp(bob, 'bob');
      final room = await befriend(a, b);

      await openApp(t);
      await pumpUntil(t, find.widgetWithText(ContactTile, b.code));
      await t.tap(find.widgetWithText(ContactTile, b.code));
      await pumpUntil(t, find.byType(ChatScreen));

      await t.enterText(field('type a message'), '   ');
      await t.tap(find.byTooltip('Send'));
      await t.pump(const Duration(seconds: 1));
      expect(await repo.messagesStream(room).first, isEmpty);
    });

    testWidgets('a sent file shows in the chat and the peer downloads it', (
      t,
    ) async {
      final a = await signUp(repo, 'alice');
      final b = await signUp(bob, 'bob');
      final room = await befriend(a, b);
      final bytes = Uint8List.fromList(utf8.encode('quarterly numbers: 42'));

      await openApp(t);
      await pumpUntil(t, find.widgetWithText(ContactTile, b.code));
      await t.tap(find.widgetWithText(ContactTile, b.code));
      await pumpUntil(t, find.byType(ChatScreen));

      // The native file picker can't be driven by tests, so send directly.
      await repo.sendFile(room, 'notes.txt', bytes);
      await pumpUntil(t, find.text('notes.txt'));

      final msgs = await waitFor(bob.messagesStream(room), (l) => l.isNotEmpty);
      final file = msgs.single;
      expect(file.isFile, isTrue);
      expect(file.text, 'notes.txt');
      expect(file.fileSize, bytes.length);
      expect(await bob.downloadFile(room, file.fileId!), bytes);
    });

    test('files work in both directions', () async {
      final a = await signUp(repo, 'alice');
      final b = await signUp(bob, 'bob');
      final room = await befriend(a, b);
      final bytes = Uint8List.fromList(List.generate(300000, (i) => i % 256));

      await bob.sendFile(room, 'photo.jpg', bytes);
      final msgs = await waitFor(repo.messagesStream(room), (l) => l.isNotEmpty);
      expect(await repo.downloadFile(room, msgs.single.fileId!), bytes);
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  group('Remove contact wipes the chat', () {
    testWidgets('removing from the home screen wipes it for both users', (
      t,
    ) async {
      final a = await signUp(repo, 'alice');
      final b = await signUp(bob, 'bob');
      final room = await befriend(a, b);
      await repo.sendText(room, 'soon gone');
      await bob.sendFile(room, 'x.bin', Uint8List.fromList([1, 2, 3]));

      await openApp(t);
      await pumpUntil(t, find.widgetWithText(ContactTile, b.code));
      await t.tap(find.byTooltip('Remove and wipe chat'));
      await pumpUntil(t, find.text('Wipe chat'));
      await t.tap(find.text('Wipe chat'));
      await pumpUntil(t, find.text('Chat with ${b.code} wiped.'));

      expect(await repo.contactsStream().first, isEmpty);
      expect(await bob.contactsStream().first, isEmpty);
      expect(await isGone(repo, 'rooms/$room'), isTrue);
      expect(await isGone(repo, 'files/$room'), isTrue);
    });

    testWidgets('cancelling the confirm dialog keeps everything', (t) async {
      final a = await signUp(repo, 'alice');
      final b = await signUp(bob, 'bob');
      final room = await befriend(a, b);
      await repo.sendText(room, 'still here');

      await openApp(t);
      await pumpUntil(t, find.widgetWithText(ContactTile, b.code));
      await t.tap(find.byTooltip('Remove and wipe chat'));
      await pumpUntil(t, find.text('Cancel'));
      await t.tap(find.text('Cancel'));
      await t.pump(const Duration(seconds: 1));

      expect(find.widgetWithText(ContactTile, b.code), findsOneWidget);
      expect((await bob.messagesStream(room).first).single.text, 'still here');
    });

    testWidgets('when the peer removes you, your open chat closes', (t) async {
      final a = await signUp(repo, 'alice');
      final b = await signUp(bob, 'bob');
      final room = await befriend(a, b);
      await bob.sendText(room, 'bye');

      await openApp(t);
      await pumpUntil(t, find.widgetWithText(ContactTile, b.code));
      await t.tap(find.widgetWithText(ContactTile, b.code));
      await pumpUntil(t, find.text('bye'));

      await bob.removeContact(a.uid);
      await pumpUntil(t, find.text('The chat with ${b.code} was removed.'));
      // The message shows while the chat screen is still sliding away.
      await pumpGone(t, find.byType(ChatScreen));
      await pumpGone(t, find.byType(ContactTile));
      expect(await isGone(repo, 'rooms/$room'), isTrue);
    });

    test('a wiped file can no longer be downloaded', () async {
      final a = await signUp(repo, 'alice');
      final b = await signUp(bob, 'bob');
      final room = await befriend(a, b);
      await repo.sendFile(room, 'a.txt', Uint8List.fromList([9, 9, 9]));
      final msgs = await waitFor(bob.messagesStream(room), (l) => l.isNotEmpty);

      await repo.removeContact(b.uid);
      expect(bob.downloadFile(room, msgs.single.fileId!), throwsA(anything));
    });

    test('re-adding each other starts with an empty chat', () async {
      final a = await signUp(repo, 'alice');
      final b = await signUp(bob, 'bob');
      final room = await befriend(a, b);
      await repo.sendText(room, 'old message');
      await repo.removeContact(b.uid);

      expect(await befriend(a, b), room);
      expect(await repo.messagesStream(room).first, isEmpty);
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  group('Encryption at rest', () {
    test('a text message is stored encrypted; the peer reads it', () async {
      final a = await signUp(repo, 'alice');
      final b = await signUp(bob, 'bob');
      final room = await befriend(a, b);
      const secret = 'the vault code is 7319';

      await repo.sendText(room, secret);

      final raw = await repo.ref('rooms/$room/messages').get();
      for (final s in stringLeaves(raw.value)) {
        expect(s, isNot(contains(secret)));
        expect(s, isNot(contains('7319')));
      }
      final bobSees = await waitFor(bob.messagesStream(room), (l) => l.isNotEmpty);
      expect(bobSees.single.text, secret);
    });

    test('the sender can still read their own message', () async {
      final a = await signUp(repo, 'alice');
      final b = await signUp(bob, 'bob');
      final room = await befriend(a, b);

      await repo.sendText(room, 'note to self');
      final mine = await waitFor(repo.messagesStream(room), (l) => l.isNotEmpty);
      expect(mine.single.text, 'note to self');
    });

    test('file contents are stored encrypted; the peer gets the original', () async {
      final a = await signUp(repo, 'alice');
      final b = await signUp(bob, 'bob');
      final room = await befriend(a, b);
      final bytes = Uint8List.fromList(utf8.encode('CONFIDENTIAL payroll'));

      await repo.sendFile(room, 'payroll.csv', bytes);

      final raw = await repo.ref('files/$room').get();
      for (final s in stringLeaves(raw.value)) {
        expect(s, isNot(base64Encode(bytes)));
        expect(s, isNot(contains('CONFIDENTIAL')));
        final Uint8List decoded;
        try {
          decoded = base64Decode(s);
        } on FormatException {
          continue; // not base64, already checked as plain text above
        }
        expect(
          utf8.decode(decoded, allowMalformed: true),
          isNot(contains('CONFIDENTIAL')),
        );
      }
      final msgs = await waitFor(bob.messagesStream(room), (l) => l.isNotEmpty);
      expect(await bob.downloadFile(room, msgs.single.fileId!), bytes);
    });

    test('the file name is stored encrypted; the peer sees it', () async {
      final a = await signUp(repo, 'alice');
      final b = await signUp(bob, 'bob');
      final room = await befriend(a, b);

      await repo.sendFile(room, 'salary_2026.xlsx', Uint8List.fromList([1]));

      final raw = await repo.ref('rooms/$room/messages').get();
      for (final s in stringLeaves(raw.value)) {
        expect(s, isNot(contains('salary_2026')));
      }
      final msgs = await waitFor(bob.messagesStream(room), (l) => l.isNotEmpty);
      expect(msgs.single.text, 'salary_2026.xlsx');
    });

    test('an outsider cannot read the pair\'s messages or files', () async {
      final a = await signUp(repo, 'alice');
      final b = await signUp(bob, 'bob');
      final room = await befriend(a, b);
      await repo.sendText(room, 'private');
      await signUp(carol, 'carol');

      Future<void> denied(String path) => expectLater(
        carol.ref(path).get(),
        throwsA(
          isA<FirebaseException>().having((e) => e.code, 'code', 'permission-denied'),
        ),
        reason:
            'A non-member could read $path. Put your security rules in '
            'database.rules.json and list it under "database" in firebase.json.',
      );
      await denied('rooms/$room/messages');
      await denied('files/$room');
    });
  });
}
