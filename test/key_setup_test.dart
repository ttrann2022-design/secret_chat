// Widget tests for the private key screens and the AES key dialog. They get
// their data through callbacks, so no Firebase is needed. The real flow
// (new account, new device, new key pair) is in
// integration_test/app_flow_test.dart.
// Run: flutter test test/key_setup_test.dart

import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:security_app/chat_repository.dart';
import 'package:security_app/main.dart';

// The blinking cursor never stops, so pumpAndSettle() would hang.
Future<void> settle(WidgetTester tester) =>
    tester.pump(const Duration(milliseconds: 300));

Future<void> pumpScreen(WidgetTester tester, Widget screen) async {
  await tester.pumpWidget(MaterialApp(theme: buildTheme(), home: screen));
  await settle(tester);
}

void main() {
  group('Save your private key', () {
    testWidgets('shows the key; Continue only works after confirming', (
      tester,
    ) async {
      var saved = false;
      await pumpScreen(
        tester,
        PrivateKeyBackupScreen(
          privateKey: 'ABCDEF123456',
          onSaved: () => saved = true,
        ),
      );
      expect(find.text('Save your private key'), findsOneWidget);
      expect(find.text('ABCDEF123456'), findsOneWidget);

      await tester.tap(find.text('Continue'));
      await settle(tester);
      expect(saved, isFalse); // disabled until the box is ticked

      await tester.tap(find.text('I saved my private key'));
      await settle(tester);
      await tester.tap(find.text('Continue'));
      await settle(tester);
      expect(saved, isTrue);
    });
  });

  group('Cannot find your private key', () {
    Future<List<String>> pumpRestore(
      WidgetTester tester, {
      Future<void> Function(String)? onRestore,
      Future<void> Function()? onGenerate,
    }) async {
      final calls = <String>[];
      await pumpScreen(
        tester,
        RestoreKeyScreen(
          onRestore: onRestore ?? (key) async => calls.add('restore:$key'),
          onGenerate: onGenerate ?? () async => calls.add('generate'),
          onLogout: () => calls.add('logout'),
        ),
      );
      return calls;
    }

    testWidgets('an empty field asks for the key first', (tester) async {
      final calls = await pumpRestore(tester);
      await tester.tap(find.text('Restore'));
      await settle(tester);
      expect(find.text('error: Paste your private key first.'), findsOneWidget);
      expect(calls, isEmpty);
    });

    testWidgets('Restore passes the pasted key on', (tester) async {
      final calls = await pumpRestore(tester);
      await tester.enterText(find.byType(TextField), '  MYKEY==  ');
      await tester.tap(find.text('Restore'));
      await settle(tester);
      expect(calls, ['restore:MYKEY==']);
    });

    testWidgets('a wrong key shows the error and stays on the screen', (
      tester,
    ) async {
      await pumpRestore(
        tester,
        onRestore: (_) async => throw AppError('Wrong private key.'),
      );
      await tester.enterText(find.byType(TextField), 'WRONG');
      await tester.tap(find.text('Restore'));
      await settle(tester);
      expect(find.text('error: Wrong private key.'), findsOneWidget);
      expect(find.text('Restore'), findsOneWidget);
    });

    testWidgets('generating a new pair asks first; Cancel does nothing', (
      tester,
    ) async {
      final calls = await pumpRestore(tester);
      await tester.tap(find.text('Generate new key pair'));
      await settle(tester);
      expect(find.textContaining('cannot be undone'), findsOneWidget);

      await tester.tap(find.text('Cancel'));
      await settle(tester);
      expect(calls, isEmpty);

      await tester.tap(find.text('Generate new key pair'));
      await settle(tester);
      await tester.tap(find.text('Delete chats & generate'));
      await settle(tester);
      expect(calls, ['generate']);
    });
  });

  group('Reveal AES key', () {
    Future<void> openDialog(
      WidgetTester tester,
      Future<({String locked, Uint8List key})> Function() load,
    ) async {
      await pumpScreen(
        tester,
        Builder(
          builder: (context) => TextButton(
            onPressed: () => showDialog<void>(
              context: context,
              builder: (_) => AesKeyDialog(contactCode: 'BOB23456', load: load),
            ),
            child: const Text('open'),
          ),
        ),
      );
      await tester.tap(find.text('open'));
      await settle(tester); // the dialog opens and starts loading
      await settle(tester); // the loaded key is shown
    }

    Finder selectable(String text) =>
        find.byWidgetPredicate((w) => w is SelectableText && w.data == text);

    testWidgets('shows the locked copy and the real key in hex', (
      tester,
    ) async {
      final key = Uint8List.fromList(List.generate(32, (i) => i));
      await openDialog(tester, () async => (locked: 'LOCKED==', key: key));

      expect(selectable('LOCKED=='), findsOneWidget);
      expect(
        selectable(
          '00010203 04050607 08090a0b 0c0d0e0f '
          '10111213 14151617 18191a1b 1c1d1e1f',
        ),
        findsOneWidget,
      );
      expect(find.textContaining('32 bytes'), findsOneWidget);
    });

    testWidgets('shows the error if the key cannot be unlocked', (
      tester,
    ) async {
      await openDialog(
        tester,
        () async => throw AppError("This chat's key can't be unlocked."),
      );
      expect(
        find.text("error: This chat's key can't be unlocked."),
        findsOneWidget,
      );
    });
  });

  group('Safety number', () {
    testWidgets('shows the first 16 bytes and how to compare them', (
      tester,
    ) async {
      final number = Uint8List.fromList(List.generate(32, (i) => i));
      await pumpScreen(
        tester,
        Builder(
          builder: (context) => TextButton(
            onPressed: () => showDialog<void>(
              context: context,
              builder: (_) => SafetyNumberDialog(
                contactCode: 'BOB23456',
                load: () async => number,
              ),
            ),
            child: const Text('open'),
          ),
        ),
      );
      await tester.tap(find.text('open'));
      await settle(tester); // the dialog opens and starts loading
      await settle(tester); // the loaded number is shown

      expect(
        find.byWidgetPredicate(
          (w) =>
              w is SelectableText &&
              w.data == '00010203 04050607 08090a0b 0c0d0e0f',
        ),
        findsOneWidget,
      );
      expect(
        find.textContaining('Compare this number with BOB23456'),
        findsOneWidget,
      );
    });
  });

  test('formatHex groups 4 bytes, or none', () {
    expect(formatHex([0xb7, 0x07, 0x5c, 0xf0, 0x1a]), 'b7075cf0 1a');
    expect(
      formatHex([0xb7, 0x07, 0x5c, 0xf0, 0x1a], groups: false),
      'b7075cf01a',
    );
  });
}
