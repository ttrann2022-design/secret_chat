// Widget tests for the login/register form and the add-contact dialog.
// These only cover input checks that happen BEFORE anything is sent to
// Firebase, so no Firebase is needed. Real register/login is covered in
// integration_test/app_flow_test.dart.
// Run: flutter test test/auth_screen_test.dart

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:security_app/main.dart';

// The blinking cursor never stops, so pumpAndSettle() would hang.
Future<void> settle(WidgetTester tester) =>
    tester.pump(const Duration(milliseconds: 300));

Future<void> pumpAuth(WidgetTester tester) async {
  await tester.pumpWidget(
    MaterialApp(theme: buildTheme(), home: const AuthScreen()),
  );
  await settle(tester);
}

Finder field(String label) => find.widgetWithText(TextField, label);

void main() {
  group('Login form', () {
    testWidgets('shows email and password, no confirm field', (tester) async {
      await pumpAuth(tester);
      expect(field('email'), findsOneWidget);
      expect(field('password'), findsOneWidget);
      expect(field('confirm password'), findsNothing);
      expect(find.text('Log in'), findsOneWidget);
    });

    testWidgets('hides the password while typing', (tester) async {
      await pumpAuth(tester);
      final pass = tester.widget<TextField>(field('password'));
      expect(pass.obscureText, isTrue);
    });

    testWidgets('rejects empty email and password', (tester) async {
      await pumpAuth(tester);
      await tester.tap(find.text('Log in'));
      await settle(tester);
      expect(find.text('error: Enter your email and password.'), findsOne);
    });

    testWidgets('treats a blank (spaces only) email as empty', (tester) async {
      await pumpAuth(tester);
      await tester.enterText(field('email'), '   ');
      await tester.enterText(field('password'), 'secret123');
      await tester.tap(find.text('Log in'));
      await settle(tester);
      expect(find.text('error: Enter your email and password.'), findsOne);
    });
  });

  group('Register form', () {
    Future<void> openRegister(WidgetTester tester) async {
      await pumpAuth(tester);
      await tester.tap(find.text('New here? Create an account'));
      await settle(tester);
    }

    testWidgets('switching to register shows confirm password', (tester) async {
      await openRegister(tester);
      expect(field('confirm password'), findsOneWidget);
      expect(find.text('Create account'), findsOneWidget);
    });

    testWidgets('rejects passwords shorter than 6 characters', (tester) async {
      await openRegister(tester);
      await tester.enterText(field('email'), 'a@b.com');
      await tester.enterText(field('password'), '12345');
      await tester.enterText(field('confirm password'), '12345');
      await tester.tap(find.text('Create account'));
      await settle(tester);
      expect(find.text('error: Password needs at least 6 characters.'), findsOne);
    });

    testWidgets('rejects passwords that do not match', (tester) async {
      await openRegister(tester);
      await tester.enterText(field('email'), 'a@b.com');
      await tester.enterText(field('password'), 'secret123');
      await tester.enterText(field('confirm password'), 'secret124');
      await tester.tap(find.text('Create account'));
      await settle(tester);
      expect(find.text("error: Passwords don't match."), findsOne);
    });

    testWidgets('switching back to login clears the error', (tester) async {
      await openRegister(tester);
      await tester.tap(find.text('Create account'));
      await settle(tester);
      expect(find.textContaining('error:'), findsOne);

      await tester.tap(find.text('Already have an account? Log in'));
      await settle(tester);
      expect(find.textContaining('error:'), findsNothing);
      expect(field('confirm password'), findsNothing);
    });
  });

  group('Add contact dialog', () {
    Future<void> openDialog(WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          theme: buildTheme(),
          home: Builder(
            builder: (context) => TextButton(
              onPressed: () => showDialog<String>(
                context: context,
                builder: (_) => const AddContactDialog(),
              ),
              child: const Text('open'),
            ),
          ),
        ),
      );
      await tester.tap(find.text('open'));
      await settle(tester);
    }

    testWidgets('code field uppercases, drops symbols, max 8 chars', (
      tester,
    ) async {
      await openDialog(tester);
      await tester.enterText(find.byType(TextField), 'ab-c1 2d!ef9z');
      await settle(tester);
      final input = tester.widget<TextField>(find.byType(TextField));
      expect(input.controller!.text, 'ABC12DEF');
    });

    testWidgets('Cancel closes the dialog', (tester) async {
      await openDialog(tester);
      expect(find.byType(AddContactDialog), findsOneWidget);
      await tester.tap(find.text('Cancel'));
      await settle(tester);
      expect(find.byType(AddContactDialog), findsNothing);
    });
  });
}
