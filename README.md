<div align="center">

<img src="assets/logo.png" alt="Secret Chat logo" width="120">

# Secret Chat

**Private, end-to-end encrypted chat rooms for two.**

![Version](https://img.shields.io/badge/version-1.0.5-39FF88)
![Platform](https://img.shields.io/badge/platform-Android-3DDC84?logo=android&logoColor=white)
![Flutter](https://img.shields.io/badge/Flutter-02569B?logo=flutter&logoColor=white)
![Firebase](https://img.shields.io/badge/Firebase-FFCA28?logo=firebase&logoColor=black)
![Encryption](https://img.shields.io/badge/encryption-RSA%20%2B%20AES--256-555555)

</div>

---

A simple private chat app for two people at a time. Add a friend with their personal code, chat, share files, and wipe the whole conversation whenever you want. Everything you send is end-to-end encrypted.

## ✨ Features

- **Personal code.** You get an 8-character code. Share it so friends can add you.
- **Contact requests.** Nobody can chat with you until you accept their request.
- **End-to-end encryption.** Messages, file names and files are encrypted on your phone. Only you and your contact can read them, not even the server owner.
- **Messages and files.** Send text and files up to 5 MB. Tap a received file to save it.
- **Safety number.** Compare a short number with your contact to make sure nobody is in the middle.
- **Private key backup.** Save your private key once, then use it to open your chats on a new phone.
- **Wipe anytime.** Removing a contact deletes all your messages and files with them, for both of you.

## 📲 Install (Android)

1. Open the [**Releases**](../../releases) page of this repository.
2. Download the `.apk` file from the latest release.
3. Open it on your phone. If asked, allow installing apps from this source.

> [!NOTE]
> Because the app isn't from the Play Store, your phone may show a warning. Tap **Install anyway**.

## 🚀 How to use

1. Create an account with your email and a password.
2. **Save your private key.** The app shows it once. Copy it somewhere safe, like a password manager, then tick the box and continue.
3. Your code is at the top of the home screen. Tap it to copy and share it.
4. To add someone, tap **Add contact** and enter their code.
5. When they accept, they appear in your contact list. Tap them to chat.
6. Tap the paperclip to send a file.
7. Tap the shield icon to see the safety number. If it matches on both phones, your chat is secure.
8. Tap the red trash icon to remove a contact and wipe the chat.

> [!TIP]
> **New phone or reinstalled the app?** Log in and paste the private key you saved. If you lost it, you can generate a new one, but that deletes the messages and files in all your chats (your contacts stay).

## 🔐 How the encryption works

The app uses a hybrid scheme:

| Part | What it does |
|---|---|
| **RSA (1024-bit), written by hand** | Every user has a key pair. The public key is stored on the server; the private key never leaves the phone. |
| **AES-256-GCM** | Each chat has its own random AES key that encrypts every message and file. It is stored only in locked form, once for each person, with their RSA public key. |
| **Signatures (RSA + SHA-256)** | Whoever creates a chat's key signs it, so a key slipped in by someone else is rejected. |

Prime generation, Miller-Rabin, RSA padding, signatures and SHA-256 are in [`lib/crypto/key_manager.dart`](lib/crypto/key_manager.dart). AES is in [`lib/crypto/cipher.dart`](lib/crypto/cipher.dart).

## 📌 Good to know

> [!IMPORTANT]
> **Keep your private key safe.** Anyone who has it can read your chats. Nobody can recover it for you if you lose it.

- The server can still see who you chat with, when, and how big your files are, just not what you say.
- Contacts only see your code, never your email address.
- Files are limited to 5 MB each.
- Wiped chats can't be recovered.
