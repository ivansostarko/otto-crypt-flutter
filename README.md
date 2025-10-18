# OTTO Crypt — Flutter/Dart Package





Implements **OTTO-256-GCM-HKDF-SIV**:
- **AES-256-GCM** (`package:cryptography`) with 16-byte tags
- **HKDF(SHA-256)** key schedule + deterministic per-chunk nonce derivation
- **Argon2id** + **X25519** (via `package:sodium` + `sodium_libs`, which bundle **libsodium**)

> ⚠️ This is a custom composition around standard primitives. Obtain an **independent security audit** before production.

---

## Install

`pubspec.yaml`:
```yaml
dependencies:
  otto_crypt: ^0.1.0
  sodium: ^2.0.0
  sodium_libs: ^2.0.0
```

On first run, `sodium_libs` downloads the right native binaries.

---

## Quick Start

```dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:otto_crypt/otto_crypt.dart';

void main() async {
  final otto = await OttoCrypt.create(withSodium: true);

  // Strings (password)
  final opt = OttoOptions(password: 'P@ssw0rd!');
  final enc = await otto.encryptString(Uint8List.fromList(utf8.encode('Hello OTTO')), opt);
  final dec = await otto.decryptString(enc.cipherAndTag, enc.header, opt);

  // Files (photos/docs/audio/video)
  await otto.encryptFile('movie.mp4', 'movie.mp4.otto', opt);
  await otto.decryptFile('movie.mp4.otto', 'movie.dec.mp4', opt);

  // X25519 E2E
  final kp = otto.generateKeypair();
  final encOpt = OttoOptions(recipientPublic: base64.encode(kp.publicKey));
  final decOpt = OttoOptions(senderSecret: base64.encode(kp.secret));
  await otto.encryptFile('photo.jpg', 'photo.jpg.otto', encOpt);
  await otto.decryptFile('photo.jpg.otto', 'photo.jpg', decOpt);
}
```

---

## API

```dart
final otto = await OttoCrypt.create(withSodium: true, chunkSize: 1<<20);

Future<OttoEncResult> encryptString(Uint8List plaintext, OttoOptions opt);
Future<Uint8List>     decryptString(Uint8List cipherAndTag, Uint8List header, OttoOptions opt);

Future<void> encryptFile(String inputPath, String outputPath, OttoOptions opt);
Future<void> decryptFile(String inputPath, String outputPath, OttoOptions opt);

// X25519 helpers (libsodium)
OttoKeypair  generateKeypair();
Uint8List    deriveSharedSecret(Uint8List mySecret, Uint8List theirPublic);
Future<Uint8List> deriveSessionKey(Uint8List shared, Uint8List salt, String context);
```

`OttoOptions` accepts one of:
- `password` → Argon2id (libsodium). Header stores `opslimit` + `memlimitKiB` used.
- `rawKey` (32 bytes hex/base64/raw)
- `recipientPublic` (X25519, for encrypt) / `senderSecret` (X25519, for decrypt)

---

## Wire Format (identical to Laravel)

### Header
```
magic      : "OTTO1" (5 bytes)
algo_id    : 0xA1
kdf_id     : 0x01=password | 0x02=raw key | 0x03=X25519
flags      : bit0=chunked
reserved   : 0x00
header_len : uint16 BE of HVAR
HVAR:
  file_salt  (16)
  if kdf=01 (password): pw_salt(16) + opslimit(uint32 BE) + memlimitKiB(uint32 BE)
  if kdf=03 (X25519):   eph_pubkey(32)
```
**AEAD AD** = full header bytes.

### Streaming layout
Per chunk: `[len (u32 BE of ciphertext)] [ciphertext] [tag(16)]`

### Key derivation
```
enc_key   = HKDF(master, 32, "OTTO-ENC-KEY",  file_salt)
nonce_key = HKDF(master, 32, "OTTO-NONCE-KEY", file_salt)
nonce_i   = HKDF(nonce_key, 12, "OTTO-CHUNK-NONCE" || counter64be, "")
```
`master` comes from: **Argon2id**, **raw 32-byte key**, or **X25519 ECDH** via ephemeral sender key (stored in header).

---

## Interop

This Dart port is **byte-for-byte compatible** with the Laravel, Node, Python, .NET, Java/Android, Swift, and C++ OTTO packages:
- Same header fields/order, AD binding, HKDF labels, chunking
- Deterministic nonce derivation
- AES-256-GCM 16-byte tag

You can encrypt in PHP and decrypt in Flutter, and vice versa.

---

## Security Notes

- AES-GCM provides confidentiality + integrity; header is bound as AAD.
- Deterministic nonces eliminate userland nonce-reuse bugs.
- For messengers, prefer **E2E (X25519)**. If using passwords, enforce strong Argon2id settings.
- In-memory key zeroization in Dart/Flutter is limited by GC / copy-on-write.
- **Independent security audit** advised before production use.

---

## Example project

See `/example` for a minimal sample; run `dart run example/main.dart` (desktop) or embed in Flutter.

---

MIT © 2025 Ivan Sostarko
