library otto_crypt;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:sodium/sodium.dart';

/// OTTO Crypt options
class OttoOptions {
  String? password;
  String? recipientPublic; // base64/hex/raw
  String? senderSecret;    // base64/hex/raw
  String? rawKey;          // base64/hex/raw
  int? opslimit;           // Argon2id ops (libsodium)
  int? memlimit;           // Argon2id mem bytes (libsodium)

  OttoOptions({
    this.password,
    this.recipientPublic,
    this.senderSecret,
    this.rawKey,
    this.opslimit,
    this.memlimit,
  });
}

class OttoEncResult {
  final Uint8List cipherAndTag;
  final Uint8List header;
  OttoEncResult(this.cipherAndTag, this.header);
}

class OttoKeypair {
  final Uint8List secret;
  final Uint8List publicKey;
  OttoKeypair(this.secret, this.publicKey);
}

/// Core implementation
class OttoCrypt {
  static final Uint8List magic = Uint8List.fromList(utf8.encode("OTTO1"));
  static const int algoId = 0xA1;
  static const int kdfPassword = 0x01;
  static const int kdfRawKey   = 0x02;
  static const int kdfX25519   = 0x03;
  static const int flagChunked = 0x01;

  final int chunkSize;
  final AesGcm _aes;
  final Hkdf _hkdf;
  final Sodium? _sodium;

  OttoCrypt._(this.chunkSize, this._aes, this._hkdf, this._sodium);

  /// Create an instance. If [withSodium] is true, initializes libsodium for Argon2id + X25519.
  static Future<OttoCrypt> create({int chunkSize = 1<<20, bool withSodium = true}) async {
    final aes = AesGcm.with256bits();
    final hkdf = Hkdf(hmac: Hmac.sha256());
    Sodium? sodium;
    if (withSodium) {
      sodium = await SodiumInit.init();
    }
    return OttoCrypt._(chunkSize, aes, hkdf, sodium);
  }

  // ===== Helpers =====
  Uint8List _decodeKey(String? s) {
    if (s == null) return Uint8List(0);
    final t = s.trim();
    if (t.isEmpty) return Uint8List(0);
    final hexRe = RegExp(r'^[0-9a-fA-F]+$');
    if (hexRe.hasMatch(t) && t.length % 2 == 0) {
      try {
        final out = Uint8List(t.length ~/ 2);
        for (var i = 0; i < out.length; i++) {
          out[i] = int.parse(t.substring(2*i, 2*i+2), radix: 16);
        }
        return out;
      } catch (_) {}
    }
    try {
      return Uint8List.fromList(base64.decode(t));
    } catch (_) {
      return Uint8List.fromList(utf8.encode(t));
    }
  }

  Uint8List _be16(int v) {
    return Uint8List.fromList([(v >> 8) & 0xff, v & 0xff]);
  }
  Uint8List _be32(int v) {
    return Uint8List.fromList([
      (v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff
    ]);
  }
  int _readU32(Uint8List b, int off) {
    return ((b[off] & 0xff) << 24) |
           ((b[off+1] & 0xff) << 16) |
           ((b[off+2] & 0xff) << 8) |
           (b[off+3] & 0xff);
  }

  Future<Uint8List> _hkdfDerive({
    required List<int> ikm,
    required int length,
    required List<int> info,
    required List<int> salt,
  }) async {
    final secret = SecretKey(ikm);
    final out = await _hkdf.deriveKey(
      secretKey: secret,
      outputLength: length,
      nonce: salt, // HKDF uses salt parameter here
      info: info,
    );
    return Uint8List.fromList(await out.extractBytes());
  }

  Future<(Uint8List, Uint8List)> _aesGcmEncrypt({
    required Uint8List key32,
    required Uint8List nonce12,
    required Uint8List aad,
    required Uint8List plain,
  }) async {
    final secretKey = SecretKey(key32);
    final res = await _aes.encrypt(
      plain,
      secretKey: secretKey,
      nonce: nonce12,
      aad: aad,
    );
    final ct = Uint8List.fromList(res.cipherText);
    final tag = Uint8List.fromList(res.mac.bytes);
    return (ct, tag);
  }

  Future<Uint8List> _aesGcmDecrypt({
    required Uint8List key32,
    required Uint8List nonce12,
    required Uint8List aad,
    required Uint8List cipher,
    required Uint8List tag,
  }) async {
    final secretKey = SecretKey(key32);
    final res = await _aes.decrypt(
      SecretBox(cipher, nonce: nonce12, mac: Mac(tag)),
      secretKey: secretKey,
      aad: aad,
    );
    return Uint8List.fromList(res);
  }

  Future<Uint8List> _chunkNonce(Uint8List nonceKey, int counter) async {
    final ctr = ByteData(8)..setUint64(0, counter, Endian.big);
    final info = Uint8List.fromList([
      ...utf8.encode("OTTO-CHUNK-NONCE"),
      ...ctr.buffer.asUint8List()
    ]);
    return _hkdfDerive(
      ikm: nonceKey,
      length: 12,
      info: info,
      salt: const <int>[],
    );
  }

  Uint8List _random(int n) {
    final rnd = Random.secure();
    final b = Uint8List(n);
    for (var i = 0; i < n; i++) {
      b[i] = rnd.nextInt(256);
    }
    return b;
  }

  // ==== Public API ====

  /// Encrypt a UTF-8 string or arbitrary bytes (pass your own bytes) and return cipher+tag plus header.
  Future<OttoEncResult> encryptString(Uint8List plaintext, OttoOptions opt) async {
    final ctx = await _initContext(opt: opt, chunked: false);
    final nonce = await _chunkNonce(ctx.nonceKey, 0);
    final (cipher, tag) = await _aesGcmEncrypt(
      key32: ctx.encKey, nonce12: nonce, aad: ctx.header, plain: plaintext
    );
    final out = Uint8List(cipher.length + tag.length)
      ..setRange(0, cipher.length, cipher)
      ..setRange(cipher.length, cipher.length + tag.length, tag);
    return OttoEncResult(out, ctx.header);
  }

  Future<Uint8List> decryptString(Uint8List cipherAndTag, Uint8List header, OttoOptions opt) async {
    if (cipherAndTag.length < 16) {
      throw StateError("cipher too short");
    }
    final ctx = await _initContextForDecrypt(header, opt);
    final cipher = cipherAndTag.sublist(0, cipherAndTag.length - 16);
    final tag = cipherAndTag.sublist(cipherAndTag.length - 16);
    final nonce = await _chunkNonce(ctx.nonceKey, 0);
    final plain = await _aesGcmDecrypt(
      key32: ctx.encKey, nonce12: nonce, aad: ctx.aad, cipher: cipher, tag: tag
    );
    return plain;
  }

  /// Stream/large-file encryption; reads input file and writes output file with header + chunked payload.
  Future<void> encryptFile(String inputPath, String outputPath, OttoOptions opt) async {
    final ctx = await _initContext(opt: opt, chunked: true);
    final out = File(outputPath)..createSync(recursive: true);
    final sink = out.openWrite();
    sink.add(ctx.header);
    final file = File(inputPath);
    final raf = await file.open();
    try {
      var counter = 0;
      while (true) {
        final chunk = await raf.read(chunkSize);
        if (chunk.isEmpty) break;
        final nonce = await _chunkNonce(ctx.nonceKey, counter);
        final (c, tag) = await _aesGcmEncrypt(
          key32: ctx.encKey, nonce12: nonce, aad: ctx.aad, plain: Uint8List.fromList(chunk)
        );
        sink.add(_be32(c.length));
        sink.add(c);
        sink.add(tag);
        counter += 1;
      }
    } finally {
      await raf.close();
      await sink.close();
    }
  }

  /// Decrypt a file produced by [encryptFile].
  Future<void> decryptFile(String inputPath, String outputPath, OttoOptions opt) async {
    final fin = await File(inputPath).open();
    try {
      // read header
      final fixed = await fin.read(11);
      if (fixed.length != 11) throw StateError("bad header");
      if (!ListEquality().equals(fixed.sublist(0,5), magic)) throw StateError("bad magic");
      if (fixed[5] != algoId) throw StateError("unsupported algo");
      final hlen = ByteData.sublistView(Uint8List.fromList(fixed.sublist(9,11))).getUint16(0, Endian.big);
      final varPart = await fin.read(hlen);
      if (varPart.length != hlen) throw StateError("truncated header");
      final header = Uint8List(11 + hlen)
        ..setRange(0, 11, fixed)
        ..setRange(11, 11 + hlen, varPart);

      final ctx = await _initContextForDecrypt(header, opt);
      final out = File(outputPath)..createSync(recursive: True);
      final sink = out.openWrite();

      var counter = 0;
      while (true) {
        final lenBytes = await fin.read(4);
        if (lenBytes.isEmpty) break;
        if (lenBytes.length < 4) throw StateError("truncated chunk length");
        final clen = _readU32(Uint8List.fromList(lenBytes), 0);
        if (clen <= 0) break;
        final cipher = await fin.read(clen);
        if (cipher.length < clen) throw StateError("truncated cipher");
        final tag = await fin.read(16);
        if (tag.length < 16) throw StateError("missing tag");
        final nonce = await _chunkNonce(ctx.nonceKey, counter);
        final plain = await _aesGcmDecrypt(
          key32: ctx.encKey, nonce12: nonce, aad: ctx.aad,
          cipher: Uint8List.fromList(cipher), tag: Uint8List.fromList(tag)
        );
        sink.add(plain);
        counter += 1;
      }
      await sink.close();
    } finally {
      await fin.close();
    }
  }

  /// X25519 helper (uses libsodium)
  OttoKeypair generateKeypair() {
    final s = _sodium ?? (throw StateError("Sodium not initialized; create(withSodium: true)"));
    final sk = s.randombytes.buf(s.crypto.scalarmult.scalarBytes);
    final pk = s.crypto.scalarmult.base(sk);
    return OttoKeypair(Uint8List.fromList(sk), Uint8List.fromList(pk));
  }

  Uint8List deriveSharedSecret(Uint8List mySecret, Uint8List theirPublic) {
    final s = _sodium ?? (throw StateError("Sodium not initialized; create(withSodium: true)"));
    final shared = s.crypto.scalarmult.scalarMult(mySecret, theirPublic);
    return Uint8List.fromList(shared);
  }

  Future<Uint8List> deriveSessionKey(Uint8List shared, Uint8List salt, String context) {
    return _hkdfDerive(
      ikm: shared, length: 32, info: utf8.encode(context), salt: salt
    );
  }

  // ==== Internals ====
  static const _encLabel = "OTTO-ENC-KEY";
  static const _nonceLabel = "OTTO-NONCE-KEY";
  static const _masterLabel = "OTTO-E2E-MASTER";

  Future<_Ctx> _initContext({required OttoOptions opt, required bool chunked}) async {
    final fileSalt = _random(16);
    final header = BytesBuilder();
    header.add(magic);
    header.add([algoId]);

    int kdfId;
    final headerExtra = BytesBuilder();
    late Uint8List master;

    if ((opt.password ?? '').isNotEmpty) {
      if (_sodium == null) {
        throw StateError("Password mode requires libsodium. Create with withSodium: true.");
      }
      kdfId = kdfPassword;
      final pwSalt = _random(16);
      final ops = opt.opslimit ?? _sodium!.crypto.pwhash.opsLimitModerate;
      final mem = opt.memlimit ?? _sodium!.crypto.pwhash.memLimitModerate;
      final out = _sodium!.crypto.pwhash.call(
        outLen: 32,
        password: utf8.encode(opt.password!),
        salt: pwSalt,
        opslimit: ops,
        memlimit: mem,
        alg: CryptoPwhashAlgorithm.argon2id13,
      );
      master = Uint8List.fromList(out);
      headerExtra.add(pwSalt);
      headerExtra.add(_be32(ops));
      headerExtra.add(_be32(mem ~/ 1024));
      header.add([kdfId]);
    } else if ((opt.rawKey ?? '').isNotEmpty) {
      kdfId = kdfRawKey;
      master = _decodeKey(opt.rawKey);
      if (master.length != 32) {
        throw ArgumentError("rawKey must be 32 bytes");
      }
      header.add([kdfId]);
    } else if ((opt.recipientPublic ?? '').isNotEmpty) {
      if (_sodium == null) {
        throw StateError("X25519 mode requires libsodium. Create with withSodium: true.");
      }
      kdfId = kdfX25519;
      final rcpt = _decodeKey(opt.recipientPublic);
      if (rcpt.length != _sodium!.crypto.scalarmult.bytes) {
        throw ArgumentError("recipientPublic length");
      }
      final ephSk = _sodium!.randombytes.buf(_sodium!.crypto.scalarmult.scalarBytes);
      final ephPk = _sodium!.crypto.scalarmult.base(ephSk);
      final shared = _sodium!.crypto.scalarmult.scalarMult(ephSk, rcpt);
      master = await _hkdfDerive(
        ikm: shared, length: 32, info: utf8.encode(_masterLabel), salt: fileSalt
      );
      headerExtra.add(ephPk);
      header.add([kdfId]);
    } else {
      throw ArgumentError("Provide one of: password, rawKey, recipientPublic");
    }

    header.add([chunked ? flagChunked : 0x00]);
    header.add([0x00]); // reserved

    final varPart = BytesBuilder();
    varPart.add(fileSalt);
    varPart.add(headerExtra.toBytes());

    final vp = varPart.toBytes();
    header.add(_be16(vp.length));
    header.add(vp);
    final headerBytes = header.toBytes();

    final encKey = await _hkdfDerive(
      ikm: master, length: 32, info: utf8.encode(_encLabel), salt: fileSalt
    );
    final nonceKey = await _hkdfDerive(
      ikm: master, length: 32, info: utf8.encode(_nonceLabel), salt: fileSalt
    );

    return _Ctx(headerBytes, headerBytes, encKey, nonceKey, master);
  }

  Future<_Ctx> _initContextForDecrypt(Uint8List header, OttoOptions opt) async {
    if (header.length < 11) throw StateError("header too short");
    if (!ListEquality().equals(header.sublist(0,5), magic)) throw StateError("bad magic");
    if (header[5] != algoId) throw StateError("unsupported algo");
    final kdfId = header[6];
    final hlen = ByteData.sublistView(header, 9, 11).getUint16(0, Endian.big);
    final varPart = header.sublist(11, 11 + hlen);
    var off = 0;
    final fileSalt = varPart.sublist(off, off+16); off += 16;
    late Uint8List master;

    if (kdfId == kdfPassword) {
      if (_sodium == null) {
        throw StateError("Password mode requires libsodium. Create with withSodium: true.");
      }
      final pwSalt = varPart.sublist(off, off+16); off += 16;
      final ops = _readU32(varPart, off); off += 4;
      final memKiB = _readU32(varPart, off); off += 4;
      final mem = memKiB * 1024;
      if ((opt.password ?? '').isEmpty) throw ArgumentError("Password required");
      final out = _sodium!.crypto.pwhash.call(
        outLen: 32,
        password: utf8.encode(opt.password!),
        salt: pwSalt,
        opslimit: ops,
        memlimit: mem,
        alg: CryptoPwhashAlgorithm.argon2id13,
      );
      master = Uint8List.fromList(out);
    } else if (kdfId == kdfRawKey) {
      final rk = _decodeKey(opt.rawKey);
      if (rk.length != 32) throw ArgumentError("rawKey (32 bytes) required");
      master = rk;
    } else if (kdfId == kdfX25519) {
      if (_sodium == null) {
        throw StateError("X25519 mode requires libsodium. Create with withSodium: true.");
      }
      final ephPk = varPart.sublist(off, off + _sodium!.crypto.scalarmult.bytes); off += _sodium!.crypto.scalarmult.bytes;
      final sk = _decodeKey(opt.senderSecret);
      if (sk.length != _sodium!.crypto.scalarmult.scalarBytes) throw ArgumentError("senderSecret length");
      final shared = _sodium!.crypto.scalarmult.scalarMult(sk, ephPk);
      master = await _hkdfDerive(
        ikm: shared, length: 32, info: utf8.encode(_masterLabel), salt: fileSalt
      );
    } else {
      throw StateError("Unknown KDF");
    }

    final encKey = await _hkdfDerive(
      ikm: master, length: 32, info: utf8.encode(_encLabel), salt: fileSalt
    );
    final nonceKey = await _hkdfDerive(
      ikm: master, length: 32, info: utf8.encode(_nonceLabel), salt: fileSalt
    );
    final fullHeader = header.sublist(0, 11 + hlen);
    return _Ctx(fullHeader, fullHeader, encKey, nonceKey, master);
  }
}

class _Ctx {
  final Uint8List header;
  final Uint8List aad;
  final Uint8List encKey;
  final Uint8List nonceKey;
  final Uint8List master;
  _Ctx(this.header, this.aad, this.encKey, this.nonceKey, this.master);
}

// Simple List equality (avoid importing collection just for this).
class ListEquality {
  const ListEquality();
  bool equals(List<int> a, List<int> b) {
    if (a.length != b.length) return False;
    for (var i=0;i<a.length;i++) { if (a[i] != b[i]) return False; }
    return True;
  }
}
