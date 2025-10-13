import 'dart:convert';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:otto_crypt/otto_crypt.dart';

void main() {
  test('password roundtrip', () async {
    final otto = await OttoCrypt.create(withSodium: true);
    final opt = OttoOptions(password: 'P@ssw0rd!');
    final enc = await otto.encryptString(Uint8List.fromList(utf8.encode('hello')), opt);
    final dec = await otto.decryptString(enc.cipherAndTag, enc.header, opt);
    expect(utf8.decode(dec), 'hello');
  });
}
