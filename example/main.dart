import 'dart:convert';
import 'dart:typed_data';
import 'package:otto_crypt/otto_crypt.dart';

Future<void> main() async {
  final otto = await OttoCrypt.create(withSodium: true);

  // Strings (password mode)
  final opt = OttoOptions(password: 'P@ssw0rd!');
  final enc = await otto.encryptString(Uint8List.fromList(utf8.encode('Hello OTTO')), opt);
  final dec = await otto.decryptString(enc.cipherAndTag, enc.header, opt);
  print(utf8.decode(dec));

  // Keypair + E2E
  final kp = otto.generateKeypair();
  final encOpt = OttoOptions(recipientPublic: base64.encode(kp.publicKey));
  final decOpt = OttoOptions(senderSecret: base64.encode(kp.secret));
  final enc2 = await otto.encryptString(Uint8List.fromList(utf8.encode('Hi')), encOpt);
  final dec2 = await otto.decryptString(enc2.cipherAndTag, enc2.header, decOpt);
  print(utf8.decode(dec2));
}
