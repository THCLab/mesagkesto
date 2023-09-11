import 'dart:ffi';
import 'dart:io';

import 'bridge_generated.dart';

class Mesagkesto {
  static const base = 'bindings';
  static final path = Platform.isWindows ? '$base.dll' : 'lib$base.so';
  static final dylib = Platform.isIOS
      ? DynamicLibrary.process()
      : Platform.isMacOS
          ? DynamicLibrary.executable()
          : DynamicLibrary.open(path);
  static final api = BindingsImpl(dylib);

  Future<String> registerToken(
      {required String id, required String token, dynamic hint}) async {
    return await api.registerToken(id: id, token: token);
  }

  Future<String> forwardMessage(
      {required String receiverId, required String data, dynamic hint}) async {
    return await api.forwardMessage(receiverId: receiverId, data: data);
  }

  Future<String> queryBySn(
      {required String receiverId, required int sn, dynamic hint}) async {
    return await api.queryBySn(receiverId: receiverId, sn: sn);
  }

  Future<String> queryByDigest(
      {required String receiverId,
      required List<String> digests,
      dynamic hint}) async {
    return await api.queryByDigest(receiverId: receiverId, digests: digests);
  }
}
