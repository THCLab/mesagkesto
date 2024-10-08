// AUTO GENERATED FILE, DO NOT EDIT.
// Generated by `flutter_rust_bridge`@ 1.82.1.
// ignore_for_file: non_constant_identifier_names, unused_element, duplicate_ignore, directives_ordering, curly_braces_in_flow_control_structures, unnecessary_lambdas, slash_for_doc_comments, prefer_const_literals_to_create_immutables, implicit_dynamic_list_literal, duplicate_import, unused_import, unnecessary_import, prefer_single_quotes, prefer_const_constructors, use_super_parameters, always_use_package_imports, annotate_overrides, invalid_use_of_protected_member, constant_identifier_names, invalid_use_of_internal_member, prefer_is_empty, unnecessary_const

import 'dart:convert';
import 'dart:async';
import 'package:meta/meta.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge.dart';
import 'package:uuid/uuid.dart';

import 'dart:ffi' as ffi;

abstract class Bindings {
  Future<String> registerToken(
      {required String id, required String token, dynamic hint});

  FlutterRustBridgeTaskConstMeta get kRegisterTokenConstMeta;

  Future<String> forwardMessage(
      {required String receiverId, required String data, dynamic hint});

  FlutterRustBridgeTaskConstMeta get kForwardMessageConstMeta;

  Future<String> queryBySn(
      {required String receiverId, required int sn, dynamic hint});

  FlutterRustBridgeTaskConstMeta get kQueryBySnConstMeta;

  Future<String> queryByDigest(
      {required String receiverId,
      required List<String> digests,
      dynamic hint});

  FlutterRustBridgeTaskConstMeta get kQueryByDigestConstMeta;
}

class BindingsImpl implements Bindings {
  final BindingsPlatform _platform;
  factory BindingsImpl(ExternalLibrary dylib) =>
      BindingsImpl.raw(BindingsPlatform(dylib));

  /// Only valid on web/WASM platforms.
  factory BindingsImpl.wasm(FutureOr<WasmModule> module) =>
      BindingsImpl(module as ExternalLibrary);
  BindingsImpl.raw(this._platform);
  Future<String> registerToken(
      {required String id, required String token, dynamic hint}) {
    var arg0 = _platform.api2wire_String(id);
    var arg1 = _platform.api2wire_String(token);
    return _platform.executeNormal(FlutterRustBridgeTask(
      callFfi: (port_) =>
          _platform.inner.wire_register_token(port_, arg0, arg1),
      parseSuccessData: _wire2api_String,
      parseErrorData: null,
      constMeta: kRegisterTokenConstMeta,
      argValues: [id, token],
      hint: hint,
    ));
  }

  FlutterRustBridgeTaskConstMeta get kRegisterTokenConstMeta =>
      const FlutterRustBridgeTaskConstMeta(
        debugName: "register_token",
        argNames: ["id", "token"],
      );

  Future<String> forwardMessage(
      {required String receiverId, required String data, dynamic hint}) {
    var arg0 = _platform.api2wire_String(receiverId);
    var arg1 = _platform.api2wire_String(data);
    return _platform.executeNormal(FlutterRustBridgeTask(
      callFfi: (port_) =>
          _platform.inner.wire_forward_message(port_, arg0, arg1),
      parseSuccessData: _wire2api_String,
      parseErrorData: null,
      constMeta: kForwardMessageConstMeta,
      argValues: [receiverId, data],
      hint: hint,
    ));
  }

  FlutterRustBridgeTaskConstMeta get kForwardMessageConstMeta =>
      const FlutterRustBridgeTaskConstMeta(
        debugName: "forward_message",
        argNames: ["receiverId", "data"],
      );

  Future<String> queryBySn(
      {required String receiverId, required int sn, dynamic hint}) {
    var arg0 = _platform.api2wire_String(receiverId);
    var arg1 = api2wire_usize(sn);
    return _platform.executeNormal(FlutterRustBridgeTask(
      callFfi: (port_) => _platform.inner.wire_query_by_sn(port_, arg0, arg1),
      parseSuccessData: _wire2api_String,
      parseErrorData: null,
      constMeta: kQueryBySnConstMeta,
      argValues: [receiverId, sn],
      hint: hint,
    ));
  }

  FlutterRustBridgeTaskConstMeta get kQueryBySnConstMeta =>
      const FlutterRustBridgeTaskConstMeta(
        debugName: "query_by_sn",
        argNames: ["receiverId", "sn"],
      );

  Future<String> queryByDigest(
      {required String receiverId,
      required List<String> digests,
      dynamic hint}) {
    var arg0 = _platform.api2wire_String(receiverId);
    var arg1 = _platform.api2wire_StringList(digests);
    return _platform.executeNormal(FlutterRustBridgeTask(
      callFfi: (port_) =>
          _platform.inner.wire_query_by_digest(port_, arg0, arg1),
      parseSuccessData: _wire2api_String,
      parseErrorData: null,
      constMeta: kQueryByDigestConstMeta,
      argValues: [receiverId, digests],
      hint: hint,
    ));
  }

  FlutterRustBridgeTaskConstMeta get kQueryByDigestConstMeta =>
      const FlutterRustBridgeTaskConstMeta(
        debugName: "query_by_digest",
        argNames: ["receiverId", "digests"],
      );

  void dispose() {
    _platform.dispose();
  }
// Section: wire2api

  String _wire2api_String(dynamic raw) {
    return raw as String;
  }

  int _wire2api_u8(dynamic raw) {
    return raw as int;
  }

  Uint8List _wire2api_uint_8_list(dynamic raw) {
    return raw as Uint8List;
  }
}

// Section: api2wire

@protected
int api2wire_u8(int raw) {
  return raw;
}

@protected
int api2wire_usize(int raw) {
  return raw;
}
// Section: finalizer

class BindingsPlatform extends FlutterRustBridgeBase<BindingsWire> {
  BindingsPlatform(ffi.DynamicLibrary dylib) : super(BindingsWire(dylib));

// Section: api2wire

  @protected
  ffi.Pointer<wire_uint_8_list> api2wire_String(String raw) {
    return api2wire_uint_8_list(utf8.encoder.convert(raw));
  }

  @protected
  ffi.Pointer<wire_StringList> api2wire_StringList(List<String> raw) {
    final ans = inner.new_StringList_0(raw.length);
    for (var i = 0; i < raw.length; i++) {
      ans.ref.ptr[i] = api2wire_String(raw[i]);
    }
    return ans;
  }

  @protected
  ffi.Pointer<wire_uint_8_list> api2wire_uint_8_list(Uint8List raw) {
    final ans = inner.new_uint_8_list_0(raw.length);
    ans.ref.ptr.asTypedList(raw.length).setAll(0, raw);
    return ans;
  }

// Section: finalizer

// Section: api_fill_to_wire
}

// ignore_for_file: camel_case_types, non_constant_identifier_names, avoid_positional_boolean_parameters, annotate_overrides, constant_identifier_names

// AUTO GENERATED FILE, DO NOT EDIT.
//
// Generated by `package:ffigen`.
// ignore_for_file: type=lint

/// generated by flutter_rust_bridge
class BindingsWire implements FlutterRustBridgeWireBase {
  @internal
  late final dartApi = DartApiDl(init_frb_dart_api_dl);

  /// Holds the symbol lookup function.
  final ffi.Pointer<T> Function<T extends ffi.NativeType>(String symbolName)
      _lookup;

  /// The symbols are looked up in [dynamicLibrary].
  BindingsWire(ffi.DynamicLibrary dynamicLibrary)
      : _lookup = dynamicLibrary.lookup;

  /// The symbols are looked up with [lookup].
  BindingsWire.fromLookup(
      ffi.Pointer<T> Function<T extends ffi.NativeType>(String symbolName)
          lookup)
      : _lookup = lookup;

  void store_dart_post_cobject(
    DartPostCObjectFnType ptr,
  ) {
    return _store_dart_post_cobject(
      ptr,
    );
  }

  late final _store_dart_post_cobjectPtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(DartPostCObjectFnType)>>(
          'store_dart_post_cobject');
  late final _store_dart_post_cobject = _store_dart_post_cobjectPtr
      .asFunction<void Function(DartPostCObjectFnType)>();

  Object get_dart_object(
    int ptr,
  ) {
    return _get_dart_object(
      ptr,
    );
  }

  late final _get_dart_objectPtr =
      _lookup<ffi.NativeFunction<ffi.Handle Function(ffi.UintPtr)>>(
          'get_dart_object');
  late final _get_dart_object =
      _get_dart_objectPtr.asFunction<Object Function(int)>();

  void drop_dart_object(
    int ptr,
  ) {
    return _drop_dart_object(
      ptr,
    );
  }

  late final _drop_dart_objectPtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.UintPtr)>>(
          'drop_dart_object');
  late final _drop_dart_object =
      _drop_dart_objectPtr.asFunction<void Function(int)>();

  int new_dart_opaque(
    Object handle,
  ) {
    return _new_dart_opaque(
      handle,
    );
  }

  late final _new_dart_opaquePtr =
      _lookup<ffi.NativeFunction<ffi.UintPtr Function(ffi.Handle)>>(
          'new_dart_opaque');
  late final _new_dart_opaque =
      _new_dart_opaquePtr.asFunction<int Function(Object)>();

  int init_frb_dart_api_dl(
    ffi.Pointer<ffi.Void> obj,
  ) {
    return _init_frb_dart_api_dl(
      obj,
    );
  }

  late final _init_frb_dart_api_dlPtr =
      _lookup<ffi.NativeFunction<ffi.IntPtr Function(ffi.Pointer<ffi.Void>)>>(
          'init_frb_dart_api_dl');
  late final _init_frb_dart_api_dl = _init_frb_dart_api_dlPtr
      .asFunction<int Function(ffi.Pointer<ffi.Void>)>();

  void wire_register_token(
    int port_,
    ffi.Pointer<wire_uint_8_list> id,
    ffi.Pointer<wire_uint_8_list> token,
  ) {
    return _wire_register_token(
      port_,
      id,
      token,
    );
  }

  late final _wire_register_tokenPtr = _lookup<
      ffi.NativeFunction<
          ffi.Void Function(ffi.Int64, ffi.Pointer<wire_uint_8_list>,
              ffi.Pointer<wire_uint_8_list>)>>('wire_register_token');
  late final _wire_register_token = _wire_register_tokenPtr.asFunction<
      void Function(
          int, ffi.Pointer<wire_uint_8_list>, ffi.Pointer<wire_uint_8_list>)>();

  void wire_forward_message(
    int port_,
    ffi.Pointer<wire_uint_8_list> receiver_id,
    ffi.Pointer<wire_uint_8_list> data,
  ) {
    return _wire_forward_message(
      port_,
      receiver_id,
      data,
    );
  }

  late final _wire_forward_messagePtr = _lookup<
      ffi.NativeFunction<
          ffi.Void Function(ffi.Int64, ffi.Pointer<wire_uint_8_list>,
              ffi.Pointer<wire_uint_8_list>)>>('wire_forward_message');
  late final _wire_forward_message = _wire_forward_messagePtr.asFunction<
      void Function(
          int, ffi.Pointer<wire_uint_8_list>, ffi.Pointer<wire_uint_8_list>)>();

  void wire_query_by_sn(
    int port_,
    ffi.Pointer<wire_uint_8_list> receiver_id,
    int sn,
  ) {
    return _wire_query_by_sn(
      port_,
      receiver_id,
      sn,
    );
  }

  late final _wire_query_by_snPtr = _lookup<
      ffi.NativeFunction<
          ffi.Void Function(ffi.Int64, ffi.Pointer<wire_uint_8_list>,
              ffi.UintPtr)>>('wire_query_by_sn');
  late final _wire_query_by_sn = _wire_query_by_snPtr
      .asFunction<void Function(int, ffi.Pointer<wire_uint_8_list>, int)>();

  void wire_query_by_digest(
    int port_,
    ffi.Pointer<wire_uint_8_list> receiver_id,
    ffi.Pointer<wire_StringList> digests,
  ) {
    return _wire_query_by_digest(
      port_,
      receiver_id,
      digests,
    );
  }

  late final _wire_query_by_digestPtr = _lookup<
      ffi.NativeFunction<
          ffi.Void Function(ffi.Int64, ffi.Pointer<wire_uint_8_list>,
              ffi.Pointer<wire_StringList>)>>('wire_query_by_digest');
  late final _wire_query_by_digest = _wire_query_by_digestPtr.asFunction<
      void Function(
          int, ffi.Pointer<wire_uint_8_list>, ffi.Pointer<wire_StringList>)>();

  ffi.Pointer<wire_StringList> new_StringList_0(
    int len,
  ) {
    return _new_StringList_0(
      len,
    );
  }

  late final _new_StringList_0Ptr = _lookup<
          ffi.NativeFunction<ffi.Pointer<wire_StringList> Function(ffi.Int32)>>(
      'new_StringList_0');
  late final _new_StringList_0 = _new_StringList_0Ptr
      .asFunction<ffi.Pointer<wire_StringList> Function(int)>();

  ffi.Pointer<wire_uint_8_list> new_uint_8_list_0(
    int len,
  ) {
    return _new_uint_8_list_0(
      len,
    );
  }

  late final _new_uint_8_list_0Ptr = _lookup<
          ffi
          .NativeFunction<ffi.Pointer<wire_uint_8_list> Function(ffi.Int32)>>(
      'new_uint_8_list_0');
  late final _new_uint_8_list_0 = _new_uint_8_list_0Ptr
      .asFunction<ffi.Pointer<wire_uint_8_list> Function(int)>();

  void free_WireSyncReturn(
    WireSyncReturn ptr,
  ) {
    return _free_WireSyncReturn(
      ptr,
    );
  }

  late final _free_WireSyncReturnPtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(WireSyncReturn)>>(
          'free_WireSyncReturn');
  late final _free_WireSyncReturn =
      _free_WireSyncReturnPtr.asFunction<void Function(WireSyncReturn)>();
}

final class _Dart_Handle extends ffi.Opaque {}

final class wire_uint_8_list extends ffi.Struct {
  external ffi.Pointer<ffi.Uint8> ptr;

  @ffi.Int32()
  external int len;
}

final class wire_StringList extends ffi.Struct {
  external ffi.Pointer<ffi.Pointer<wire_uint_8_list>> ptr;

  @ffi.Int32()
  external int len;
}

typedef DartPostCObjectFnType = ffi.Pointer<
    ffi.NativeFunction<
        ffi.Bool Function(DartPort port_id, ffi.Pointer<ffi.Void> message)>>;
typedef DartPort = ffi.Int64;
