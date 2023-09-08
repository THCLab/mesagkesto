# Messagebox bindings

## Generating dart code

Pregenerated files can be found in `lib` folder.

To generate them, create and configure flutter project with:

- `flutter create messagebox_bindings`
- `cd messagebox_bindings` 
- `flutter pub add ffi` 
- `flutter pub add dev:ffigen:8.0.0`
- `flutter pub get`

Then run:
- `flutter_rust_bridge_codegen --rust-input ../src/api.rs --dart-output ../lib/bridge_generated.dart --c-output ../lib/bridge_generated.h`

## Build for android

- `export ANDROID_NDK_HOME="$HOME/path/to/ndk"`
- `cargo ndk -o ./jniLibs build`