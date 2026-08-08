/// The shared cross-language capture vectors, read from this package.
///
/// A vector is one capture envelope with the byte length of its deterministic
/// CBOR encoding and the sha256 of those bytes. The Rust encoder in this same
/// crate is pinned to the very same files, so the Dart and Rust sides are held
/// against one artefact rather than against each other's copied literals.
///
/// See `vectors/README.md` beside this file for the rule that makes them worth
/// having: a vector is never regenerated from an implementation it checks.
library;

import 'dart:convert';
import 'dart:io';

/// Every vector's name.
///
/// A consumer loops over this rather than naming vectors one at a time. A
/// vector added to the directory but reaching nobody's assertions would look
/// like coverage and be none; iterating makes that impossible to do quietly.
const vectorNames = <String>[
  'base',
  'documented',
  'boundary',
  'frame-bound',
  'depth-bound',
];

Directory? _root;

/// This package's own directory, read from the `package_config.json` that pub
/// writes for the consumer.
///
/// Not `Isolate.resolvePackageUri`, which `flutter test` does not implement, and
/// not a `../` relative path — a relative path is what put these files out of
/// reach the moment the tree was split across repositories, which is the whole
/// reason they are reached through a dependency now. The config is the one place
/// that knows where a package actually landed, whether that is a sibling
/// directory or a checkout of a pinned git ref.
Directory _packageRoot() {
  for (var dir = Directory.current; ; dir = dir.parent) {
    final config = File('${dir.path}/.dart_tool/package_config.json');
    if (config.existsSync()) {
      final packages = (jsonDecode(config.readAsStringSync())
          as Map<String, Object?>)['packages'] as List;
      for (final p in packages.cast<Map<String, Object?>>()) {
        if (p['name'] == 'vaulet_core') {
          return Directory.fromUri(config.uri.resolve(p['rootUri'] as String));
        }
      }
      throw StateError('vaulet_core is not a dependency of this package');
    }
    if (dir.path == dir.parent.path) {
      throw StateError('no .dart_tool/package_config.json above the working '
          'directory — run `flutter pub get` first');
    }
  }
}

/// One vector: its `envelope`, the `cbor_len` of the canonical encoding, and
/// the `sha256` of those bytes.
Map<String, Object?> vector(String name) {
  _root ??= _packageRoot();
  final f = File('${_root!.path}/vectors/belt/$name.json');
  if (!f.existsSync()) {
    throw ArgumentError('no shared vector named $name');
  }
  return jsonDecode(f.readAsStringSync()) as Map<String, Object?>;
}
