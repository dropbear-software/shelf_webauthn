import 'dart:io';

void main() {
  final file = File('spec/webauthn_spec.html');
  final html = file.readAsStringSync();

  final sectionRegex = RegExp(
    r'<h3[^>]*id="(sctn-test-vectors-[^"]+)"[^>]*>.*?</h3>(.*?)(?=<h3|$)',
    dotAll: true,
  );
  final preRegex = RegExp(r'<pre[^>]*>(.*?)</pre>', dotAll: true);
  final varRegex = RegExp(
    r'<c- nc>([^<]+)</c->\s*<c- o>=</c->\s*h<c- t>'
    "'"
    '([^'
    "'"
    ']+)'
    "'"
    '</c->',
  );

  final out = StringBuffer();
  out.writeln('// GENERATED CODE - DO NOT MODIFY BY HAND');
  out.writeln('// Extracted from WebAuthn Spec Section 16');
  out.writeln();
  out.writeln('class WebAuthnTestVector {');
  out.writeln('  final String name;');
  out.writeln('  final Map<String, String> registration;');
  out.writeln('  final Map<String, String> authentication;');
  out.writeln(
    '  const WebAuthnTestVector({required this.name, required this.registration, required this.authentication});',
  );
  out.writeln('}');
  out.writeln();
  out.writeln('const testVectors = <WebAuthnTestVector>[');

  final matches = sectionRegex.allMatches(html);
  for (final match in matches) {
    final id = match.group(1)!;
    final content = match.group(2)!;

    // There are usually two <pre> blocks: one for Registration, one for Authentication
    // Sometimes only one if it's the root cert.
    if (id == 'sctn-test-vectors-attestation-root-cert') continue;
    if (id == 'sctn-test-vectors-extensions') continue;
    if (id.startsWith('sctn-test-vectors-extensions-')) continue;

    final pres = preRegex.allMatches(content).toList();
    if (pres.isEmpty) continue;

    Map<String, String> reg = {};
    Map<String, String> auth = {};

    void parseBlock(String block, Map<String, String> map) {
      for (final vMatch in varRegex.allMatches(block)) {
        map[vMatch.group(1)!] = vMatch.group(2)!;
      }
    }

    if (pres.isNotEmpty) parseBlock(pres[0].group(1)!, reg);
    if (pres.length >= 2) parseBlock(pres[1].group(1)!, auth);

    String mapToCode(Map<String, String> m) {
      if (m.isEmpty) return '{}';
      var s = '{\n';
      m.forEach((k, v) {
        s += "    '$k': '$v',\n";
      });
      s += '  }';
      return s;
    }

    out.writeln('  WebAuthnTestVector(');
    out.writeln("    name: '$id',");
    out.writeln('    registration: ${mapToCode(reg)},');
    out.writeln('    authentication: ${mapToCode(auth)},');
    out.writeln('  ),');
  }

  out.writeln('];');

  File('test/vectors.dart').writeAsStringSync(out.toString());
  print('Extracted vectors to test/vectors.dart');
}
