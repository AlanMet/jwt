import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:pointycastle/export.dart';
import 'package:basic_utils/basic_utils.dart';

/// A class to handle JSON Web Token (JWT) creation, verification, and payload decoding using RSA encryption.
///
/// The `JWT` class provides methods to:
/// - Create a JWT token with a given payload and private key.
/// - Decode a JWT token's payload.
/// - Verify the signature of a JWT token using the public key.
///
/// Example usage:
/// ```dart
/// final privateKey = 'your-private-key';
/// final publicKey = 'your-public-key';
/// final jwt = JWT(privateKey, publicKey);
///
/// final payload = {
///   'sub': '1234567890',
///   'name': 'John Doe',
///   'iat': DateTime.now().millisecondsSinceEpoch ~/ 1000,
///   'exp': DateTime.now().add(Duration(hours: 1)).millisecondsSinceEpoch ~/ 1000,
/// };
///
/// final token = jwt.createToken(payload);
/// print('JWT Token: $token');
///
/// final decodedPayload = jwt.decodePayload(token);
/// print('Decoded Payload: $decodedPayload');
///
/// final isVerified = jwt.verifyToken(token);
/// print('Token Verified: $isVerified');
/// ```
class JWT {
  late PrivateKey _privateKey;
  late PublicKey _publicKey;

  /// Creates an instance of the JWT class.
  ///
  /// Loads the private and public keys (either from file or raw PEM string).
  /// Throws an exception if the keys are invalid or cannot be loaded.
  JWT(String privateKey, String publicKey) {
    try {
      _privateKey = _loadPrivateKey(privateKey);
      _publicKey = _loadPublicKey(publicKey);
    } catch (e) {
      throw Exception('Failed to load keys: $e');
    }
  }

  /// Creates a JWT token with the given payload.
  ///
  /// Takes a [Map] as the payload, encodes the header and payload, and signs the token
  /// using the private key. Returns the complete JWT token as a string.
  ///
  /// Throws an exception if the token cannot be created.
  String createToken(Map<String, dynamic> payload) {
    try {
      final header = _getHeader();
      final encodedHeader = base64Encode(utf8.encode(jsonEncode(header)));
      final encodedPayload = base64Encode(utf8.encode(jsonEncode(payload)));

      final data = '$encodedHeader.$encodedPayload';

      final signature = _signToken(data, _privateKey);

      return '$data.$signature';
    } catch (e) {
      throw Exception('Failed to create token: $e');
    }
  }

  /// Decodes the payload of the given JWT token.
  ///
  /// Splits the token into its parts, decodes the payload, and returns it as a
  /// [Map] of the decoded JSON data. Throws an exception if the token is invalid
  /// or cannot be decoded.
  Map<String, dynamic> decodePayload(String token) {
    try {
      final parts = token.split('.');
      if (parts.length != 3) {
        throw FormatException('Invalid token format');
      }

      final payload = parts[1];
      final decodedPayload = utf8.decode(base64Url.decode(payload));
      return jsonDecode(decodedPayload);
    } catch (e) {
      throw Exception('Failed to decode payload: $e');
    }
  }

  /// Verifies the given JWT token.
  ///
  /// Takes a [String] token, splits it into its components, hashes the data,
  /// and verifies the signature using the public key. Returns `true` if the
  /// token is valid, `false` otherwise.
  ///
  /// Throws an exception if the token format is invalid or the signature cannot
  /// be verified.
  bool verifyToken(String token) {
    try {
      final parts = token.split('.');
      if (parts.length != 3 || token.isEmpty) {
        throw FormatException('Invalid token format');
      }

      final header = parts[0];
      final payload = parts[1];

      late Uint8List signature;
      try {
        signature = base64Url.decode(parts[2]);
      } catch (e) {
        throw FormatException('Invalid base64 encoding for the signature');
      }

      final data = '$header.$payload';

      final hashedData = SHA256Digest().process(
        Uint8List.fromList(utf8.encode(data)),
      );

      final signer = RSASigner(SHA256Digest(), '0609608648016503040201');
      signer.init(false, PublicKeyParameter<RSAPublicKey>(_publicKey));

      final verified = signer.verifySignature(
        hashedData,
        RSASignature(signature),
      );

      return verified;
    } catch (e) {
      print('Error verifying token: $e');
      return false;
    }
  }

  Map<String, dynamic> _getHeader() {
    return {"alg": "RS256", "typ": "JWT"};
  }

  _signToken(String data, PrivateKey privateKey) {
    try {
      final digest = SHA256Digest();
      final bytes = utf8.encode(data);
      final hashedData = digest.process(Uint8List.fromList(bytes));

      final signer = RSASigner(digest, '0609608648016503040201');
      signer.init(true, PrivateKeyParameter<RSAPrivateKey>(privateKey));
      final signature = signer.generateSignature(hashedData);

      return base64Url.encode(signature.bytes);
    } catch (e) {
      throw Exception('Failed to sign token: $e');
    }
  }

  RSAPrivateKey _loadPrivateKey(String input) {
    try {
      if (_isPath(input)) {
        input = _getKeyFromPath(input);
      }
      return CryptoUtils.rsaPrivateKeyFromPem(input);
    } catch (e) {
      throw Exception('Failed to load private key: $e');
    }
  }

  RSAPublicKey _loadPublicKey(String input) {
    try {
      if (_isPath(input)) {
        input = _getKeyFromPath(input);
      }
      return CryptoUtils.rsaPublicKeyFromPem(input);
    } catch (e) {
      throw Exception('Failed to load public key: $e');
    }
  }

  bool _isPath(String path) {
    final file = File(path);
    return file.existsSync();
  }

  String _getKeyFromPath(String path) {
    try {
      final file = File(path);
      if (!file.existsSync()) {
        throw FileSystemException('File not found', path);
      }
      return file.readAsStringSync();
    } catch (e) {
      throw Exception('Failed to read key file: $e');
    }
  }
}
