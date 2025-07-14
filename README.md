# Custom Dart JWT Library
This is a personal Dart library for creating, verifying, and decoding JSON Web Tokens (JWT) using RSA encryption (RS256).

can be installed through [pub.dev](https://pub.dev/packages/easy_dart_jwt/install)

## Overview
The JWT class in this library supports:

- Creating JWT tokens from payload data signed with an RSA private key

- Decoding JWT payloads

- Verifying JWT signatures using an RSA public key

- Validating tokens with signature and expiration checks

- Keys can be provided as PEM strings or as file paths.

## Usage
```dart
Copy
Edit
final privateKey = '-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----';
final publicKey = '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----';

final jwt = JWT(privateKey, publicKey);

final payload = {
  'sub': '1234567890',
  'name': 'John Doe',
  'iat': DateTime.now().millisecondsSinceEpoch ~/ 1000,
  'exp': DateTime.now().add(Duration(hours: 1)).millisecondsSinceEpoch ~/ 1000,
};

final token = jwt.createToken(payload);
print('Token: $token');

final decoded = jwt.decodePayload(token);
print('Payload: $decoded');

final isVerified = jwt.verifyToken(token);
print('Verified: $isVerified');

final isValid = jwt.isValid(token);
print('Valid: $isValid');
```
## Notes
- RSA keys must be in PEM format.

- The expiration claim (exp) should be a UNIX timestamp.

- This is a custom implementation designed for your personal use.
