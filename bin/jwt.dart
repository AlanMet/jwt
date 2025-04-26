import 'package:easy_dart_jwt/easy_dart_jwt.dart';

/// Generates a JWT for the given payload, prints the token,
/// decoded payload, and verification result.
void handleValidToken(JWT jwt) {
  final validPayload = {
    'sub': '1234567890',
    'name': 'John Doe',
    'iat': DateTime.now().millisecondsSinceEpoch ~/ 1000,
    'exp':
        DateTime.now().add(Duration(hours: 1)).millisecondsSinceEpoch ~/ 1000,
  };

  // Create token
  final token = jwt.createToken(validPayload);
  print('Valid Token: $token');

  // Decode and print payload
  final decoded = jwt.decodePayload(token);
  print('Decoded Payload: $decoded');

  // Verify token
  final isVerified = jwt.verifyToken(token);
  print('Token verified: $isVerified');
}

/// Generates an expired JWT, prints the token and its validity.
void handleExpiredToken(JWT jwt) {
  final expiredPayload = {
    'sub': '1234567890',
    'name': 'John Doe',
    'iat':
        DateTime.now().subtract(Duration(hours: 2)).millisecondsSinceEpoch ~/
        1000,
    'exp':
        DateTime.now().subtract(Duration(hours: 1)).millisecondsSinceEpoch ~/
        1000,
  };

  // Create expired token
  final expiredToken = jwt.createToken(expiredPayload);
  print('Expired Token: $expiredToken');

  // Check validity
  final isStillValid = jwt.isValid(expiredToken);
  print('Expired token is valid: $isStillValid');
}

void main() {
  // Initialize JWT with your key pair
  final jwt = JWT('private_key.pem', 'public_key.pem');

  // Handle a valid token scenario
  handleValidToken(jwt);

  // Handle an expired token scenario
  handleExpiredToken(jwt);
}
