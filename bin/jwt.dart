import 'package:easy_dart_jwt/easy_dart_jwt.dart';

void main() {
  JWT jwt = JWT('private_key.pem', 'public_key.pem');

  Map<String, dynamic> payload = {
    'sub': '1234567890', // Subject, typically a user ID or unique identifier
    'name': 'John Doe', // User's name
    'iat':
        DateTime.now().millisecondsSinceEpoch ~/
        1000, // Issued at time (in seconds)
    'exp':
        DateTime.now()
            .add(Duration(hours: 1)) // Expiration time (1 hour from now)
            .millisecondsSinceEpoch ~/
        1000, // Expiration in seconds
  };

  String token = jwt.createToken(payload);
  print(token);

  payload = jwt.decodePayload(token);
  print(payload);

  print("token is verified: ${jwt.verifyToken(token)}");
}
