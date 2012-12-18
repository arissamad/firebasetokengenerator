firebasetokengenerator
======================

Simple java utility to generate JWT (JSON Web Tokens) for use with Firebase.

Provides Firebase-specific basic HMAC signing of a JWT (JSON Web Token).
See https://www.firebase.com/docs/security/authentication.html.

Example usage:
	FirebaseTokenGenerator ftg = new FirebaseTokenGenerator(apiKey);
	ftg.setOption("admin", true);
	ftg.setOption("debug", true);
	ftg.setData("somedata", "here");
	String token = ftg.createToken();	

The token is signed but not encrypted.

I designed this helper class to have minimum dependencies on classes like JSONObject etc.
The only dependency is on apache's commons-codec, tested with version 1.6.
As a result, however, only simple strings, booleans and numbers are accepted as option/data types.
