package com.sirra.firebaseutil;
import java.io.*;
import java.security.*;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.*;

import org.apache.commons.codec.binary.Base64;


/**
 * Provides Firebase-specific basic HMAC signing of a JWT (JSON Web Token).
 * See https://www.firebase.com/docs/security/authentication.html.
 * 
 * Example usage:
 *   FirebaseTokenGenerator ftg = new FirebaseTokenGenerator(apiKey);
 *   ftg.setOption("admin", true);
 *   ftg.setOption("debug", true);
 *   ftg.setData("somedata", "here");
 *   String token = ftg.createToken();	
 * 
 * The token is signed but not encrypted.
 * 
 * I designed this helper class to have minimum dependencies on classes like JSONObject etc.
 * The only dependency is on apache's commons-codec, tested with version 1.6.
 * As a result, however, only simple strings, booleans and numbers are accepted as option/data types.
 * 
 * @author aris
 */
public class FirebaseTokenGenerator {
	
	protected int version = 0;
	protected static final String UTF8 = "utf-8";

	protected String header;
	protected String firebaseSecret;
	
	protected Map<String, Object> data;
	protected Map<String, Object> options;
	
	/**
	 * @param claims is in JSON format, i.e. {"some":"data"}.
	 */
	public FirebaseTokenGenerator(String apiKey) {
		this.header = "{\"alg\":\"HS256\"}";
		this.firebaseSecret = apiKey;
		
		data = new HashMap<String, Object>();
		options = new HashMap<String, Object>();
	}
	
	/**
	 * Only supports values made of simple strings with no special characters and boolean.
	 */
	public void setData(String dataName, Object value) {
		data.put(dataName, value);
	}
	
	/**
	 * See https://www.firebase.com/docs/security/nodejs-token-generator.html for a list
	 * of Firebase-supported options.
	 * 
	 * Examples:
	 *  - admin (boolean) - Set to true if you want to disable all Security Rules for this client
	 *  - debug (boolean) - Set to true to enable debug output from your Security Rules.
	 */
	public void setOption(String optionName, Object value) {
		options.put(optionName, value);
	}
	
	public String createToken() {
		StringBuilder sb = new StringBuilder();
		sb.append(encodeJson(header));
		sb.append(".");
		sb.append(encodeJson(getClaimsString()));
		
		String signature = getSignature(sb.toString());
		
		sb.append(".");
		sb.append(signature);
		
		return sb.toString();
	}
	
	/* 
	 * Ultra-basic implementation: We just build the JSON claims data as a string. 
	 * You can subclass this method and beef this up with a class like "JSONObject"
	 * if you want better handling (i.e. escaping) of JSON data.
	 * 
	 * This is public so you can take a look at how the claims string looks like if you want.
	 */
	public String getClaimsString() {
		
		StringBuilder claims = new StringBuilder();
		
		claims.append("{");
		
		// "v" seems to be a version string of some kind
		claims.append("\"v\": " + version);
		claims.append(",");
		
		// "iat" is JWT-standard "issued at" token
		// DISCREPANCY: http://tools.ietf.org/html/draft-jones-json-web-token-10
		// Spec defines iat as number of seconds. However, firebase seems to expect number of milliseconds.
		Date date = new Date();
		long iat = date.getTime();
		claims.append("\"iat\": " + iat);
		claims.append(",");
		
		// options are inserted
		if(options.size() > 0) {
			claims.append(mapToJson(options));
			claims.append(",");
		}
		
		// "d" is where user data is appended
		claims.append("\"d\":{");
		claims.append(mapToJson(data));
		claims.append("}");
		
		claims.append("}");
		
		System.out.println("Claims:\n" + claims);
		
		return claims.toString();
	}
	
	protected String getSignature(String signableContent) {
		try {
			Mac mac = Mac.getInstance("HMACSHA256");
			
			try {
				mac.init(new SecretKeySpec(firebaseSecret.getBytes(UTF8), mac.getAlgorithm()));
				
			} catch (InvalidKeyException e) {
				throw new RuntimeException("Invalid HMAC key: " + e.getMessage(), e);
			}
			
			mac.update(signableContent.getBytes(UTF8));
			
			return encodeSignature(mac.doFinal());
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * Encode a JSON string like {"some": "data"} as Base64URL.
	 */
	protected String encodeJson(String text) {
		try {
			return Base64.encodeBase64URLSafeString(text.getBytes(UTF8));
		} catch (UnsupportedEncodingException e) {
			// UTF-8 should always be supported
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * Encode the signature byte series as Base64URL.
	 */
	protected String encodeSignature(byte[] bytes) {
		return Base64.encodeBase64URLSafeString(bytes);
	}
	
	protected String mapToJson(Map<String, Object> incomingMap) {
		StringBuilder sb = new StringBuilder();
		
		Iterator<String> it = incomingMap.keySet().iterator();
		while(it.hasNext()) {
			String key = it.next();
			sb.append(toJavaScript(key));
			sb.append(":");
			sb.append(toJavaScript(incomingMap.get(key)));
			
			if(it.hasNext()) {
				sb.append(",");
			}
		}
		
		return sb.toString();
	}
	
	/**
	 * Converts a java object like String, Boolean and Double/Float/Integer to JSON-friendly strings.
	 */
	protected String toJavaScript(Object obj) {
		if(obj == null) return "null";
		
		if(obj instanceof String) {
			return "\"" + obj+ "\"";
		} else if(obj instanceof Boolean) {
			Boolean b = (Boolean) obj;
			return  b.toString();
		} else if(obj instanceof Integer || obj instanceof Double || obj instanceof Float) {
			return "" + obj;
		} else {
			throw new RuntimeException("Unsupported type: " + obj.getClass());
		}
	}
}

