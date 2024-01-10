
# Encryption and Decryption Documentation

This document provides documentation for the encryption and decryption functionalities implemented in Java, PHP, and C# programming languages. The encryption algorithm used is AES-256-CBC with PBKDF2 key derivation.

## Java Code

```java
package RSA_1_5.AES256_CBC;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionUtility {

	public static String encrypt(String keyString, String plaintext) throws Exception {
	    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
	    PBEKeySpec pbeKeySpec = new PBEKeySpec(keyString.toCharArray(), new byte[] { 
	            73, 118, 97, 110, 32, 77, 101, 100, 118, 101, 
	            100, 101, 118 }, 1000, 384);
	    Key secretKey = factory.generateSecret(pbeKeySpec);
	    byte[] key = new byte[32];
	    byte[] iv = new byte[16];
	    System.arraycopy(secretKey.getEncoded(), 0, key, 0, 32);
	    System.arraycopy(secretKey.getEncoded(), 32, iv, 0, 16);
	    SecretKeySpec secret = new SecretKeySpec(key, "AES");
	    AlgorithmParameterSpec ivSpec = new IvParameterSpec(iv);
	    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	    cipher.init(1, secret, ivSpec);
	    String serialized = Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes("UTF-16LE")));
	    return serialized;
	}

    public static String decrypt(String keyString, String encryptedData) throws Exception {
        if (encryptedData.startsWith("Bearer "))
            encryptedData = encryptedData.substring(7);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec pbeKeySpec = new PBEKeySpec(keyString.toCharArray(), new byte[]{
                73, 118, 97, 110, 32, 77, 101, 100, 118, 101,
                100, 101, 118}, 1000, 384);
        Key secretKey = factory.generateSecret(pbeKeySpec);
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        System.arraycopy(secretKey.getEncoded(), 0, key, 0, 32);
        System.arraycopy(secretKey.getEncoded(), 32, iv, 0, 16);
        SecretKeySpec secret = new SecretKeySpec(key, "AES");
        AlgorithmParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secret, ivSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedBytes, "UTF-16LE");
    }
    
   
    
}

```

## PHP Code

```php
<?php
 
function utf16le_encode($str) {
    $result = '';
    for ($i = 0; $i < strlen($str); $i++) {
        $result .= $str[$i] . "\0";
    }
    return $result;
}
 
function encrypt($keyString, $plaintext) {
    $key = hash_pbkdf2("sha1", $keyString, pack("C*", 73, 118, 97, 110, 32, 77, 101, 100, 118, 101, 100, 101, 118), 1000, 32 + 16, true);
    $iv = substr($key, 32, 16);
    $key = substr($key, 0, 32);
    $cipher = "AES-256-CBC";
    $plaintextUtf16le = utf16le_encode($plaintext);
    $encryptedData = openssl_encrypt($plaintextUtf16le, $cipher, $key, OPENSSL_RAW_DATA, $iv);
    $base64Encoded = base64_encode($encryptedData);
    return $base64Encoded;
}
 
function decrypt($keyString, $encryptedData) {
    if (strpos($encryptedData, "Bearer ") === 0) {
        $encryptedData = substr($encryptedData, 7);
    }
 
    $key = hash_pbkdf2("sha1", $keyString, pack("C*", 73, 118, 97, 110, 32, 77, 101, 100, 118, 101, 100, 101, 118), 1000, 32 + 16, true);
    $iv = substr($key, 32, 16);
    $key = substr($key, 0, 32);
 
    $cipher = "AES-256-CBC";
    $decodedData = base64_decode($encryptedData);
    $decryptedBytes = openssl_decrypt($decodedData, $cipher, $key, OPENSSL_RAW_DATA, $iv);
    $decryptedData = rtrim(utf16le_decode($decryptedBytes), "\0");
    return $decryptedData;
}
 
function utf16le_decode($str) {
    $result = '';
    for ($i = 0; $i < strlen($str); $i += 2) {
        $result .= $str[$i];
    }
    return $result;
}
 
// Example usage:
$keyString = "F3880A8D84AFE230E9D14CEE1380BD73739731264A7525B7CA1049F9903C3021";
$plaintext = "Hello, World!";
 
$encryptedData = encrypt($keyString, $plaintext);
echo "Encrypted: " . $encryptedData . PHP_EOL;
 
$decryptedData = decrypt($keyString, $encryptedData);
echo "Decrypted: " . $decryptedData . PHP_EOL;
 
?>
```

## C# Code

```csharp
using System;
using System.Security.Cryptography;
using System.Text;
 
namespace AES_Encryption_Decryption
{
    public class EncryptionUtil
    {
        public static string Encrypt(string keyString, string plaintext)
        {
            Rfc2898DeriveBytes derivedKey = new Rfc2898DeriveBytes(keyString, new byte[] { 
                73, 118, 97, 110, 32, 77, 101, 100, 118, 101, 
                100, 101, 118 }, 1000);
            byte[] key = derivedKey.GetBytes(32);
            byte[] iv = derivedKey.GetBytes(16);
 
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Padding = PaddingMode.PKCS7;
 
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
 
                byte[] plaintextBytes = Encoding.Unicode.GetBytes(plaintext);
                byte[] encryptedBytes = encryptor.TransformFinalBlock(plaintextBytes, 0, plaintextBytes.Length);
 
                string encryptedData = Convert.ToBase64String(encryptedBytes);
                return encryptedData;
            }
        }
 
        public static string Decrypt(string keyString, string encryptedData)
        {
            if (encryptedData.StartsWith("Bearer "))
                encryptedData = encryptedData.Substring(7);
 
            Rfc2898DeriveBytes derivedKey = new Rfc2898DeriveBytes(keyString, new byte[] { 
                73, 118, 97, 110, 32, 77, 101, 100, 118, 101, 
                100, 101, 118 }, 1000);
            byte[] key = derivedKey.GetBytes(32);
            byte[] iv = derivedKey.GetBytes(16);
 
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Padding = PaddingMode.PKCS7;
 
                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
 
                byte[] encryptedBytes = Convert.FromBase64String(encryptedData);
                byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
 
                string decryptedData = Encoding.Unicode.GetString(decryptedBytes);
                return decryptedData;
            }
        }
 
        public static void Main(string[] args)
        {
            try
            {
                string key = "AESkey";
                string data = "test";
                string encryptedData = Encrypt(key, data);
                Console.WriteLine("Encrypted data: " + encryptedData);
                string decryptedData = Decrypt(key, encryptedData);
                Console.WriteLine("Decrypted data: " + decryptedData);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }
    }
}
```


## Node Js Code 
```JS
const crypto = require('crypto');

function utf16leEncode(str) {
    let result = '';
    for (let i = 0; i < str.length; i++) {
        result += str[i] + '\0';
    }
    return result;
}

function encrypt(keyString, plaintext) {
    const keyBuffer = crypto.pbkdf2Sync(
        keyString,
        Buffer.from([73, 118, 97, 110, 32, 77, 101, 100, 118, 101, 100, 101, 118]),
        1000,
        32 + 16,
        'sha1'
    );

    const iv = keyBuffer.slice(32, 32 + 16);
    const key = keyBuffer.slice(0, 32);

    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(utf16leEncode(plaintext), 'utf-8', 'base64');
    encrypted += cipher.final('base64');

    return encrypted;
}

function decrypt(keyString, encryptedData) {
    const keyBuffer = crypto.pbkdf2Sync(
        keyString,
        Buffer.from([73, 118, 97, 110, 32, 77, 101, 100, 118, 101, 100, 101, 118]),
        1000,
        32 + 16,
        'sha1'
    );

    const iv = keyBuffer.slice(32, 32 + 16);
    const key = keyBuffer.slice(0, 32);

    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encryptedData, 'base64', 'utf-8');
    decrypted += decipher.final('utf-8');

    return decrypted;
}

// Example usage:
const keyString = "F3880A8D84AFE230E9D14CEE1380BD73739731264A7525B7CA1049F9903C3021";
const plaintext = "Hello, World!";
const encryptedData = encrypt(keyString, plaintext);
console.log("Encrypted:", encryptedData);

const decryptedData = decrypt(keyString, encryptedData);
console.log("Decrypted:", String(decryptedData));

```

## Conclusion

This documentation provides an overview of the encryption and decryption functionality implemented in Java, PHP, Node js and C# for the AES-256-CBC algorithm with PBKDF2 key derivation. Users can refer to this documentation for understanding and utilizing the provided encryption and decryption methods in their applications.
```
