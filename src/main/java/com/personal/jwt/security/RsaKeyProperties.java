package com.personal.jwt.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@ConfigurationProperties(prefix = "rsa")
public record RsaKeyProperties (RSAPublicKey publicKey, RSAPrivateKey privateKey, File encryptedPrivateKey){

    public RSAPrivateKey getDecryptedPrivateKey() {
        try {
            // Read the content of the private key file
            byte[] privateKeyBytes = Files.readAllBytes(Paths.get(encryptedPrivateKey.toURI()));

            String privateKeyString = new String(privateKeyBytes, StandardCharsets.UTF_8);
            privateKeyString = privateKeyString
                    .replace("-----BEGIN ENCRYPTED PRIVATE KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END ENCRYPTED PRIVATE KEY-----", "").trim();

            // Base64 decode the private key
            byte[] decodedPrivateKeyBytes = Base64.getDecoder().decode(privateKeyString);

            // Get the RSA KeyFactory instance
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            // Generate the encrypted RSAPrivateKey
            EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(decodedPrivateKeyBytes);
            PBEKeySpec pbeKeySpec = new PBEKeySpec("passkey".toCharArray()); // password while creating encrypted key
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(encryptedPrivateKeyInfo.getAlgName());
            Key secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
            PKCS8EncodedKeySpec decryptedKeySpec = encryptedPrivateKeyInfo.getKeySpec(secretKey);

            // Generate the RSAPrivateKey from the decrypted key spec
            return (RSAPrivateKey) keyFactory.generatePrivate(decryptedKeySpec);
        } catch (Exception e) {
            // Handle decryption errors gracefully
            e.printStackTrace();
            return null;
        }
    }
}
