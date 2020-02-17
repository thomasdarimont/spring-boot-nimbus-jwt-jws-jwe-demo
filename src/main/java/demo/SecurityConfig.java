package demo;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyStore;

@Configuration
class SecurityConfig {

    @Value("${jwt.encryption.keystore.type:JKS}")
    String keystoreType;

    @Value("${jwt.encryption.keystore.path:keystore.jks}")
    String keystorePath;

    @Value("${jwt.encryption.keystore.password:geheim}")
    String keystorePassword;

    @Bean
    KeyStore signingKeystore() throws Exception {

        KeyStore keyStore = KeyStore.getInstance(keystoreType);
        char[] password = keystorePassword.toCharArray();
        keyStore.load(getClass().getClassLoader().getResourceAsStream(keystorePath), password);

        return keyStore;
    }

    @Bean
    RSAKey jwsSigningKey(KeyStore signingKeystore) throws Exception {

        char[] password = keystorePassword.toCharArray();
        RSAKey key = RSAKey.load(signingKeystore, "jwt-signing", password);

        RSAKey signingKey = new RSAKey.Builder(key)
                .keyID("jwt-signing")
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(new Algorithm("RS256"))
                .build();

        return signingKey;
    }

    @Bean
    SecretKey encryptionKey() throws Exception {

        // Get the expected key length for JWE enc "A128CBC-HS256"
        int keyBitLength = EncryptionMethod.A256GCM.cekBitLength();

        // Generate key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keyBitLength);
        SecretKey key = keyGen.generateKey();

        return key;
    }

    @Bean
    TokenManager tokenManager(RSAKey jwsSigningKey, SecretKey jweEncryptionKey) {
        return new TokenManager(jwsSigningKey, jweEncryptionKey);
    }
}
