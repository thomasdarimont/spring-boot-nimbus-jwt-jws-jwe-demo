package demo;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;

import javax.crypto.SecretKey;

@RequiredArgsConstructor
class TokenManager {

    private final RSAKey signingKey;

    private final SecretKey encryptionKey;

    public String toEncryptedToken(JWTClaimsSet claims) throws Exception {

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build(),
                claims);

        signedJWT.sign(new RSASSASigner(signingKey));
        JWEObject jweObjectOutput = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM).contentType("JWT").build(),
                new Payload(signedJWT));

        jweObjectOutput.encrypt(new DirectEncrypter(encryptionKey));

        String jweString = jweObjectOutput.serialize();

        System.out.println(jweString);

        return jweString;
    }

    public JWTClaimsSet parseEncryptedToken(String encryptedToken) throws Exception {

        RSAKey senderPublicJWK = signingKey.toPublicJWK();

        JWEObject jweObjectInput = JWEObject.parse(encryptedToken);

        jweObjectInput.decrypt(new DirectDecrypter(encryptionKey));

        Payload payload = jweObjectInput.getPayload();

        JWSVerifier verifier = new RSASSAVerifier(senderPublicJWK);

        SignedJWT signedJWT = payload.toSignedJWT();

        if (!signedJWT.verify(verifier)) {
            throw new Exception("Bad token signature");
        }

        return signedJWT.getJWTClaimsSet();
    }
}