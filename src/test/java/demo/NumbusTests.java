package demo;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Date;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class NumbusTests {

    @Autowired
    TokenManager tokenManager;

    @Test
    void numbusApiPlayground() throws Exception {

        JWTClaimsSet claimsInput = new JWTClaimsSet.Builder()
                .subject("alice")
                .issueTime(new Date())
                .issuer("https://bubu.acme.com")
                .build();

        String encryptedTokenString = tokenManager.toEncryptedToken(claimsInput);
        JWTClaimsSet claimsOutput = tokenManager.parseEncryptedToken(encryptedTokenString);

        System.out.println(claimsOutput);
    }
}
