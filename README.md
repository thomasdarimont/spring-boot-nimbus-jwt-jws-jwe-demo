spring-boot-nimbus-jwt-jws-jwt-demo
---

Example for generating and parsing JWEs with nested JWS.

# Generate Keystore

```
keytool -genkey \
        -alias jwt-signing \
        -keystore src/main/resources/keystore.jks \
        -storepass geheim \
        -dname "CN=Ali G., OU=R&D, O=codecentric AG, L=Saarbrücken, ST=SL, C=DE"  \
        -keyalg RSA \
        -keysize 2048
```