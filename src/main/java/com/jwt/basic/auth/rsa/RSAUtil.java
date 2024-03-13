package com.jwt.basic.auth.rsa;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import lombok.SneakyThrows;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;

@Service
public class RSAUtil {

    @Value("${auth.issuer.url}")
    private String issuerUrl;

    final RSAKeyProvider rsaKeyProvider;
    final Algorithm algorithm;

    @SneakyThrows
    public RSAUtil(@Value("classpath:signing_public.pub") Resource filepathPublicKey,
                   @Value("classpath:signing_private_key_in_pkcs8.pem") Resource filepathPrivateKey) {



        this.rsaKeyProvider = new AbconRSAKeyProvider(loadPrivateKey(filepathPrivateKey), loadPublicKey(filepathPublicKey));
        this.algorithm = Algorithm.RSA256(rsaKeyProvider);
    }

    private byte[] loadPrivateKey(Resource resource) {
        try (InputStream inputStream = resource.getInputStream()) {
            return readBytesFromInputStream(inputStream);
        } catch (IOException e) {
          throw new RuntimeException(e);
        }
    }

    private byte[] loadPublicKey(Resource resource) {
        try (InputStream inputStream = resource.getInputStream()) {
            return readBytesFromInputStream(inputStream);
        } catch (IOException e) {
          throw new RuntimeException(e);
        }
    }




    private byte[] readBytesFromInputStream(InputStream inputStream) {
        try (PemReader reader = new PemReader(new InputStreamReader(inputStream))) {
            PemObject pemObject = reader.readPemObject();
            return pemObject.getContent();
        } catch (IOException e) {
            throw new RuntimeException("Error reading bytes from input stream", e);
        }
    }
    public String generateToken(String email, String userId, List<String> roles, LocalDateTime expiryDate, LocalDateTime issDate) {
        return JWT.create()
                .withIssuer(issuerUrl)
                .withExpiresAt(Date.from(expiryDate.toInstant(ZoneOffset.UTC)))
                .withIssuedAt(Date.from(issDate.toInstant(ZoneOffset.UTC)))
                .withClaim("email", email)
                .withClaim("id", userId)
                .withArrayClaim("roles", roles.toArray(new String[0]))
                .sign(algorithm);
    }

    public void verifyJwt(String token) {
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(issuerUrl)
                .withClaim("iat", new Date().toInstant().getEpochSecond())
                .withClaim("exp", new Date().toInstant().getEpochSecond())
                .build();
        verifier.verify(token);
    }

}