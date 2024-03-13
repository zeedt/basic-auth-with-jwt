package com.jwt.basic.auth.rsa;

import com.jwt.basic.auth.utils.PemUtils;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import lombok.SneakyThrows;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class AbconRSAKeyProvider implements RSAKeyProvider {

    private final byte[] filepathPrivateKey;
    private final byte[] filepathPublicKey;

    public AbconRSAKeyProvider(byte[] filepathPrivateKey, byte[] filepathPublicKey) {

        this.filepathPrivateKey = filepathPrivateKey;
        this.filepathPublicKey = filepathPublicKey;
    }


    @SneakyThrows
    @Override
    public RSAPublicKey getPublicKeyById(String s) {
        return (RSAPublicKey) PemUtils.readPublicKeyFromFile(filepathPublicKey, "RSA");
    }

    @SneakyThrows
    @Override
    public RSAPrivateKey getPrivateKey() {
        return (RSAPrivateKey) PemUtils.readPrivateKeyFromFile(filepathPrivateKey, "RSA");
    }

    @Override
    public String getPrivateKeyId() {
        return null;
    }

}