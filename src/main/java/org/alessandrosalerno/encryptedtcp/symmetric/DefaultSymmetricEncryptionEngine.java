package org.alessandrosalerno.encryptedtcp.symmetric;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public final class DefaultSymmetricEncryptionEngine implements SymmetricEncryptionEngine {
    private SecretKey secretKey;
    private IvParameterSpec iv;

    public DefaultSymmetricEncryptionEngine(int keySize) {
        this.secretKey = this.generateSecretKey(keySize);
        this.iv = this.generateIv();
    }

    public DefaultSymmetricEncryptionEngine() {
        this(128);
    }

    public DefaultSymmetricEncryptionEngine(SecretKey secretKey, IvParameterSpec iv) {
        this.secretKey = secretKey;
        this.iv = iv;
    }

    @Override
    public byte[] encrypt(byte[] message) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, this.secretKey, this.iv);
            return cipher.doFinal(message);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] decrypt(byte[] message) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, this.secretKey, this.iv);
            return cipher.doFinal(message);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String getAlgorithm() {
        return "AES";
    }

    @Override
    public SecretKey getSecretKey() {
        return this.secretKey;
    }

    @Override
    public IvParameterSpec getIv() {
        return this.iv;
    }

    @Override
    public void setSecreteKey(SecretKey secreteKey) {
        this.secretKey = secreteKey;
    }

    @Override
    public void setIv(IvParameterSpec iv) {
        this.iv = iv;
    }

    private SecretKey generateSecretKey(int keySize) {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(keySize);
            return keyGenerator.generateKey();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
}
