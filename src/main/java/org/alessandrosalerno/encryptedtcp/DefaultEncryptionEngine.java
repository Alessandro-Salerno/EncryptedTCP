package org.alessandrosalerno.encryptedtcp;

import javax.crypto.Cipher;
import java.security.*;

final class DefaultEncryptionEngine implements EncryptionEngine {
    private final String algorithm;
    private int keySize;
    private KeyPair keyPair;

    public DefaultEncryptionEngine(String algorithm, int keySize) {
        this.algorithm = algorithm;
        this.keySize = keySize;
        this.keyPair = this.generateKeyPair();
    }

    public DefaultEncryptionEngine(KeyPair keyPair) {
        this.algorithm = "RSA";
        this.keySize = 0;
        this.keyPair = keyPair;
    }

    public DefaultEncryptionEngine(int keySize) {
        this("RSA", keySize);
    }

    private KeyPair generateKeyPair() {
        try {
            SecureRandom secureRandom = new SecureRandom();
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(this.algorithm);
            keyPairGenerator.initialize(this.keySize, secureRandom);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            return null;
        }
    }

    @Override
    public byte[] encrypt(byte[] message) {
        try {
            Cipher cipher = Cipher.getInstance(this.algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, this.keyPair.getPrivate());
            return cipher.doFinal(message);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] decrypt(byte[] message) {
        try {
            Cipher cipher = Cipher.getInstance(this.algorithm);
            cipher.init(Cipher.DECRYPT_MODE, this.keyPair.getPrivate());
            return cipher.doFinal(message);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String getAlgorithm() {
        return this.algorithm;
    }

    @Override
    public PublicKey getPublicKey() {
        return this.keyPair.getPublic();
    }

    @Override
    public PrivateKey getPrivateKey() {
        return this.keyPair.getPrivate();
    }

    @Override
    public void setPublicKey(PublicKey publicKey) {
        this.keyPair = new KeyPair(publicKey, this.keyPair.getPrivate());
        this.keySize = publicKey.getEncoded().length;
    }

    @Override
    public void setPrivateKey(PrivateKey privateKey) {
        this.keyPair = new KeyPair(this.keyPair.getPublic(), privateKey);
        this.keySize = privateKey.getEncoded().length;
    }
}
