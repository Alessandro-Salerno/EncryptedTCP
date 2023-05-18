package org.alessandrosalerno.encryptedtcp.asymmetric;

import javax.crypto.Cipher;
import java.security.*;

public final class DefaultAsymmetricEncryptionEngine implements AsymmetricEncryptionEngine {
    private KeyPair keyPair;

    public DefaultAsymmetricEncryptionEngine(int keySize) {
        this.keyPair = this.generateKeyPair(keySize);
    }

    public DefaultAsymmetricEncryptionEngine(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    @Override
    public byte[] encrypt(byte[] message) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, this.keyPair.getPrivate());
            return cipher.doFinal(message);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] decrypt(byte[] message) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, this.keyPair.getPrivate());
            return cipher.doFinal(message);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String getAlgorithm() {
        return "RSA";
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
    }

    @Override
    public void setPrivateKey(PrivateKey privateKey) {
        this.keyPair = new KeyPair(this.keyPair.getPublic(), privateKey);
    }

    private KeyPair generateKeyPair(int keySize) {
        try {
            SecureRandom secureRandom = new SecureRandom();
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(keySize, secureRandom);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            return null;
        }
    }
}
