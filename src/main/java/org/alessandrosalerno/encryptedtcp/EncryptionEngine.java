package org.alessandrosalerno.encryptedtcp;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface EncryptionEngine {
    byte[] encrypt(byte[] message);
    byte[] decrypt(byte[] message);
    String getAlgorithm();
    PublicKey getPublicKey();
    PrivateKey getPrivateKey();
    void setPublicKey(PublicKey publicKey);
    void setPrivateKey(PrivateKey privateKey);
}
