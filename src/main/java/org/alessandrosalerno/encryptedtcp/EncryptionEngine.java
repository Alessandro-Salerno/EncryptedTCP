package org.alessandrosalerno.encryptedtcp;

public interface EncryptionEngine {
    byte[] encrypt(byte[] message);
    byte[] decrypt(byte[] message);
    String getAlgorithm();
}
