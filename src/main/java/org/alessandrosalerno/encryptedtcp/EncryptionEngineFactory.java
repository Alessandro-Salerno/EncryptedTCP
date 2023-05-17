package org.alessandrosalerno.encryptedtcp;

import java.security.KeyPair;

public interface EncryptionEngineFactory {
    EncryptionEngine newInstance();
    EncryptionEngine newInstance(int keySize);
    EncryptionEngine newInstance(KeyPair keyPair);
}
