package org.alessandrosalerno.encryptedtcp;

import java.security.KeyPair;

public final class DefaultEncryptionEngineFactory implements EncryptionEngineFactory {
    @Override
    public EncryptionEngine newInstance() {
        return this.newInstance(2048);
    }

    @Override
    public EncryptionEngine newInstance(int keySize) {
        return new DefaultEncryptionEngine(keySize);
    }

    @Override
    public EncryptionEngine newInstance(KeyPair keyPair) {
        return new DefaultEncryptionEngine(keyPair);
    }
}
