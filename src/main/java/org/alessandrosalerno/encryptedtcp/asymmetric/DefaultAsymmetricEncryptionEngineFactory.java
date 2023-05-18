package org.alessandrosalerno.encryptedtcp.asymmetric;

import java.security.KeyPair;

public final class DefaultAsymmetricEncryptionEngineFactory implements AsymmetricEncryptionEngineFactory {
    @Override
    public AsymmetricEncryptionEngine newInstance() {
        return this.newInstance(2048);
    }

    @Override
    public AsymmetricEncryptionEngine newInstance(int keySize) {
        return new DefaultAsymmetricEncryptionEngine(keySize);
    }

    @Override
    public AsymmetricEncryptionEngine newInstance(KeyPair keyPair) {
        return new DefaultAsymmetricEncryptionEngine(keyPair);
    }
}
