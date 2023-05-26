package alessandrosalerno.encryptedtcp.asymmetric;

import java.security.KeyPair;

public interface AsymmetricEncryptionEngineFactory {
    AsymmetricEncryptionEngine newInstance();
    AsymmetricEncryptionEngine newInstance(int keySize);
    AsymmetricEncryptionEngine newInstance(KeyPair keyPair);
}
