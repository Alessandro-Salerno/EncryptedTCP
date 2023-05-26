package alessandrosalerno.encryptedtcp.symmetric;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public final class DefaultSymmetricEncryptionEngineFactory implements SymmetricEncryptionEngineFactory {
    @Override
    public SymmetricEncryptionEngine newInstance() {
        return new DefaultSymmetricEncryptionEngine();
    }

    @Override
    public SymmetricEncryptionEngine newInstance(int keySIze) {
        return new DefaultSymmetricEncryptionEngine(keySIze);
    }

    @Override
    public SymmetricEncryptionEngine newInstance(SecretKey secretKey, IvParameterSpec iv) {
        return new DefaultSymmetricEncryptionEngine(secretKey, iv);
    }
}
