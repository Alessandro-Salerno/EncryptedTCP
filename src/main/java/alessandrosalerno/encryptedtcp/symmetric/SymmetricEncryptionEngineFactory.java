package alessandrosalerno.encryptedtcp.symmetric;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public interface SymmetricEncryptionEngineFactory {
    SymmetricEncryptionEngine newInstance();
    SymmetricEncryptionEngine newInstance(int keySIze);
    SymmetricEncryptionEngine newInstance(SecretKey secretKey, IvParameterSpec iv);
}
