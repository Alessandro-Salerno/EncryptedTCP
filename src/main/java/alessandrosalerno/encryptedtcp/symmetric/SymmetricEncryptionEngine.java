package alessandrosalerno.encryptedtcp.symmetric;

import alessandrosalerno.encryptedtcp.EncryptionEngine;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public interface SymmetricEncryptionEngine extends EncryptionEngine {
    SecretKey getSecretKey();
    IvParameterSpec getIv();
    void setSecreteKey(SecretKey secreteKey);
    void setIv(IvParameterSpec iv);
}
