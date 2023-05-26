package alessandrosalerno.encryptedtcp.asymmetric;

import alessandrosalerno.encryptedtcp.EncryptionEngine;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface AsymmetricEncryptionEngine extends EncryptionEngine {
    PublicKey getPublicKey();
    PrivateKey getPrivateKey();
    void setPublicKey(PublicKey publicKey);
    void setPrivateKey(PrivateKey privateKey);
}
