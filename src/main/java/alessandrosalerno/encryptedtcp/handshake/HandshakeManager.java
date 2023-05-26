package alessandrosalerno.encryptedtcp.handshake;

import alessandrosalerno.encryptedtcp.symmetric.SymmetricEncryptionEngine;

public interface HandshakeManager {
    SymmetricEncryptionEngine finalizeHandshake();
}
