package org.alessandrosalerno.encryptedtcp.handshake;

import org.alessandrosalerno.encryptedtcp.symmetric.SymmetricEncryptionEngine;

public interface HandshakeManager {
    SymmetricEncryptionEngine finalizeHandshake();
}
