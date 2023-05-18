package org.alessandrosalerno.encryptedtcp.handshake.modes.master;

import org.alessandrosalerno.encryptedtcp.asymmetric.AsymmetricEncryptionEngineFactory;
import org.alessandrosalerno.encryptedtcp.handshake.HandshakeResult;
import org.alessandrosalerno.encryptedtcp.handshake.modes.HandshakeMode;
import org.alessandrosalerno.encryptedtcp.symmetric.SymmetricEncryptionEngineFactory;

import java.net.Socket;

public final class DefaultMasterHandshake implements HandshakeMode {
    private final Socket socket;
    private final AsymmetricEncryptionEngineFactory asymmetricEncryptionEngineFactory;
    private final SymmetricEncryptionEngineFactory symmetricEncryptionEngineFactory;

    public DefaultMasterHandshake(Socket socket,
                                  AsymmetricEncryptionEngineFactory asymmetricEncryptionEngineFactory,
                                  SymmetricEncryptionEngineFactory symmetricEncryptionEngineFactory) {

        this.socket = socket;
        this.asymmetricEncryptionEngineFactory = asymmetricEncryptionEngineFactory;
        this.symmetricEncryptionEngineFactory = symmetricEncryptionEngineFactory;
    }

    @Override
    public HandshakeResult perform() {
        return null;
    }
}
