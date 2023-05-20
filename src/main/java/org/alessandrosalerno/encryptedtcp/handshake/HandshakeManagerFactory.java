package org.alessandrosalerno.encryptedtcp.handshake;

import org.alessandrosalerno.encryptedtcp.asymmetric.AsymmetricEncryptionEngineFactory;
import org.alessandrosalerno.encryptedtcp.handshake.modes.HandshakeModeFactory;
import org.alessandrosalerno.encryptedtcp.symmetric.SymmetricEncryptionEngineFactory;

import java.net.Socket;

public interface HandshakeManagerFactory {
    HandshakeManager newInstance(Socket socket,
                                 AsymmetricEncryptionEngineFactory asymmetricEncryptionEngineFactory,
                                 SymmetricEncryptionEngineFactory symmetricEncryptionEngineFactory,
                                 HandshakeModeFactory handshakeModeFactory);

    HandshakeManager newInstance(Socket socket);
}
