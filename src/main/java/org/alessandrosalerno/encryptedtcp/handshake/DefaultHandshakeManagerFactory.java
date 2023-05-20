package org.alessandrosalerno.encryptedtcp.handshake;

import org.alessandrosalerno.encryptedtcp.asymmetric.AsymmetricEncryptionEngineFactory;
import org.alessandrosalerno.encryptedtcp.asymmetric.DefaultAsymmetricEncryptionEngineFactory;
import org.alessandrosalerno.encryptedtcp.handshake.modes.DefaultHandshakeModeFactory;
import org.alessandrosalerno.encryptedtcp.handshake.modes.HandshakeModeFactory;
import org.alessandrosalerno.encryptedtcp.symmetric.DefaultSymmetricEncryptionEngineFactory;
import org.alessandrosalerno.encryptedtcp.symmetric.SymmetricEncryptionEngineFactory;

import java.net.Socket;

public final class DefaultHandshakeManagerFactory implements HandshakeManagerFactory {
    @Override
    public HandshakeManager newInstance(Socket socket,
                                        AsymmetricEncryptionEngineFactory asymmetricEncryptionEngineFactory,
                                        SymmetricEncryptionEngineFactory symmetricEncryptionEngineFactory,
                                        HandshakeModeFactory handshakeModeFactory) {

        return new DefaultHandshakeManager(socket,
                asymmetricEncryptionEngineFactory,
                symmetricEncryptionEngineFactory,
                handshakeModeFactory);
    }

    @Override
    public HandshakeManager newInstance(Socket socket) {
        return this.newInstance(socket,
                new DefaultAsymmetricEncryptionEngineFactory(),
                new DefaultSymmetricEncryptionEngineFactory(),
                new DefaultHandshakeModeFactory());
    }
}
