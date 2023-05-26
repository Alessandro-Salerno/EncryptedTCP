package alessandrosalerno.encryptedtcp.handshake;

import alessandrosalerno.encryptedtcp.asymmetric.AsymmetricEncryptionEngineFactory;
import alessandrosalerno.encryptedtcp.asymmetric.DefaultAsymmetricEncryptionEngineFactory;
import alessandrosalerno.encryptedtcp.handshake.modes.DefaultHandshakeModeFactory;
import alessandrosalerno.encryptedtcp.handshake.modes.HandshakeModeFactory;
import alessandrosalerno.encryptedtcp.symmetric.DefaultSymmetricEncryptionEngineFactory;
import alessandrosalerno.encryptedtcp.symmetric.SymmetricEncryptionEngineFactory;

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
