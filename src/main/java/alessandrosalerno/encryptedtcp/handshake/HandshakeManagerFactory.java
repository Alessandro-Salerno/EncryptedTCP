package alessandrosalerno.encryptedtcp.handshake;

import alessandrosalerno.encryptedtcp.asymmetric.AsymmetricEncryptionEngineFactory;
import alessandrosalerno.encryptedtcp.handshake.modes.HandshakeModeFactory;
import alessandrosalerno.encryptedtcp.symmetric.SymmetricEncryptionEngineFactory;

import java.net.Socket;

public interface HandshakeManagerFactory {
    HandshakeManager newInstance(Socket socket,
                                 AsymmetricEncryptionEngineFactory asymmetricEncryptionEngineFactory,
                                 SymmetricEncryptionEngineFactory symmetricEncryptionEngineFactory,
                                 HandshakeModeFactory handshakeModeFactory);

    HandshakeManager newInstance(Socket socket);
}
