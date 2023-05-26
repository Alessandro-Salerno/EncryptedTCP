package alessandrosalerno.encryptedtcp.handshake.modes;

import alessandrosalerno.encryptedtcp.asymmetric.AsymmetricEncryptionEngineFactory;
import alessandrosalerno.encryptedtcp.symmetric.SymmetricEncryptionEngineFactory;

import java.net.Socket;

public interface HandshakeModeFactory {
    HandshakeMode newSlave(Socket socket,
                           AsymmetricEncryptionEngineFactory asymmetricEncryptionEngineFactory,
                           SymmetricEncryptionEngineFactory symmetricEncryptionEngineFactory);
    HandshakeMode newMaster(Socket socket,
                            AsymmetricEncryptionEngineFactory asymmetricEncryptionEngineFactory,
                            SymmetricEncryptionEngineFactory symmetricEncryptionEngineFactory);
    HandshakeMode fromNumbers(int me,
                              int other,
                              Socket socket,
                              AsymmetricEncryptionEngineFactory asymmetricEncryptionEngineFactory,
                              SymmetricEncryptionEngineFactory symmetricEncryptionEngineFactory);
}
