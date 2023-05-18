package org.alessandrosalerno.encryptedtcp.handshake.modes;

import org.alessandrosalerno.encryptedtcp.asymmetric.AsymmetricEncryptionEngineFactory;
import org.alessandrosalerno.encryptedtcp.symmetric.SymmetricEncryptionEngineFactory;

import java.net.Socket;

public final class DefaultHandshakeModeFactory implements HandshakeModeFactory {
    @Override
    public HandshakeMode newSlave(Socket socket,
                                  AsymmetricEncryptionEngineFactory asymmetricEncryptionEngineFactory,
                                  SymmetricEncryptionEngineFactory symmetricEncryptionEngineFactory) {
        return null;
    }

    @Override
    public HandshakeMode newMaster(Socket socket,
                                   AsymmetricEncryptionEngineFactory asymmetricEncryptionEngineFactory,
                                   SymmetricEncryptionEngineFactory symmetricEncryptionEngineFactory) {
        return null;
    }

    @Override
    public HandshakeMode fromNumbers(int me,
                                     int other,
                                     Socket socket,
                                     AsymmetricEncryptionEngineFactory asymmetricEncryptionEngineFactory,
                                     SymmetricEncryptionEngineFactory symmetricEncryptionEngineFactory) {

        return switch (Integer.compare(me, other)) {
            case -1 -> this.newSlave(socket,
                    asymmetricEncryptionEngineFactory,
                    symmetricEncryptionEngineFactory);

            case 1 -> this.newMaster(socket,
                    asymmetricEncryptionEngineFactory,
                    symmetricEncryptionEngineFactory);

            default -> null;
        };
    }
}
