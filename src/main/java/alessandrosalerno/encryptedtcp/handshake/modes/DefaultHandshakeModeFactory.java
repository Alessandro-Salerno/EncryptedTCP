package alessandrosalerno.encryptedtcp.handshake.modes;

import alessandrosalerno.encryptedtcp.asymmetric.AsymmetricEncryptionEngineFactory;
import alessandrosalerno.encryptedtcp.handshake.modes.master.DefaultMasterHandshake;
import alessandrosalerno.encryptedtcp.handshake.modes.slave.DefaultSlaveHandshake;
import alessandrosalerno.encryptedtcp.symmetric.SymmetricEncryptionEngineFactory;

import java.net.Socket;

public final class DefaultHandshakeModeFactory implements HandshakeModeFactory {
    @Override
    public HandshakeMode newSlave(Socket socket,
                                  AsymmetricEncryptionEngineFactory asymmetricEncryptionEngineFactory,
                                  SymmetricEncryptionEngineFactory symmetricEncryptionEngineFactory) {

        return new DefaultSlaveHandshake(socket,
                asymmetricEncryptionEngineFactory,
                symmetricEncryptionEngineFactory);
    }

    @Override
    public HandshakeMode newMaster(Socket socket,
                                   AsymmetricEncryptionEngineFactory asymmetricEncryptionEngineFactory,
                                   SymmetricEncryptionEngineFactory symmetricEncryptionEngineFactory) {

        return new DefaultMasterHandshake(socket,
                asymmetricEncryptionEngineFactory,
                symmetricEncryptionEngineFactory);
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
