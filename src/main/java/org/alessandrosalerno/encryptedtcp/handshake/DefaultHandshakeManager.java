package org.alessandrosalerno.encryptedtcp.handshake;

import org.alessandrosalerno.encryptedtcp.asymmetric.AsymmetricEncryptionEngineFactory;
import org.alessandrosalerno.encryptedtcp.exceptions.IncompatibleProtocolVersionException;
import org.alessandrosalerno.encryptedtcp.handshake.modes.HandshakeMode;
import org.alessandrosalerno.encryptedtcp.handshake.modes.HandshakeModeFactory;
import org.alessandrosalerno.encryptedtcp.symmetric.SymmetricEncryptionEngine;
import org.alessandrosalerno.encryptedtcp.symmetric.SymmetricEncryptionEngineFactory;
import org.alessandrosalerno.framedtcp.FramedReader;
import org.alessandrosalerno.framedtcp.FramedWriter;

import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.net.SocketException;
import java.util.Random;

public final class DefaultHandshakeManager implements HandshakeManager {
    private final Socket socket;
    private final AsymmetricEncryptionEngineFactory asymmetricEncryptionEngineFactory;
    private final SymmetricEncryptionEngineFactory symmetricEncryptionEngineFactory;
    private final HandshakeMode handshakeMode;

    public DefaultHandshakeManager(Socket socket,
                                   AsymmetricEncryptionEngineFactory asymmetricEncryptionEngineFactory,
                                   SymmetricEncryptionEngineFactory symmetricEncryptionEngineFactory,
                                   HandshakeModeFactory handshakeModeFactory) {

        this.socket = socket;
        this.asymmetricEncryptionEngineFactory = asymmetricEncryptionEngineFactory;
        this.symmetricEncryptionEngineFactory = symmetricEncryptionEngineFactory;

        this.handshakeMode = this.establishConnection(handshakeModeFactory);
    }

    @Override
    public SymmetricEncryptionEngine finalizeHandshake() {
        return null;
    }

    private HandshakeMode establishConnection(HandshakeModeFactory handshakeModeFactory) {
        if (this.socket.isClosed())
            throw new RuntimeException(new SocketException("Socket closed!"));

        try {
            FramedReader reader = new FramedReader(new InputStreamReader(this.socket.getInputStream()));
            FramedWriter writer = new FramedWriter(new OutputStreamWriter(this.socket.getOutputStream()));

            String myProtocolVersion = "0.0.1";
            writer.writeString(myProtocolVersion);
            String otherVersion = reader.readString();

            if (!myProtocolVersion.equals(otherVersion))
                throw new IncompatibleProtocolVersionException(otherVersion);

            int myRandom = new Random().nextInt();
            writer.writeString(String.valueOf(myRandom));
            int otherRandom = Integer.parseInt(reader.readString());

            return handshakeModeFactory.fromNumbers(myRandom,
                                                        otherRandom,
                                                        this.socket,
                                                        this.asymmetricEncryptionEngineFactory,
                                                        this.symmetricEncryptionEngineFactory);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
