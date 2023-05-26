package alessandrosalerno.encryptedtcp.handshake;

import alessandrosalerno.encryptedtcp.asymmetric.AsymmetricEncryptionEngineFactory;
import alessandrosalerno.encryptedtcp.exceptions.IncompatibleProtocolVersionException;
import alessandrosalerno.encryptedtcp.handshake.modes.HandshakeMode;
import alessandrosalerno.encryptedtcp.handshake.modes.HandshakeModeFactory;
import alessandrosalerno.encryptedtcp.symmetric.SymmetricEncryptionEngine;
import alessandrosalerno.encryptedtcp.symmetric.SymmetricEncryptionEngineFactory;
import alessandrosalerno.framedtcp.FramedReader;
import alessandrosalerno.framedtcp.FramedWriter;

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
        HandshakeResult handshake = this.handshakeMode.perform();;
        return this.symmetricEncryptionEngineFactory.newInstance(handshake.secretKey(), handshake.iv());
    }

    private HandshakeMode establishConnection(HandshakeModeFactory handshakeModeFactory) {
        if (this.socket.isClosed())
            throw new RuntimeException(new SocketException("Socket closed!"));

        try {
            FramedReader reader = new FramedReader(new InputStreamReader(this.socket.getInputStream()));
            FramedWriter writer = new FramedWriter(new OutputStreamWriter(this.socket.getOutputStream()));

            String myProtocolVersion = "VANILLA/0.0.2";
            writer.writeString(myProtocolVersion);
            String otherVersion = reader.readString();

            if (!myProtocolVersion.equals(otherVersion))
                throw new IncompatibleProtocolVersionException(otherVersion);

            int myRandom, otherRandom;

            do {
                myRandom = new Random().nextInt();;
                writer.writeString(String.valueOf(myRandom));
                otherRandom = Integer.parseInt(reader.readString());
            } while (myRandom == otherRandom);

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
