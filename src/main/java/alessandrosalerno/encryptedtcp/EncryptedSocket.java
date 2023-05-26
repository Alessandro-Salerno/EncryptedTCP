package alessandrosalerno.encryptedtcp;

import alessandrosalerno.encryptedtcp.asymmetric.AsymmetricEncryptionEngineFactory;
import alessandrosalerno.encryptedtcp.handshake.DefaultHandshakeManagerFactory;
import alessandrosalerno.encryptedtcp.handshake.HandshakeManager;
import alessandrosalerno.encryptedtcp.handshake.HandshakeManagerFactory;
import alessandrosalerno.encryptedtcp.handshake.modes.DefaultHandshakeModeFactory;
import alessandrosalerno.encryptedtcp.handshake.modes.HandshakeModeFactory;
import alessandrosalerno.encryptedtcp.asymmetric.DefaultAsymmetricEncryptionEngineFactory;
import alessandrosalerno.encryptedtcp.symmetric.DefaultSymmetricEncryptionEngineFactory;
import alessandrosalerno.encryptedtcp.symmetric.SymmetricEncryptionEngine;
import alessandrosalerno.encryptedtcp.symmetric.SymmetricEncryptionEngineFactory;
import alessandrosalerno.framedtcp.FramedReader;
import alessandrosalerno.framedtcp.FramedWriter;

import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;

public class EncryptedSocket {
    private final Socket socket;
    private final EncryptedReader reader;
    private final EncryptedWriter writer;

    public EncryptedSocket(Socket socket,
                           AsymmetricEncryptionEngineFactory asymmetricEncryptionEngineFactory,
                           SymmetricEncryptionEngineFactory symmetricEncryptionEngineFactory,
                           HandshakeManagerFactory handshakeManagerFactory,
                           HandshakeModeFactory handshakeModeFactory) {

        this.socket = socket;

        HandshakeManager manager = handshakeManagerFactory.newInstance(socket,
                asymmetricEncryptionEngineFactory,
                symmetricEncryptionEngineFactory,
                handshakeModeFactory);

        SymmetricEncryptionEngine sym = manager.finalizeHandshake();

        try {
            this.reader = new EncryptedReader(new FramedReader(new InputStreamReader(this.socket.getInputStream())), sym);
            this.writer = new EncryptedWriter(new FramedWriter(new OutputStreamWriter(this.socket.getOutputStream())), sym);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public EncryptedSocket(Socket socket) {
        this(socket,
                new DefaultAsymmetricEncryptionEngineFactory(),
                new DefaultSymmetricEncryptionEngineFactory(),
                new DefaultHandshakeManagerFactory(),
                new DefaultHandshakeModeFactory());
    }

    public EncryptedReader getReader() {
        return this.reader;
    }

    public EncryptedWriter getWriter() {
        return this.writer;
    }
}
