package org.alessandrosalerno.encryptedtcp;

import org.alessandrosalerno.framedtcp.FramedReader;
import org.alessandrosalerno.framedtcp.FramedWriter;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

public class EncryptedSocket {
    private final Socket socket;
    private final EncryptionEngine encrypt;
    private final EncryptionEngine decrypt;
    private final EncryptedReader reader;
    private final EncryptedWriter writer;

    public EncryptedSocket(Socket socket, EncryptionEngineFactory encryptionEngineFactory) {
        if (socket.isClosed())
            throw new RuntimeException(new SocketException("socket closed"));

        this.socket = socket;
        this.encrypt = encryptionEngineFactory.newInstance();
        this.decrypt = encryptionEngineFactory.newInstance();

        try {
            PublicKey publicKey = this.establishEncryption();
            this.encrypt.setPublicKey(publicKey);

            this.reader = new EncryptedReader(new FramedReader(new InputStreamReader(this.socket.getInputStream())),
                                                this.decrypt);

            this.writer = new EncryptedWriter(new FramedWriter(new OutputStreamWriter(this.socket.getOutputStream())),
                                                this.encrypt);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public EncryptedSocket(Socket socket) {
        this(socket, new DefaultEncryptionEngineFactory());
    }

    private PublicKey establishEncryption() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        FramedReader fReader = new FramedReader(new InputStreamReader(this.socket.getInputStream()));
        FramedWriter fWriter = new FramedWriter(new OutputStreamWriter(this.socket.getOutputStream()));

        fWriter.writeBytes(this.encrypt.getPublicKey().getEncoded());
        return PublicKeyFactory.fromEncodedKey(this.encrypt.getAlgorithm(), fReader.readBytes());
    }

    public EncryptedReader getReader() {
        return this.reader;
    }

    public EncryptedWriter getWriter() {
        return this.writer;
    }
}
