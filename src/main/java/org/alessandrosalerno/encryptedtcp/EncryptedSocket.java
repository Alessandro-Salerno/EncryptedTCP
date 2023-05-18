package org.alessandrosalerno.encryptedtcp;

import org.alessandrosalerno.encryptedtcp.asymmetric.AsymmetricEncryptionEngine;
import org.alessandrosalerno.encryptedtcp.asymmetric.AsymmetricEncryptionEngineFactory;
import org.alessandrosalerno.encryptedtcp.asymmetric.DefaultAsymmetricEncryptionEngineFactory;
import org.alessandrosalerno.encryptedtcp.asymmetric.PublicKeyFactory;
import org.alessandrosalerno.encryptedtcp.handshake.DefaultHandshakeManagerFactory;
import org.alessandrosalerno.encryptedtcp.handshake.HandshakeManagerFactory;
import org.alessandrosalerno.encryptedtcp.symmetric.DefaultSymmetricEncryptionEngineFactory;
import org.alessandrosalerno.encryptedtcp.symmetric.SymmetricEncryptionEngine;
import org.alessandrosalerno.encryptedtcp.symmetric.SymmetricEncryptionEngineFactory;
import org.alessandrosalerno.framedtcp.FramedReader;
import org.alessandrosalerno.framedtcp.FramedWriter;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.net.SocketException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

public class EncryptedSocket {
    private final Socket socket;

    public EncryptedSocket(Socket socket,
                           AsymmetricEncryptionEngineFactory asymmetricEncryptionEngineFactory,
                           SymmetricEncryptionEngineFactory symmetricEncryptionEngineFactory,
                           HandshakeManagerFactory handshakeManagerFactory) {

        this.socket = socket;

    }

    public EncryptedSocket(Socket socket) {
        this(socket,
                new DefaultAsymmetricEncryptionEngineFactory(),
                new DefaultSymmetricEncryptionEngineFactory(),
                null /*new DefaultHandshakeManagerFactory()*/);
    }
}
