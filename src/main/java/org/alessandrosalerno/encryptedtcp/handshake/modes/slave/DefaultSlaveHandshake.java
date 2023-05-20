package org.alessandrosalerno.encryptedtcp.handshake.modes.slave;

import org.alessandrosalerno.encryptedtcp.EncryptedReader;
import org.alessandrosalerno.encryptedtcp.asymmetric.AsymmetricEncryptionEngine;
import org.alessandrosalerno.encryptedtcp.asymmetric.AsymmetricEncryptionEngineFactory;
import org.alessandrosalerno.encryptedtcp.handshake.HandshakeResult;
import org.alessandrosalerno.encryptedtcp.handshake.modes.HandshakeMode;
import org.alessandrosalerno.encryptedtcp.symmetric.SymmetricEncryptionEngineFactory;
import org.alessandrosalerno.framedtcp.FramedReader;
import org.alessandrosalerno.framedtcp.FramedWriter;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;

public final class DefaultSlaveHandshake implements HandshakeMode {
    private final Socket socket;
    private final AsymmetricEncryptionEngineFactory asymmetricEncryptionEngineFactory;
    private final SymmetricEncryptionEngineFactory symmetricEncryptionEngineFactory;

    public DefaultSlaveHandshake(Socket socket,
                                 AsymmetricEncryptionEngineFactory asymmetricEncryptionEngineFactory,
                                 SymmetricEncryptionEngineFactory symmetricEncryptionEngineFactory) {

        this.socket = socket;
        this.asymmetricEncryptionEngineFactory = asymmetricEncryptionEngineFactory;
        this.symmetricEncryptionEngineFactory = symmetricEncryptionEngineFactory;
    }

    @Override
    public HandshakeResult perform() {
        AsymmetricEncryptionEngine asym = this.asymmetricEncryptionEngineFactory.newInstance();

        try {
            FramedReader reader = new FramedReader(new InputStreamReader(this.socket.getInputStream()));
            EncryptedReader aReader = new EncryptedReader(reader, asym);

            FramedWriter writer = new FramedWriter(new OutputStreamWriter(this.socket.getOutputStream()));

            writer.writeBytes(asym.getPublicKey().getEncoded());
            byte[] symKey = aReader.readBytes();
            byte[] symIv = aReader.readBytes();

            SecretKey sKey = new SecretKeySpec(symKey, "AES");
            IvParameterSpec iv = new IvParameterSpec(symIv);

            writer.writeString("OK");
            while (!reader.readString().equals("OK"));

            return new HandshakeResult(sKey, iv);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
