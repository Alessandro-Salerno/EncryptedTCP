package alessandrosalerno.encryptedtcp.handshake.modes.master;

import alessandrosalerno.encryptedtcp.EncryptedReader;
import alessandrosalerno.encryptedtcp.asymmetric.AsymmetricEncryptionEngine;
import alessandrosalerno.encryptedtcp.asymmetric.AsymmetricEncryptionEngineFactory;
import alessandrosalerno.encryptedtcp.asymmetric.PublicKeyFactory;
import alessandrosalerno.encryptedtcp.handshake.HandshakeResult;
import alessandrosalerno.encryptedtcp.handshake.modes.HandshakeMode;
import alessandrosalerno.encryptedtcp.EncryptedWriter;
import alessandrosalerno.encryptedtcp.symmetric.SymmetricEncryptionEngine;
import alessandrosalerno.encryptedtcp.symmetric.SymmetricEncryptionEngineFactory;
import alessandrosalerno.framedtcp.FramedReader;
import alessandrosalerno.framedtcp.FramedWriter;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.security.KeyPair;

public final class DefaultMasterHandshake implements HandshakeMode {
    private final Socket socket;
    private final AsymmetricEncryptionEngineFactory asymmetricEncryptionEngineFactory;
    private final SymmetricEncryptionEngineFactory symmetricEncryptionEngineFactory;

    public DefaultMasterHandshake(Socket socket,
                                  AsymmetricEncryptionEngineFactory asymmetricEncryptionEngineFactory,
                                  SymmetricEncryptionEngineFactory symmetricEncryptionEngineFactory) {

        this.socket = socket;
        this.asymmetricEncryptionEngineFactory = asymmetricEncryptionEngineFactory;
        this.symmetricEncryptionEngineFactory = symmetricEncryptionEngineFactory;
    }

    @Override
    public HandshakeResult perform() {
        try {
            FramedReader reader = new FramedReader(new InputStreamReader(this.socket.getInputStream()));
            FramedWriter writer = new FramedWriter(new OutputStreamWriter(this.socket.getOutputStream()));

            byte[] slavePublicKey = reader.readBytes();
            KeyPair keyPair = new KeyPair(PublicKeyFactory.fromEncodedKey("RSA", slavePublicKey), null);

            AsymmetricEncryptionEngine asym = this.asymmetricEncryptionEngineFactory.newInstance(keyPair);
            EncryptedReader aReader = new EncryptedReader(reader, asym);
            EncryptedWriter aWriter = new EncryptedWriter(writer, asym);

            SymmetricEncryptionEngine sym = this.symmetricEncryptionEngineFactory.newInstance();
            SecretKey sKey = sym.getSecretKey();
            IvParameterSpec iv = sym.getIv();

            aWriter.writeBytes(sKey.getEncoded());
            aWriter.writeBytes(iv.getIV());

            while (!reader.readString().equals("OK"));
            writer.writeString("OK");

            return new HandshakeResult(sKey, iv);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
