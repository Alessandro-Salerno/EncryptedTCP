package org.alessandrosalerno.encryptedtcp;

import org.alessandrosalerno.encryptedtcp.asymmetric.AsymmetricEncryptionEngine;
import org.alessandrosalerno.framedtcp.FramedReader;

import java.io.IOException;
import java.nio.ByteBuffer;

public class EncryptedReader {
    private final FramedReader baseReader;
    private final EncryptionEngine encryptionEngine;

    public EncryptedReader(FramedReader baseReader, EncryptionEngine encryptionEngine) {
        this.baseReader = baseReader;
        this.encryptionEngine = encryptionEngine;
    }

    public byte[] readBytes() throws IOException {
        byte[] message = this.baseReader.readBytes();
        return this.encryptionEngine.decrypt(message);
    }

    public char[] readChars() throws IOException {
        return ByteBuffer.wrap(this.readBytes()).asCharBuffer().array();
    }

    public String readString() throws IOException {
        return new String(this.readBytes());
    }

    public FramedReader getBaseReader() {
        return this.baseReader;
    }
}
