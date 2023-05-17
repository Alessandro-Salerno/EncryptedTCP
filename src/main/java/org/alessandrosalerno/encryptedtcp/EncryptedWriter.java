package org.alessandrosalerno.encryptedtcp;

import org.alessandrosalerno.framedtcp.FramedWriter;

import java.io.IOException;

public class EncryptedWriter {
    private final FramedWriter baseWriter;
    private final EncryptionEngine encryptionEngine;

    public EncryptedWriter(FramedWriter baseWriter, EncryptionEngine encryptionEngine) {
        this.baseWriter = baseWriter;
        this.encryptionEngine = encryptionEngine;
    }

    public void writeBytes(byte[] bytes) throws IOException {
        this.baseWriter.writeBytes(this.encryptionEngine.encrypt(bytes));
    }

    public void writeChars(char[] chars) throws IOException {
        this.writeBytes(new String(chars).getBytes());
    }

    public void writeString(String string) throws IOException {
        this.writeBytes(string.getBytes());
    }
}
