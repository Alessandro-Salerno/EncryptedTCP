package alessandrosalerno.encryptedtcp.exceptions;

public class IncompatibleProtocolVersionException extends Exception {
    public IncompatibleProtocolVersionException(String otherVersion) {
        super("EncryptedTCP Protocol v" + otherVersion + " is not supported!");
    }
}
