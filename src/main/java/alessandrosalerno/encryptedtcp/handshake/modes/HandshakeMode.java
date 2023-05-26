package alessandrosalerno.encryptedtcp.handshake.modes;

import alessandrosalerno.encryptedtcp.handshake.HandshakeResult;

public interface HandshakeMode {
    HandshakeResult perform();
}
