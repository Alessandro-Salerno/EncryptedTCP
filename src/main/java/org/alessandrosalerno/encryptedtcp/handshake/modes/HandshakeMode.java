package org.alessandrosalerno.encryptedtcp.handshake.modes;

import org.alessandrosalerno.encryptedtcp.handshake.HandshakeResult;

public interface HandshakeMode {
    HandshakeResult perform();
}
