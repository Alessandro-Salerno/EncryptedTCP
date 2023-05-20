# EncryptedTCP
EncryptedTCP is a very simple library based on [FramedTCP](https://github.com/Alessandro-Salerno/FramedTCP) that provides a fairly secure ecnrypted TCP connection.
EncryptedTCP works by using asymmetric encryption to exchange a symmetric key and its Init Vector to use for all other susequent messages.

## Protocol & Handshake
Assuming a clinet wants to connect to a server
1. The client and the server exchange their protocol versions (Currently ```"VANILLA/0.0.1"```)
2. If the protocol versions don't match, the secure connection is terminated
3. Otherwise, the server and the client exchange their randomly generated IDs
4. Depending on the IDs, a slave and a master are chosen
5. The slave sends his public RSA key to the master
6. The master generates a symmetric key and an IV
7. The master encrypts the symmetric key and the IV with the slave's public key and sends them to it
8. The slave constructs the Java representation of the key and the IV
9. The slaves sends an ```"OK"``` message to the master and waits for a reply
10. When the master replies with an ```"OK"``` message of its own, the handshake is over and all later messages will be secured by the symmetric key

## How to use
The library provides a series of classes that you can use to take advantage of its features. Unfortunatelly these are **NOT** standardized for now. This is how you build an echo server, for example.
### Server
```java
LOOP: while (true) {
    try (ServerSocket serverSocket = new ServerSocket(8000)) {
        Socket socket = serverSocket.accept();
        EncryptedSocket encryptedSocket = new EncryptedSocket(socket);
        String recv = encryptedSocket.getReader().readString();
        System.out.println("SERVER: " + recv);
        encryptedSocket.getWriter().writeString(recv);
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}
```

### Client
```java
try {
    Socket socket = new Socket("localhost", 8000);
    EncryptedSocket encryptedSocket = new EncryptedSocket(socket);
    encryptedSocket.getWriter().writeString("Hello world");
    System.out.println("CLIENT: " + encryptedSocket.getReader().readString());
  } catch (Exception e) {
    throw new RuntimeException(e);
  }
```

## License
EncryptedTCP is licensed under the terms of the MIT license.
