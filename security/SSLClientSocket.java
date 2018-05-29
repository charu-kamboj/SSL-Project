package security;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.Socket;

public class SSLClientSocket
        extends Socket {

    protected byte[] gKey;
    protected HashGen gHash;
    protected CryptoInStream gCryptoIn;
    protected CryptoOutStream gCryptoOut;
    protected Socket gSocket;

    public SSLClientSocket(Socket pSocket, byte[] pKey, HashGen pHash)
            throws IOException {
        gSocket = pSocket;
        gKey = pKey;
        gHash = pHash;
    }

    public SSLClientSocket(String host, int port, byte[] pUsername, byte[] pCompany, byte[] pEnKey, byte[] pKey, HashGen pHash)
            throws IOException {
        super(host, port);
        this.gKey = pKey;
        this.gHash = pHash;
        handshake(pUsername, pCompany, pEnKey);
    }

    protected void handshake(byte[] pUsername, byte[] pCompany, byte[] pKey)
            throws IOException {
        System.out.println("Setting Up Handshake...");
        SSLPacketAssembly lPacketObject = new SSLPacketAssembly(pUsername, pCompany, pKey);
        ObjectOutputStream lObjOutStream = new ObjectOutputStream(super.getOutputStream());
        lObjOutStream.writeObject(lPacketObject);
        lObjOutStream.flush();
        System.out.println("Hankshake Completed...");
    }

    public CryptoInStream getInputStream()
            throws IOException {
        if (this.gCryptoIn == null) {
            this.gCryptoIn = new CryptoInStream(this.gSocket != null ? this.gSocket.getInputStream() : super.getInputStream(), this.gKey, this.gHash);
        }
        return this.gCryptoIn;
    }

    public CryptoOutStream getOutputStream()
            throws IOException {
        if (this.gCryptoOut == null) {
            this.gCryptoOut = new CryptoOutStream(this.gSocket != null ? this.gSocket.getOutputStream() : super.getOutputStream(), this.gKey, this.gHash);
        }
        return this.gCryptoOut;
    }

    public void close()
            throws IOException {
        if (this.gSocket != null) {
            this.gSocket.close();
        }
        super.close();
    }
}
