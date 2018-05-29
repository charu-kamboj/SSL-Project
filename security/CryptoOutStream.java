package security;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class CryptoOutStream
        extends FilterOutputStream {

    protected HashGen gHash;
    protected byte[] gKey;
    private byte[] gDataBytes;
    private int gBuffPtr;

    public CryptoOutStream(OutputStream pOStream, byte[] pKey, HashGen pHash) {
        super(pOStream);
        gKey = pKey;
        gHash = pHash;
        gDataBytes = new byte[pHash.gDatabytes];
        gBuffPtr = 0;
    }

    public void flush()
            throws IOException {
        if (gBuffPtr != 0) {
            shallowFlush();
        }
        super.flush();
    }

    protected void shallowFlush()
            throws IOException {
        if (gBuffPtr != 0) {
            write(gDataBytes, 0, gBuffPtr);
            gBuffPtr = 0;
        }
    }

    public void write(int b)
            throws IOException {
        gDataBytes[(gBuffPtr++)] = ((byte) b);
        if (gBuffPtr == gDataBytes.length) {
            gBuffPtr = 0;
            write(gDataBytes, 0, gDataBytes.length);
        }
    }

    public void write(byte[] pData, int pOffset, int pLength)
            throws IOException {
        byte[] buffer = new byte[pLength];
        System.arraycopy(pData, pOffset, buffer, 0, pLength);
        byte[] messageData = gHash.packer(buffer);
        messageData = OneTimeKeyGen.xor(messageData, gKey);
        out.write(messageData);
    }
}
