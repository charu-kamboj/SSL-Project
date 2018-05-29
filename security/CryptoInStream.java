package security;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

public class CryptoInStream
        extends FilterInputStream {

    protected HashGen gHash;
    protected byte[] gKey;
    private byte[] gBuff;
    private int gBuffPtr;

    public CryptoInStream(InputStream pIStream, byte[] pKey, HashGen pHash) {
        super(pIStream);
        gKey = pKey;
        gHash = pHash;
        gBuffPtr = 0;
    }

    public int read()
            throws IOException {
        if (gBuffPtr == 0) {
            int x = 0;
            int n = gHash.getPacketSize();
            byte[] lArBy_temp = new byte[n];
            for (int y = 0; y < n; y++) {
                int z = in.read();
                if (z == -1) {
                    if (y == 0) {
                        return -1;
                    }
                    throw new IOException("packet data not sliced up properly");
                }
                lArBy_temp[(x++)] = ((byte) z);
            }
            lArBy_temp = OneTimeKeyGen.xor(lArBy_temp, gKey);
            try {
                gBuff = gHash.unpacker(lArBy_temp);
            } catch (Exception ex) {
                System.out.println("Error");
            }
        }
        int temp = gBuff[gBuffPtr];
        gBuffPtr = ((gBuffPtr + 1) % gBuff.length);
        return temp;
    }

    public int available()
            throws IOException {
        return super.available() / gHash.getPacketSize() * gHash.gDatabytes;
    }
}
