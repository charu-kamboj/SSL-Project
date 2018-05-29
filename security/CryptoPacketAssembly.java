package security;

import java.io.Serializable;

public class CryptoPacketAssembly
        implements Serializable {

    private static final long serialVersionUID = 1L;
    byte[] gData;

    public CryptoPacketAssembly(byte[] pData) {
        this.gData = pData;
    }

}
