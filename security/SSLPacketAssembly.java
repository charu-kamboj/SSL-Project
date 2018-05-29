package security;

import java.io.Serializable;

public class SSLPacketAssembly
        implements Serializable {

    private static final long serialVersionUID = 1L;
    byte[] gUsername;
    byte[] gCompany;
    byte[] gKey;

    public SSLPacketAssembly(byte[] pUsername, byte[] pCompany, byte[] pKey) {
        gUsername = pUsername;
        gCompany = pCompany;
        gKey = pKey;
    }
}
