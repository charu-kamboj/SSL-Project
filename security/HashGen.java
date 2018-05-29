package security;

import java.math.BigInteger;

public class HashGen {

    int gDatabytes;
    int gCheckbytes;
    byte gPattern;
    int gK;

    public HashGen(int pDatabytes, int pCheckbytes, byte pPattern, int pK) {
        this.gDatabytes = pDatabytes;
        this.gCheckbytes = pCheckbytes;
        this.gPattern = pPattern;
        this.gK = pK;
    }

    public int getPacketSize() {
        return gDatabytes + gCheckbytes + 1;
    }

    public byte[] packer(byte[] lData) {
        return HashGen.this.packer(lData, gDatabytes, gCheckbytes, gPattern, gK);
    }

    public static byte[] packer(byte[] pData, int pDatabytes, int pCheckbytes, byte pPattern, int pK) {
        if (pDatabytes > 256) {
            throw new RuntimeException("Maximum Size of databytes is 255.");
        }
        int lDataLength = pData.length;

        int lPacketLength = pDatabytes + pCheckbytes + 1;

        int lInt_Temp = lDataLength % pDatabytes == 0 ? lDataLength / pDatabytes : lDataLength / pDatabytes + 1;

        byte[] lArBy_temp = new byte[lInt_Temp * lPacketLength];
        int i2 = 0;
        for (int n = 0; n < lInt_Temp; n++) {
            int i3 = (byte) ((n + 1) * pDatabytes > lDataLength ? lDataLength % pDatabytes : pDatabytes);

            lArBy_temp[(n * lPacketLength)] = (byte) i3;

            BigInteger lBigInt_temp = BigInteger.valueOf(0L);
            byte b;
            for (int i1 = 0; i1 < i3; i1++) {
                b = pData[i2];
                i2++;
                lBigInt_temp = lBigInt_temp.add(BigInteger.valueOf((pPattern & b) * pK));
                lArBy_temp[(n * lPacketLength + i1 + 1)] = b;
            }
            lBigInt_temp = lBigInt_temp.mod(BigInteger.valueOf((int) Math.pow(2.0D, 8 * pCheckbytes)));

            b = (byte) lBigInt_temp.toByteArray().length;
            for (int i4 = 0; i4 < pCheckbytes; i4++) {
                if (pCheckbytes - i4 > b) {
                    lArBy_temp[(n * lPacketLength + pDatabytes + i4 + 1)] = 0;
                } else {
                    lArBy_temp[(n * lPacketLength + pDatabytes + i4 + 1)] = lBigInt_temp.toByteArray()[(i4 - (pCheckbytes - b))];
                }
            }
        }
        return lArBy_temp;
    }

    public byte[] unpacker(byte[] pData)
            throws Exception {
        return unpacker(pData, gDatabytes, gCheckbytes, gPattern, gK);
    }

    public static byte[] unpacker(byte[] pData, int pDatabytes, int pCheckbytes, byte pPattern, int pK)
            throws Exception {
        if (pDatabytes > 256) {
            throw new RuntimeException("Maximum size of databytes is 256");
        }
        int i = pData.length;
        int j = 1 + pDatabytes + pCheckbytes;
        if (i % j != 0) {
            throw new Exception("Packet Size is wrong");
        }
        int m = i / j;

        int n = 0;
        for (int i1 = 0; i1 < m; i1++) {
            n += pData[(i1 * j)];
        }
        byte[] lArBy_temp = new byte[n];
        int i2 = 0;
        int i3 = 0;
        int i4 = 0;
        for (; i2 < m; i2++) {
            int i5 = pData[(i2 * j)];
            BigInteger lBigInt_temp = BigInteger.valueOf(0L);
            i3++;
            byte b;
            for (int i6 = 0; i6 < i5; i6++) {
                b = pData[i3];
                i3++;
                lBigInt_temp = lBigInt_temp.add(BigInteger.valueOf((b & pPattern) * pK));
                lArBy_temp[i4] = b;
                i4++;
            }
            if (i5 < pDatabytes) {
                i3 += pDatabytes - i5;
            }
            lBigInt_temp = lBigInt_temp.mod(BigInteger.valueOf((int) Math.pow(2.0D, 8 * pCheckbytes)));
            b = (byte) lBigInt_temp.toByteArray().length;
            for (int i7 = pCheckbytes - b; i7 < pCheckbytes; i7++) {
                if (i7 >= 0) {
                    int i8 = pData[(i2 * j + pDatabytes + i7 + 1)];

                    int i9 = lBigInt_temp.toByteArray()[(b - pCheckbytes + i7)];
                    if (i8 != i9) {
                        throw new Exception("wrong checksum");
                    }
                }
            }
            i3 += pCheckbytes;
        }
        return lArBy_temp;
    }

    public static void main(String[] args)
            throws Exception {
        int lInt_databytes = Integer.parseInt(args[0]);
        int lInt_checkbytes = Integer.parseInt(args[1]);
        int lInt_pattern = (byte) Integer.parseInt(args[2]);
        int lInt_k = Integer.parseInt(args[3]);
        System.out.println("Hash Generator");
        System.out.println("---------------");
        for (int i1 = 4; i1 < args.length; i1++) {
            byte[] lByte_text = HashGen.packer(args[i1].getBytes(), lInt_databytes, lInt_checkbytes, (byte) lInt_pattern, lInt_k);
            System.out.println("Packed   : ");
            System.out.println(new String(lByte_text));
            System.out.println("Unpacked : ");
            System.out.println(new String(unpacker(lByte_text, lInt_databytes, lInt_checkbytes, (byte) lInt_pattern, lInt_k)));
        }
    }
}
// java HashGen 13 2 131 7 hello
