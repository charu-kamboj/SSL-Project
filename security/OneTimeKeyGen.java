package security;

import java.util.Random;

public class OneTimeKeyGen {

    public static byte[] genNewKey(Random pRandom, int pVal) {
        byte[] lArBy_temp = new byte[pVal];
        pRandom.nextBytes(lArBy_temp);
        return lArBy_temp;
    }

    public static byte[] genNewKey(int pVal) {
        return genNewKey(new Random(), pVal);
    }

    public static byte[] xor(byte[] pMessage, byte[] pKey) {
        if (pMessage.length % pKey.length != 0) {
            throw new RuntimeException("Runtime Exeception : Key Length Issue");
        }
        byte[] lArBy_temp = new byte[pMessage.length];
        System.arraycopy(pMessage, 0, lArBy_temp, 0, pMessage.length);

        int j = 0;
        for (int i = 0; i < pMessage.length / pKey.length; i++) {
            for (int k = 0; k < pKey.length; k++) {
                lArBy_temp[j] = ((byte) (lArBy_temp[j] ^ pKey[k]));
                j++;
            }
        }
        return lArBy_temp;
    }

    public static void main(String[] args) {
        byte[] lByte_key = args[0].getBytes();
        System.out.println("OneTimeKey Generator :");
        System.out.println("----------------------");
        for (int i = 1; i < args.length; i++) {
            System.out.println("Input   : " + args[i]);
            byte[] lByte_encoded = xor(args[i].getBytes(), lByte_key);
            System.out.println("Encoded : " + new String(lByte_encoded));
            byte[] lByte_decoded = xor(lByte_encoded, lByte_key);
            System.out.println("Decoded : " + new String(lByte_decoded));
        }
    }
}
