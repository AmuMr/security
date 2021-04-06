package com.example.security.sha;

import org.apache.commons.codec.binary.Hex;

import java.security.MessageDigest;

public class ShaDemo {



    public static void main(String[] args) throws Exception {

        /**
         * SHA
         * SHA-1
         * SHA-224
         * SHA-256
         * SHA-384
         * SHA-516
         */
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] shas = sha.digest("hello sha".getBytes());
        String hexString = Hex.encodeHexString(shas);
        System.out.println(hexString);



    }
}
