package com.example.security.des;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.*;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class DesedeCcbDemo {

    public static void main(String[] args) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
        keyGenerator.init(112);
        byte[] key = keyGenerator.generateKey().getEncoded();
        System.out.println(Hex.encodeHexString(key));


        byte[] aFinal = encrypt(key);
        System.out.println(Hex.encodeHexString(aFinal));
        byte[] bytes = decrypt(key, aFinal);
        System.out.println(new String(bytes));
    }

    private static byte[] decrypt(byte[] key, byte[] aFinal) throws Exception {
        DESedeKeySpec keySpec = new DESedeKeySpec(key);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        SecretKey secretKey = keyFactory.generateSecret(keySpec);
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey,new IvParameterSpec(new byte[8]));
        return cipher.doFinal(aFinal);
    }

    private static byte[] encrypt(byte[] key) throws Exception {
        DESedeKeySpec keySpec = new DESedeKeySpec(key);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        SecretKey secretKey = keyFactory.generateSecret(keySpec);
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey,new IvParameterSpec(new byte[8]));
        return cipher.doFinal("hello desede".getBytes());
    }
}
