package com.example.security.des;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class AesDemo {

    public static void main(String[] args) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128,new SecureRandom("123456789".getBytes()));
        byte[] key = generator.generateKey().getEncoded();
        System.out.println(Hex.encodeHexString(key));

        byte[] aFinal = encrypt(key);
        System.out.println(Hex.encodeHexString(aFinal));

        byte[] doFinal = decrypt(key, aFinal);
        System.out.println(new String(doFinal));

    }

    private static byte[] decrypt(byte[] key, byte[] aFinal) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec keySpec = new SecretKeySpec(key,"AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        return cipher.doFinal(aFinal);
    }

    private static byte[] encrypt(byte[] key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec keySpec = new SecretKeySpec(key,"AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal("hello aes".getBytes());
    }
}
