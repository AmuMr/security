package com.example.security.des;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class DesCbcDemo {

    public static void main(String[] args) throws Exception {
        byte[] password = "12345678".getBytes();

        IvParameterSpec ivParameterSpec = new IvParameterSpec(password);
        DESKeySpec spec = new DESKeySpec(password);

        //加密
        String hexString = encrypt(ivParameterSpec, spec);
        System.out.println(hexString);

        //解密
        byte[] aFinal = decrypt(ivParameterSpec, spec, hexString);
        System.out.println(new String(aFinal));



    }

    private static byte[] decrypt(IvParameterSpec ivParameterSpec, DESKeySpec spec, String hexString) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, DecoderException {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = keyFactory.generateSecret(spec);
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        return cipher.doFinal(Hex.decodeHex(hexString.toCharArray()));
    }

    private static String encrypt(IvParameterSpec ivParameterSpec, DESKeySpec spec) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = keyFactory.generateSecret(spec);
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] aFinal = cipher.doFinal("hello des".getBytes());

        return Hex.encodeHexString(aFinal);
    }

}
