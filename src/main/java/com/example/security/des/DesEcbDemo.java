package com.example.security.des;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class DesEcbDemo {
    public static void main(String[] args) throws Exception {

        //随机生成密码
        KeyGenerator des = KeyGenerator.getInstance("DES");
        des.init(56);
        byte[] bytes = des.generateKey().getEncoded();
        byte[] base64 = Base64.encodeBase64(bytes);
       //System.out.println(new String(base64));


        //获得key对象
        String password = "zoqzH3A+DbU=";
        DESKeySpec desKeySpec = new DESKeySpec(password.getBytes());
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = keyFactory.generateSecret(desKeySpec);


        //加密
        String encodeHexString = encrypt(secretKey);
        System.out.println(encodeHexString);


        //解密
        byte[] doFinal = decrypt(secretKey, encodeHexString);

        System.out.println(new String(doFinal));


    }


    private static byte[] decrypt(SecretKey secretKey, String encodeHexString) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, DecoderException {
        Cipher cipher1 = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher1.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher1.doFinal(Hex.decodeHex(encodeHexString.toCharArray()));
    }

    private static String encrypt(SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE,secretKey);
        byte[] aFinal = cipher.doFinal("hello des".getBytes());

        return Hex.encodeHexString(aFinal);
    }
}
