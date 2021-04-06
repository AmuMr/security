package com.example.security.des;

import org.apache.commons.codec.binary.Base64;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * 签名、加密、编码、解码、解密、验签处理
 */
public class SignDemo {

    /**
     * 生成公私钥对
     */
    public static void main(String[] args) {
        try {
            SecureRandom sr = new SecureRandom();
            KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
            // 注意密钥大小1024
            kg.initialize(1024, sr);
            KeyPair keyPair = kg.generateKeyPair();
            PrivateKey priKey = keyPair.getPrivate();
            PublicKey pubKey = keyPair.getPublic();
            byte[] publicKey = pubKey.getEncoded();
            byte[] privateKey = priKey.getEncoded();

            System.out.println("公钥：" + byteArr2HexString(publicKey));
            System.out.println("私钥：" + byteArr2HexString(privateKey));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 把字节数组转换成16进制字符串
     *
     * @param bytearr
     * @return
     */
    public static String byteArr2HexString(byte[] bytearr) {
        if (bytearr == null) {
            return "null";
        }
        StringBuffer sb = new StringBuffer();
        for (int k = 0; k < bytearr.length; k++) {
            if ((bytearr[k] & 0xFF) < 16) {
                sb.append("0");
            }
            sb.append(Integer.toString(bytearr[k] & 0xFF, 16));
        }

        return sb.toString();
    }

    /**
     * 把16进制字符串转换为字节数组
     *
     * @param hexStr
     * @return
     */
    public static byte[] hexStringToByteArr(String hexStr) {
        return new BigInteger(hexStr, 16).toByteArray();
    }

    /**
     * DES加密
     *
     * @param key  私钥
     * @param data
     * @return
     * @throws Exception
     */
    public static byte[] encode(String key, byte[] data) throws Exception {
        DESKeySpec dks = new DESKeySpec(key.getBytes());
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");

        // key的长度不能够小于8位字节
        SecretKey secretKey = keyFactory.generateSecret(dks);

        // 向量
        String vector = "12345678";
        IvParameterSpec iv = new IvParameterSpec(vector.getBytes());
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

        byte[] bytes = cipher.doFinal(data);
        return bytes;
    }

    /**
     * DES解密
     *
     * @param key
     * @param data
     * @return
     * @throws Exception
     */
    public static String decode(String key, byte[] data) {
        try {
            DESKeySpec dks = new DESKeySpec(key.getBytes());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");

            // key的长度不能够小于8位字节
            SecretKey secretKey = keyFactory.generateSecret(dks);

            // 向量
            String vector = "12345678";
            IvParameterSpec iv = new IvParameterSpec(vector.getBytes());
            Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
            byte[] bytes = cipher.doFinal(data);

            return new String(bytes);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * 将BASE64编码的字符串进行解码
     *
     * @param data
     * @return
     */
    public static byte[] base64dec(String data) {
        if (data == null || "".equals(data)) {
            return null;
        }
        BASE64Decoder decoder = new BASE64Decoder();
        try {
            byte[] b = decoder.decodeBuffer(data);
            return b;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * 将字符串进行BASE64编码
     *
     * @param bytes
     * @return
     */
    public static String base64enc(byte[] bytes) {
        try {
            BASE64Encoder encoder = new BASE64Encoder();
            return encoder.encode(bytes);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * 签名
     *
     * @param data 报文
     * @return
     */
    public static String sign(String privateKeyString, String data) {
        // 私钥
        try {
            byte[] key = Base64.decodeBase64(privateKeyString);
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(key);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            Signature instance = Signature.getInstance("SHA1withRSA");
            instance.initSign(privateKey);
            instance.update(data.getBytes("UTF-8"));
            byte[] sign = instance.sign();
            return byteArr2HexString(sign);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return "";
    }

    /**
     * 验签
     *
     * @param publicKeyString 公钥
     * @param data
     * @param checkValue
     * @return
     */
    public static boolean verify(String publicKeyString, String data, String checkValue) {

        // 将十六进制转为字节数组
        byte[] sign = hexStringToByteArr(checkValue);

        // 公钥
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(
                    hexStringToByteArr(publicKeyString));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicK = keyFactory.generatePublic(keySpec);
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initVerify(publicK);
            signature.update(data.getBytes("UTF-8"));

            return signature.verify(sign);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }



}
