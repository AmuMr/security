package com.example.security.rsa;


import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSADemo {

    /**
     * RSA最大加密明文大小
     */
    private static final int MAX_ENCRYPT_BLOCK = 117;

    /**
     * RSA最大解密密文大小
     * 报错 Decryption error  改成256
     */
    private static final int MAX_DECRYPT_BLOCK = 256;

    /**
     * 获取密钥对
     *
     * @return 密钥对
     */
    public static KeyPair getKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        return generator.generateKeyPair();
    }

    /**
     * 获取私钥
     *
     * @param privateKey 私钥字符串
     * @return
     */
    public static PrivateKey getPrivateKey(String privateKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] decodedKey = Base64.decodeBase64(privateKey.getBytes());
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * 获取公钥
     *
     * @param publicKey 公钥字符串
     * @return
     */
    public static PublicKey getPublicKey(String publicKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] decodedKey = Base64.decodeBase64(publicKey.getBytes());
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * RSA加密
     *
     * @param data      待加密数据
     * @param publicKey 公钥
     * @return
     */
    public static String encrypt(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        int inputLen = data.getBytes().length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offset = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offset > 0) {
            if (inputLen - offset > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data.getBytes(), offset, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data.getBytes(), offset, inputLen - offset);
            }
            out.write(cache, 0, cache.length);
            i++;
            offset = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        // 获取加密内容使用base64进行编码,并以UTF-8为标准转化成字符串
        // 加密后的字符串
        return new String(Base64.encodeBase64String(encryptedData));
    }

    /**
     * RSA解密
     *
     * @param data       待解密数据
     * @param privateKey 私钥
     * @return
     */
    public static String decrypt(String data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] dataBytes = Base64.decodeBase64(data);
        int inputLen = dataBytes.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offset = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offset > 0) {
            if (inputLen - offset > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(dataBytes, offset, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(dataBytes, offset, inputLen - offset);
            }
            out.write(cache, 0, cache.length);
            i++;
            offset = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        // 解密后的内容
        return new String(decryptedData, "UTF-8");
    }

    /**
     * 签名
     *
     * @param data       待签名数据
     * @param privateKey 私钥
     * @return 签名
     */
    public static String sign(String data, PrivateKey privateKey) throws Exception {
        byte[] keyBytes = privateKey.getEncoded();
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey key = keyFactory.generatePrivate(keySpec);
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(key);
        signature.update(data.getBytes());
        return new String(Base64.encodeBase64(signature.sign()));
    }

    /**
     * 验签
     *
     * @param srcData   原始字符串
     * @param publicKey 公钥
     * @param sign      签名
     * @return 是否验签通过
     */
    public static boolean verify(String srcData, PublicKey publicKey, String sign) throws Exception {
        byte[] keyBytes = publicKey.getEncoded();
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey key = keyFactory.generatePublic(keySpec);
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initVerify(key);
        signature.update(srcData.getBytes());
        return signature.verify(Base64.decodeBase64(sign.getBytes()));
    }

    public static void main(String[] args) {
        try {
            // 生成密钥对
//            KeyPair keyPair = getKeyPair();
//            String privateKey = new String(Base64.encodeBase64(keyPair.getPrivate().getEncoded()));
//            String publicKey = new String(Base64.encodeBase64(keyPair.getPublic().getEncoded()));
          String privateKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCaP1A7frRiTWIRasz+81bUIbF9QtO3a1xVP/ULHHulQjCAA4Vp7arV8tMc8Btb/jovfs0RJWaJyKri7pccDJsujgNuCS8Wh2gxc8RfCS/ppUgdHn7gtPBQ1KV8mDDDsgIx/+QSzj8Ol3BrJq/iVeEKZqD06DQ6Tfv1/Xo5LDptcwWnVZ+IOUjPsGN4F0Odjr+1cRC1D51jZ3l8JNXzrFdXZoy2G92cukRXlwxmi5+z3HVuer5NnDzBdj9aL88Wyon2KXBGA2Ayg9ncIzvsbdsg0BhD3EwHlw6HBvtWIuKqiFZFzo9Cz4cFA9W2V5zdIcm5FNcl3Q0onaOMJkY7rzxzAgMBAAECggEAOi7hw99yiZYpBOrlctI1kYU4H0ji9dAwnxOmCk/vMBI8mz04yRFWnKehDMxhdZz7M8k/71TNTfH8y+c15uW2b6QwFQSv126yVd0WWMbtZNPs1NcZAwgdkk/0MIBz/I2cGGIvFQzpakajqDeKpvTAE51M37TrZobeIRdBUGmnjHr6I7GpxeZ0i0tpWegAPDr5RNpflHP39aMWaUFbadblzE8lbACd6lk/+E0UC7iVN+0h2U0SktGJLPyb6zXIVvjBQKq0jVFiopLLysa6GMKlhMLm5X8Cme+SlUOwIlMQAqr6s6+FtCkyBKOC7Ne2loSIY+Z58BvzziJlP/5e4bDEUQKBgQD4S39llHAFhwiUbCQH2FUzDtS1BMc9zSGR+6GHycTmCbekIXw+9JkMPGGcv8ZFBn04K0uN+DihXVTM3jKcqJRUQFMBAoqGPfp6GynOJk/YIO3/POLARgsqX/UZWppG2j/aNSqwiRWikInYJnc/1rRRhH5QjL/RxQprnWEVXq5X2wKBgQCfCK8D7os9HU673WiXd3EkrsZQfvwJyOvx6okeRGPw5Gth9OYZwPXwoF7YLsD0Jt7KifnOoUC6wLOIwCxXF35FmgsxqHXRVFeEv5IqFbkf+F79TR/W/WO0zFzVDF6nnyqyvEqsaTu9MDpUNrf+L7lwX0PBYW71gjm4wH7Dkes9SQKBgQDkXeQVlJoXq2Prxy64fHOYW1quB3ANWn822n5t+tj7TxK1hgrViHi/tUV+OzBryhUftUpvkE7ds47MQs3AIpkSiHsPYbvwzk5zQkqIDdrACUF80Q4pFAMu/UTcBeYBpri1xNK3vc3FUDVINdDWSW5dz4OyKFJA6H62DfD+C7BEowKBgBOSvAed2mFBNCmHDJJnzvMW162ck2SY6AE0PoANJsfFNTovLArLZvmgo0u0JWdnSVBgPvChhBf4E6CnFk35xD7IwMvx0d5bpRHfihvH5Kr8pKREU8DgGt9rr5lBFn1G57hr2Dz0DrgwMV2gBnEwaoBcGTi5xzBMQNJuTqu/T9aRAoGBAKuErIgKQScPIQ8zarndmi++RDcInKsDaYRKMKWcBenh2DutgZZk5amZNep+n5OUOIme3y6uJDtrJqyvGTwicceTkb6OCRaOQW8Ycy+k2VPlMXKyFTe4ksWKd8tHODFw6FiwGKeANVsrGVshzfKYXUFZASfm/5+mnKJpkVe4GXSx";
            String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmj9QO360Yk1iEWrM/vNW1CGxfULTt2tcVT/1Cxx7pUIwgAOFae2q1fLTHPAbW/46L37NESVmiciq4u6XHAybLo4DbgkvFodoMXPEXwkv6aVIHR5+4LTwUNSlfJgww7ICMf/kEs4/Dpdwayav4lXhCmag9Og0Ok379f16OSw6bXMFp1WfiDlIz7BjeBdDnY6/tXEQtQ+dY2d5fCTV86xXV2aMthvdnLpEV5cMZoufs9x1bnq+TZw8wXY/Wi/PFsqJ9ilwRgNgMoPZ3CM77G3bINAYQ9xMB5cOhwb7ViLiqohWRc6PQs+HBQPVtlec3SHJuRTXJd0NKJ2jjCZGO688cwIDAQAB";
//            System.out.println("私钥:" + privateKey);
//            System.out.println("公钥:" + publicKey);

            // RSA加密
            String data = "待加密的文字内容";
            String encryptData = encrypt(data, getPublicKey(publicKey));
            System.out.println("加密后内容:" + encryptData);

            // RSA解密
            String decryptData = decrypt(encryptData, getPrivateKey(privateKey));
            System.out.println("解密后内容:" + decryptData);

            // RSA签名
            String sign = sign(data, getPrivateKey(privateKey));
            System.out.println("签名串：" + sign);
            // RSA验签
            boolean result = verify(data, getPublicKey(publicKey), sign);
            System.out.print("验签结果:" + result);


        } catch (Exception e) {
            e.printStackTrace();
            System.out.print("加解密异常");
        }
    }
}