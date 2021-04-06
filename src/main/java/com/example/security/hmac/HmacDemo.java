package com.example.security.hmac;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class HmacDemo {

    public static void main(String[] args) throws Exception {


        KeyGenerator hmacMd5 = KeyGenerator.getInstance("HmacMd5");
//        SecretKey generateKey = hmacMd5.generateKey();
//        自动生成密钥
//        byte[] bytes = Base64.encodeBase64(generateKey.getEncoded());
//        String key = new String(bytes);
//        System.out.println(key);
        byte[] key=Hex.decodeHex(new char[]{'1','2','3','4','5','6'});  //手动生成密钥
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HmacMd5");
        Mac mac = Mac.getInstance(secretKeySpec.getAlgorithm());
        mac.init(secretKeySpec);
        byte[] bytes = mac.doFinal("hello hmac".getBytes());
        String hexString = Hex.encodeHexString(bytes);
        System.out.println(hexString);
    }


}
