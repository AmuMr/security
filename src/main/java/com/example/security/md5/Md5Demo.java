package com.example.security.md5;

import org.apache.commons.codec.binary.Hex;
import org.springframework.util.DigestUtils;

import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;

public class Md5Demo {

    public static void main(String[] args) throws Exception {


        /**
         * MD2
         * MD4
         * MD5
         */
        MessageDigest instance = MessageDigest.getInstance("md5");
//        byte[] bytes = instance.digest("hello md5".getBytes());
//        String hexString = Hex.encodeHexString(bytes);
//        System.out.println(hexString);
//        String encode = DigestUtils.md5DigestAsHex("hello md5".getBytes());
//        System.out.println(encode);
        String file = "/Users/sky/Downloads/Obsidian.jar";
        byte[] digest = DigestUtils.md5Digest(new FileInputStream(new File(file)));
        System.out.println(Hex.encodeHexString(digest));


        //文件流
        FileInputStream inputStream = new FileInputStream(new File(file));

        byte[] bytes = new byte[4096];
        int len;
        while ((len = inputStream.read(bytes)) != -1) {
            instance.update(bytes, 0, len);
        }
        byte[] bytes1 = instance.digest();
        System.out.println(Hex.encodeHexString(bytes1));

    }


}
