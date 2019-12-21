package com.ainge.easycrypto.example;


import com.ainge.easycrypto.asymmetric.RSACrypter;
import com.ainge.easycrypto.generators.RSAKeyPairGenerator;
import org.junit.Assert;
import org.junit.Test;

import java.security.KeyPair;

/**
 * @author: Ainge
 * @Time: 2019/12/21 22:28
 */
public class RSACryptoExample extends InstallBCSupport{


    @Test
    public void rsaOAEP() throws Exception {
        KeyPair keyPair = RSAKeyPairGenerator.generateRSAKeyPair(2048);
        byte[] data = "我是对称加密密钥的key，快加密保护我".getBytes("UTF-8");

        // rsa_oaep加密
        byte[] plaintext = RSACrypter.encryptByRsaOaep(data,keyPair.getPublic());

        // rsa_oaep解密
        byte[] ciphertext = RSACrypter.decryptByRsaOaep(plaintext, keyPair.getPrivate());
        Assert.assertArrayEquals(data,ciphertext);

    }


}
