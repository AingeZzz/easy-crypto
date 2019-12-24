package com.ainge.easycrypto.example;


import com.ainge.easycrypto.asymmetric.RSACrypter;
import com.ainge.easycrypto.generators.RSAKeyPairGenerator;
import com.ainge.easycrypto.util.ByteUtil;
import org.bouncycastle.util.Strings;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.spec.MGF1ParameterSpec;

/**
 * @author: Ainge
 * @Time: 2019/12/21 22:28
 */
public class RSACryptoExample extends InstallBCSupport {


    @Test
    public void rsaOAEP() throws Exception {
        KeyPair keyPair = RSAKeyPairGenerator.generateRSAKeyPair(2048);
        byte[] data = "我是对称加密密钥的key，快加密保护我".getBytes("UTF-8");

        // rsa_oaep加密
        byte[] plaintext = RSACrypter.encryptByRsaOaep(data, keyPair.getPublic());

        // rsa_oaep解密
        byte[] ciphertext = RSACrypter.decryptByRsaOaep(plaintext, keyPair.getPrivate());
        Assert.assertArrayEquals(data, ciphertext);

    }

    @Test
    public void rsaWrapKey() throws Exception {
        KeyPair keyPair = RSAKeyPairGenerator.generateRSAKeyPair(2048);
        // 产生需要被包装的AES key
        String keyAlgorithm = "AES";
        SecretKeySpec aes = new SecretKeySpec(ByteUtil.randomBytes(16), keyAlgorithm);

        // 包装后的key
        byte[] wrappedKey = RSACrypter.keyWrapOAEP(keyPair.getPublic(), aes);
        // 还原
        SecretKey secretKey = RSACrypter.keyUnwrapOAEP(keyPair.getPrivate(), wrappedKey, keyAlgorithm);
        // 验证
        Assert.assertArrayEquals(aes.getEncoded(), secretKey.getEncoded());
        // ParamsExample
        OAEPParameterSpec oaepSpec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                new PSource.PSpecified(Strings.toByteArray("Ainge Label For Test")));
        byte[] keyWrapOAEP = RSACrypter.keyWrapOAEP(keyPair.getPublic(), oaepSpec, aes);
        SecretKey secretKey1 = RSACrypter.keyUnwrapOAEP(keyPair.getPrivate(), oaepSpec, keyWrapOAEP, keyAlgorithm);
        // verify
        Assert.assertArrayEquals(aes.getEncoded(), secretKey1.getEncoded());
    }


}
