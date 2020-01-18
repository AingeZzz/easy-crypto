package com.ainge.easycrypto.example;

import com.ainge.easycrypto.generators.PGPKeyPairGenerator;
import com.ainge.easycrypto.generators.RSAKeyPairGenerator;
import com.ainge.easycrypto.pgp.PGPKeyHolder;
import com.ainge.easycrypto.pgp.PGPSignature;
import com.ainge.easycrypto.pgp.PGPUtils;
import com.ainge.easycrypto.pgp.PersonalKey;

import org.junit.Assert;
import org.junit.Test;

import java.security.KeyPair;
import java.util.Arrays;
import java.util.Optional;

/**
 * @author: Ainge
 * @Time: 2020/1/12 22:14
 */
public class PGPKeyPairGenExample extends InstallBCSupport{


    // 密钥对产生，以及转为X509证书，并通过自定义扩展，桥接起来。
    @Test
    public void keyPairGenTest() throws Exception {

        String identity = "Ainge (for_email) <zaj9404@163.com>";
        KeyPair masterKeyPair = RSAKeyPairGenerator.generateRSAKeyPair(2048);
        KeyPair subKeyPair = RSAKeyPairGenerator.generateRSAKeyPair(2048);
        char[] passphrase = "123456".toCharArray();
        byte[][] bytes = PGPKeyPairGenerator.generateKeyRing(identity,passphrase , masterKeyPair, subKeyPair);
        System.out.println(Arrays.toString(bytes[0]));
        System.out.println(Arrays.toString(bytes[1]));
        Optional<PGPKeyHolder> pgpCoderKey = PGPUtils.readPublicKey(bytes[1]);
        PGPKeyHolder pub = pgpCoderKey.get();
        PersonalKey personalKey = PersonalKey.load(bytes[0], passphrase);
        String pemPrint = CertSignerExample.JcaPEMPrint(personalKey.getBridgeCertificate());
        System.out.println(pemPrint);
    }

    @Test
    public void pgpSignTest() throws Exception {
        String identity = "Ainge (for_email) <zaj9404@163.com>";
        KeyPair masterKeyPair = RSAKeyPairGenerator.generateRSAKeyPair(2048);
        KeyPair subKeyPair = RSAKeyPairGenerator.generateRSAKeyPair(2048);
        char[] passphrase = "123456".toCharArray();
        // bytes[0] = 私钥环，也会包含公钥，需要字节保存，也需要密码 ；byte[1]公钥环，只含私钥对应的公钥，可以公开
        byte[][] bytes = PGPKeyPairGenerator.generateKeyRing(identity,passphrase , masterKeyPair, subKeyPair);
        PersonalKey personalKey = PersonalKey.load(bytes[0], passphrase);

        byte[] signData = "签名原文123@#¥%……&（".getBytes("UTF-8");

        // 签名
        byte[] signedObject = PGPSignature.createSignedObject(1, personalKey.getmSignKey().getPrivateKey(), signData);
        // 验签
        boolean verifySignedObject = PGPSignature.verifySignedObject(personalKey.getmSignKey().getPublicKey(), signedObject);
        Assert.assertTrue(verifySignedObject);
        // 验签
        Optional<PGPKeyHolder> pgpCoderKey = PGPUtils.readPublicKey(bytes[1]);
        PGPKeyHolder pub = pgpCoderKey.get();
        verifySignedObject = PGPSignature.verifySignedObject(pub.getSignKey(), signedObject);
        Assert.assertTrue(verifySignedObject);
    }



}
