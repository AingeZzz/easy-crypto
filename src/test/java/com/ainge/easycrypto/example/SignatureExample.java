package com.ainge.easycrypto.example;

import com.ainge.easycrypto.generators.ECKeyPairGenerator;
import com.ainge.easycrypto.generators.RSAKeyPairGenerator;
import com.ainge.easycrypto.generators.SM2KeypairGenerator;
import com.ainge.easycrypto.signature.ECDSASignature;
import com.ainge.easycrypto.signature.RSASignature;
import com.ainge.easycrypto.signature.SM2Signature;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.junit.Assert;
import org.junit.Test;

import java.security.KeyPair;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * 记住一句话：
 * 私钥签名，公钥验签；
 * 公钥加密，私钥解密。
 *
 * @author: Ainge
 * @Time: 2019/12/21 22:38
 */
public class SignatureExample extends InstallBCSupport {


    @Test
    public void rsaSign() throws Exception {
        KeyPair keyPair = RSAKeyPairGenerator.generateRSAKeyPair(1024);
        // 原文
        byte[] original = "我是原文，快对我签名，防止传输被篡改数据".getBytes("utf-8");
        // 签名
        byte[] signature_p1 = RSASignature.generatePKCS1dot5Signature(keyPair.getPrivate(), original);
        // 验签..
        boolean result = RSASignature.verifyPKCS1dot5Signature(keyPair.getPublic(), original, signature_p1);
        Assert.assertTrue(result);
        // 签名
        byte[] rsapssSignature = RSASignature.generateRSAPSSSignature(keyPair.getPrivate(), original);
        // 验签
        boolean b = RSASignature.verifyRSAPSSSignature(keyPair.getPublic(), original, rsapssSignature);
        Assert.assertTrue(b);
        // 签名
        PSSParameterSpec pssSpec = new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1);
        byte[] signature = RSASignature.generateRSAPSSSignature(keyPair.getPrivate(), pssSpec, original);
        // 验证签名
        boolean b1 = RSASignature.verifyRSAPSSSignature(keyPair.getPublic(), pssSpec, original, signature);
        Assert.assertTrue(b1);
    }

    @Test
    public void ecDsaSign() throws Exception {
        // 只测试一种曲线，其他曲线自行测试
        KeyPair keyPair = ECKeyPairGenerator.generateECKeyPair();
        // 原文
        byte[] original = "我是原文，快对我签名，防止传输被篡改数据".getBytes("utf-8");
        // 签名
        byte[] signature = ECDSASignature.generateECDSASignature(keyPair.getPrivate(), original);
        // 验签
        boolean result = ECDSASignature.verifyECDSASignature(keyPair.getPublic(), original, signature);
        Assert.assertTrue(result);
    }

    /**
     * SM2是国密算法，具有密钥短，运算速度快短优势
     *
     * @throws Exception
     */
    @Test
    public void sm2Sign() throws Exception {
        KeyPair keyPair = SM2KeypairGenerator.generateSM2KeyPair();
        // 原文
        byte[] original = "我是原文，快对我签名，防止传输被篡改数据".getBytes("utf-8");
        byte[] sm2Signature = SM2Signature.generateSM2Signature(keyPair.getPrivate(), original);
        // 验证签名
        boolean result = SM2Signature.verifySM2Signature(keyPair.getPublic(), original, sm2Signature);
        Assert.assertTrue(result);
        // SM2ParamSpecExample
        byte[] id = "AingeZhu@163.com".getBytes("utf-8");
        SM2ParameterSpec sm2ParameterSpec = new SM2ParameterSpec(id);
        // 签名
        byte[] signature = SM2Signature.generateSM2Signature(keyPair.getPrivate(), sm2ParameterSpec, original);
        // 验签
        boolean result1 = SM2Signature.verifySM2Signature(keyPair.getPublic(), sm2ParameterSpec, original, signature);
        Assert.assertTrue(result1);
    }


}
