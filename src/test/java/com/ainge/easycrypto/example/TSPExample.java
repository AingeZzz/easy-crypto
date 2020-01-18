package com.ainge.easycrypto.example;

import com.ainge.easycrypto.certificate.JcaX509Certificate;
import com.ainge.easycrypto.cms.TimeStampProtocol;
import com.ainge.easycrypto.digest.MessageDigestCrypter;
import com.ainge.easycrypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

/**
 * 简单的时间戳例子
 *
 * @author: Ainge
 * @Time: 2020/1/18 17:50
 */
public class TSPExample extends InstallBCSupport{

    // 密钥对
    private KeyPair keyPair;
    // TSA证书
    private X509Certificate certificate;


    @Before
    public void setUp() throws Exception {
        keyPair = RSAKeyPairGenerator.generateRSAKeyPair(1024);
        // 时间戳
        KeyPurposeId keyPurpose = KeyPurposeId.id_kp_timeStamping;
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "CN")
                .addRDN(BCStyle.ST, "Guangdong")
                .addRDN(BCStyle.L, "Guangzhou")
                .addRDN(BCStyle.O, "谜之家")
                .addRDN(BCStyle.CN, "谜之家TSA时间戳");
        X500Name subject = x500NameBld.build();
        X509CertificateHolder holder = JcaX509Certificate.createSpecialPurposeTrustAnchor(keyPair, "SHA256WithRSA", subject, 24 * 7, keyPurpose);
        certificate = JcaX509Certificate.convertX509CertificateHolder(holder);
    }


    @Test
    public void tspClientExample() throws Exception {


        // 用户(时间戳需求方)将电子数据(文件)使用摘要算法计算出摘要值，
        byte[] ori = "我是电子数据文件原文".getBytes("utf-8");
        byte[] sha256Hash = MessageDigestCrypter.computeDigest("SHA256", ori);
        // 用户组成时间戳请求包TimeStampReq
        byte[] tspRequest = TimeStampProtocol.createTspRequest(sha256Hash);

        // 用户将请求包TimeStampReq发送给TSA（时间戳服务器）
        ASN1ObjectIdentifier tsaPolicy = new ASN1ObjectIdentifier("1.3.6.1.4.1.601.10.3.1");
        byte[] tspResponse = TimeStampProtocol.createTspResponse(keyPair.getPrivate(), certificate, BigInteger.ONE, tsaPolicy, tspRequest);

        // 用户接收到响应包TimeStampResp，并且验证该响应
        boolean verifyTspResponse = TimeStampProtocol.verifyTspResponse(certificate, tspResponse);
        Assert.assertTrue(verifyTspResponse);


    }


}
