package com.ainge.easycrypto.example;

import com.ainge.easycrypto.certificate.JcaX509Certificate;
import com.ainge.easycrypto.generators.RSAKeyPairGenerator;
import com.ainge.easycrypto.keystore.KeyStoreCertInfos;
import com.ainge.easycrypto.keystore.KeyStoreUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.Test;

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * @author: Ainge
 * @Time: 2019/12/26 23:44
 */
public class KeyStoreExample extends InstallBCSupport {


    @Test
    public void genKeyStore()throws Exception {
        String jksFileName = "~/Desktop/test.jks";
        String pfx12FileName = "~/Desktop/test.p12";
        KeyStoreCertInfos keyStoreCertInfos = genKeyStoreCertInfos();
        // KeyStoreUtils.generateJKS();
        // TODO Ainge ,先休息


    }

    public static KeyStoreCertInfos genKeyStoreCertInfos()throws Exception{
        // 签发证书
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "CN")
                .addRDN(BCStyle.ST, "Guangdong")
                .addRDN(BCStyle.L, "Guangzhou")
                .addRDN(BCStyle.O, "谜之家")
                .addRDN(BCStyle.CN, "谜之家根CA");
        X500Name rootSubject = x500NameBld.build();

        KeyPair keyPair = RSAKeyPairGenerator.generateRSAKeyPair(2048);
        String alg = "SHA256WithRSA";
        // 证书有效期 1年 24 * 365
        int certValidity = 24 * 365;
        // 1.签发root ca
        X509CertificateHolder trustAnchor = JcaX509Certificate.createTrustAnchor(keyPair, alg, rootSubject, certValidity);

        // 子ca主题
        X500Name subCaSubject = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "CN")
                .addRDN(BCStyle.ST, "Guangdong")
                .addRDN(BCStyle.L, "Guangzhou")
                .addRDN(BCStyle.O, "谜之家")
                .addRDN(BCStyle.CN, "谜之家二级CA").build();
        // 2.签发子CA证书
        KeyPair subCAKeyPair = RSAKeyPairGenerator.generateRSAKeyPair(2048);
        int followingCACerts = 0; //该子CA不允许再签发下级CA，只能签发终端实体证书
        X509CertificateHolder subCaHolder = JcaX509Certificate.createIntermediateCertificate(trustAnchor, keyPair.getPrivate(), alg, subCAKeyPair.getPublic(), subCaSubject, certValidity, followingCACerts);
        // 终端用户
        X500Name userSubject = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "CN")
                .addRDN(BCStyle.ST, "GuangXi")
                .addRDN(BCStyle.L, "Nanning")
                .addRDN(BCStyle.O, "谜之家")
                .addRDN(BCStyle.CN, "AingeZzz").build();
        KeyPair userKeyPair = RSAKeyPairGenerator.generateRSAKeyPair(2048);
        // 3.为AingeZzz签发一张代码签名证书
        X509CertificateHolder userCertificateHolder = JcaX509Certificate.createSpecialPurposeEndEntity(subCaHolder, subCAKeyPair.getPrivate(), alg, userKeyPair.getPublic(), userSubject, certValidity, KeyPurposeId.id_kp_codeSigning);

        // 4.代码签名证书
        X509Certificate x509Certificate = JcaX509Certificate.convertX509CertificateHolder(userCertificateHolder);

        // 证书链
        Certificate[] chain = {
                JcaX509Certificate.convertX509CertificateHolder(trustAnchor),
                JcaX509Certificate.convertX509CertificateHolder(subCaHolder)
                ,x509Certificate};
        return new KeyStoreCertInfos(x509Certificate,chain,userKeyPair.getPrivate());
    }


}
