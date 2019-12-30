package com.ainge.easycrypto.example;

import com.ainge.easycrypto.certificate.JcaX509Certificate;
import com.ainge.easycrypto.certreq.JcaPKCS10;
import com.ainge.easycrypto.generators.RSAKeyPairGenerator;
import com.ainge.easycrypto.generators.SM2KeypairGenerator;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.security.KeyPair;
import java.security.cert.X509Certificate;


/**
 * 证书的ASN.1结构，来源于RFC 5280规范
 * <p>
 * Certificate  ::=  SEQUENCE  {
 * tbsCertificate       TBSCertificate,
 * signatureAlgorithm   AlgorithmIdentifier,
 * signatureValue       BIT STRING  }
 * <p>
 * TBSCertificate  ::=  SEQUENCE  {
 * version         [0]  EXPLICIT Version DEFAULT v1,
 * serialNumber         CertificateSerialNumber,
 * signature            AlgorithmIdentifier,
 * issuer               Name,
 * validity             Validity,
 * subject              Name,
 * subjectPublicKeyInfo SubjectPublicKeyInfo,
 * issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
 * -- If present, version MUST be v2 or v3
 * subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
 * -- If present, version MUST be v2 or v3
 * extensions      [3]  EXPLICIT Extensions OPTIONAL
 * -- If present, version MUST be v3
 * }
 * <p>
 * Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
 * <p>
 * CertificateSerialNumber  ::=  INTEGER
 * <p>
 * Validity ::= SEQUENCE {
 * notBefore      Time,
 * notAfter       Time }
 * <p>
 * Time ::= CHOICE {
 * utcTime        UTCTime,
 * generalTime    GeneralizedTime }
 * <p>
 * UniqueIdentifier  ::=  BIT STRING
 * <p>
 * SubjectPublicKeyInfo  ::=  SEQUENCE  {
 * algorithm            AlgorithmIdentifier,
 * subjectPublicKey     BIT STRING  }
 * <p>
 * Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
 * <p>
 * Extension  ::=  SEQUENCE  {
 * extnID      OBJECT IDENTIFIER,
 * critical    BOOLEAN DEFAULT FALSE,
 * extnValue   OCTET STRING
 * -- contains the DER encoding of an ASN.1 value
 * -- corresponding to the extension type identified
 * -- by extnID
 * }
 */

/**
 * 演示：
 * 1.签发一张CA ROOT 证书
 * 2.签发一张子 CA 证书
 * 3.签发一张实体用户证书
 *
 * @author: Ainge
 * @Time: 2019/12/23 23:06
 */
public class CertSignerExample extends InstallBCSupport {


    /**
     * 直接签发证书，后续还做根据P10证书请求签发证书
     */
    @Test
    public void signCaCert() throws Exception {
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

        // 4.输入代码签名证书
        X509Certificate x509Certificate = JcaX509Certificate.convertX509CertificateHolder(userCertificateHolder);
        System.out.println(JcaPEMPrint(x509Certificate));

    }


    @Test
    public void signCertByCertReq() throws Exception {
        // 1.先有有CA
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "CN")
                .addRDN(BCStyle.ST, "Guangdong")
                .addRDN(BCStyle.L, "Guangzhou")
                .addRDN(BCStyle.O, "谜之家")
                .addRDN(BCStyle.CN, "谜之家根CA");
        X500Name rootSubject = x500NameBld.build();

        KeyPair rootKeyPair = RSAKeyPairGenerator.generateRSAKeyPair(2048);
        String alg = "SHA256WithRSA";
        // 证书有效期 1年 24 * 365
        int certValidity = 24 * 365;
        // 签发root ca
        X509CertificateHolder trustAnchor = JcaX509Certificate.createTrustAnchor(rootKeyPair, alg, rootSubject, certValidity);

        // 2.用户自己产生证书请求(向CA机构请求签发SM2证书)
        KeyPair keyPair = SM2KeypairGenerator.generateSM2KeyPair();
        X500Name subject = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "CN")
                .addRDN(BCStyle.ST, "GuangXi")
                .addRDN(BCStyle.L, "Nanning")
                .addRDN(BCStyle.O, "谜之家")
                .addRDN(BCStyle.CN, "AingeZzz").build();

        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(
                        new GeneralName(
                                GeneralName.rfc822Name,
                                "aingezhu@163.com")));
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        extGen.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));

        Extensions extensions = extGen.generate();
        PKCS10CertificationRequest certificationRequest = JcaPKCS10.createPKCS10(keyPair, "SM3WithSM2", subject, extensions);
        byte[] certReq = certificationRequest.getEncoded();

        // 3.用户把证书请求给到CA机构，CA机构对用户进行审核，签发证书
        X509CertificateHolder x509CertificateHolder = JcaX509Certificate.createEndEntity(trustAnchor, rootKeyPair.getPrivate(), alg, certValidity, certReq);
        X509Certificate x509Certificate = JcaX509Certificate.convertX509CertificateHolder(x509CertificateHolder);
        System.out.println(JcaPEMPrint(x509Certificate));

    }


    public static String JcaPEMPrint(Object object) throws Exception {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        JcaPEMWriter pemWrt = new JcaPEMWriter(new OutputStreamWriter(bOut));
        pemWrt.writeObject(object);
        pemWrt.close();
        bOut.close();
        return new String(bOut.toByteArray(), "utf-8");
    }

}
