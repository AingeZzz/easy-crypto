package com.ainge.easycrypto.example;

import com.ainge.easycrypto.certificate.JcaX509Certificate;
import com.ainge.easycrypto.cms.envelopeddata.EnvelopedData;
import com.ainge.easycrypto.cms.envelopeddata.JavaMailSMIMEEnvelopedData;
import com.ainge.easycrypto.generators.RSAKeyPairGenerator;
import com.ainge.easycrypto.generators.SM2KeypairGenerator;
import com.ainge.easycrypto.util.ByteUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.Streams;
import org.junit.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.mail.internet.MimeBodyPart;
import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

/**
 * @author: Ainge
 * @Time: 2020/1/5 19:01
 */
public class EnvelopedDataExample extends InstallBCSupport {


    /**
     * 简单演示一个数字信封的使用方式：每一个接收者，都有对应的RecipientInfo Type
     * <p>
     * 实际的应用场景，我们可能还需要验证数字证书
     * 数字信封加密的时候：可能需要验证数字证书的有效期，证书链，CRL，OCSP等，具体根据业务场景需求
     * 数字信封解密的时候，一般不对数字证书进行校验了
     *
     * @throws Exception
     */
    @Test
    public void envelopedDataExample() throws Exception {

        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "CN")
                .addRDN(BCStyle.ST, "Guangdong")
                .addRDN(BCStyle.L, "Guangzhou")
                .addRDN(BCStyle.O, "谜之家")
                .addRDN(BCStyle.CN, "谜之家根CA");
        X500Name rootSubject = x500NameBld.build();


        CMSEnvelopedDataGenerator envGen = EnvelopedData.getCMSEnvelopedDataGenerator();

        KeyPair recipientRsaKp = RSAKeyPairGenerator.generateRSAKeyPair(2048);
        X509Certificate recipientRsaCert = JcaX509Certificate.convertX509CertificateHolder(JcaX509Certificate.createTrustAnchor(recipientRsaKp, "SHA256withRSA", rootSubject, 7 * 24));
        // KeyTransRecipient Type
        EnvelopedData.addKeyTransRecipient(envGen, recipientRsaCert);

        KeyPair originatorSM2Kp = SM2KeypairGenerator.generateSM2KeyPair();
        X509Certificate originatorEcCert = JcaX509Certificate.convertX509CertificateHolder(JcaX509Certificate.createTrustAnchor(originatorSM2Kp, "SM3WithSM2", rootSubject, 7 * 24));

        KeyPair recipientSM2Kp = SM2KeypairGenerator.generateSM2KeyPair();
        X509Certificate recipientEcCert = JcaX509Certificate.convertX509CertificateHolder(JcaX509Certificate.createTrustAnchor(recipientSM2Kp, "SM3WithSM2", rootSubject, 7 * 24));
        // KeyAgreeRecipient Type
        EnvelopedData.addKeyAgreeRecipient(envGen, originatorSM2Kp.getPrivate(), originatorEcCert, recipientEcCert);

        byte[] keyID = Strings.toByteArray("AingeZhu_KeyID");
        SecretKey wrappingKey = new SecretKeySpec(ByteUtil.randomBytes(16), "AES");
        // KEKRecipient Type
        EnvelopedData.addKEKRecipient(envGen, keyID, wrappingKey);

        char[] passwd = "AingeZhu_password".toCharArray();
        // PasswordRecipient Type
        EnvelopedData.addPasswordRecipient(envGen, passwd, Strings.toByteArray("Random_Salt"), 2048);


        // 封装成数字信封
        byte[] msg = Strings.toByteArray("Hello, world!");
        CMSEnvelopedData cmsEnvelopedData = EnvelopedData.envelopedDataMsg(envGen, msg);


        // 所有接收者，一个个解开属于自己的数字信封
        byte[] envEnc = cmsEnvelopedData.getEncoded();

        byte[] keyTransRecovered = EnvelopedData.extractUsingKeyTransRecipient(envEnc, recipientRsaKp.getPrivate(), recipientRsaCert);
        System.err.println("KeyTransRecipient Type，Decode：" + Strings.fromByteArray(keyTransRecovered));

        byte[] keyAgreeRecovered = EnvelopedData.extractUsingKeyAgreeRecipient(envEnc, recipientSM2Kp.getPrivate(), recipientEcCert);
        System.err.println("KeyAgreeRecipient Type，Decode：" + Strings.fromByteArray(keyAgreeRecovered));

        byte[] kekRecovered = EnvelopedData.extractUsingKEKRecipient(envEnc, keyID, wrappingKey);
        System.err.println("KEKRecipient Type，Decode：" + Strings.fromByteArray(kekRecovered));

        byte[] passwordRecovered = EnvelopedData.extractUsingPasswordRecipient(envEnc, passwd);
        System.err.println("PasswordRecipient Type，Decode：" + Strings.fromByteArray(passwordRecovered));


        CMSEnvelopedDataStreamGenerator envStreamGen = EnvelopedData.getCMSEnvelopedDataStreamGenerator();

        EnvelopedData.addKeyTransRecipient(envStreamGen, recipientRsaCert);
        // 流方式加密
        byte[] envelopedDataMsg = EnvelopedData.envelopedDataMsg(envStreamGen, msg);
        CMSTypedStream cmsContent = EnvelopedData.streamExtractUsingKeyTransRecipient(envelopedDataMsg, recipientRsaKp.getPrivate(), recipientRsaCert);
        System.err.println("KeyTransRecipient Type，Stream Api Decode：" + Strings.fromByteArray(Streams.readAll(cmsContent.getContentStream())));
    }

    @Test
    public void javaMailSMIMEEnvelopedData() throws Exception  {
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "CN")
                .addRDN(BCStyle.ST, "Guangdong")
                .addRDN(BCStyle.L, "Guangzhou")
                .addRDN(BCStyle.O, "谜之家")
                .addRDN(BCStyle.CN, "谜之家根CA");
        X500Name rootSubject = x500NameBld.build();

        String contentTransferEncoding = "BASE64";
        String base64Data = Base64.toBase64String("Hello,world!!!".getBytes("utf-8"));
        StringBuffer sb = new StringBuffer();
        sb.append("Content-Type: text/plain; name=null;charset=utf-8");
        sb.append("\r\n");
        sb.append("Content-Transfer-Encoding:" + contentTransferEncoding);
        sb.append("\r\n");
        sb.append("Content-Disposition: inline; filename=test.txt");
        sb.append("\r\n");
        sb.append("\r\n");
        sb.append(base64Data);
        byte[] bodyPart = sb.toString().getBytes("utf-8");

        KeyPair keyPair = RSAKeyPairGenerator.generateRSAKeyPair(2048);
        X509CertificateHolder selfSignedCert = JcaX509Certificate.createTrustAnchor(keyPair, "SHA256WithRSA", rootSubject, 7 * 24);
        X509Certificate x509Certificate = JcaX509Certificate.convertX509CertificateHolder(selfSignedCert);
        MimeBodyPart mimeBodyPart = new MimeBodyPart(new ByteArrayInputStream(bodyPart));

        MimeBodyPart encryptedMessage = JavaMailSMIMEEnvelopedData.createEnveloped(x509Certificate, mimeBodyPart);

        MimeBodyPart result = JavaMailSMIMEEnvelopedData.decryptEnveloped(encryptedMessage, x509Certificate, keyPair.getPrivate());
        System.out.println(result.getContent().toString());


    }


}
