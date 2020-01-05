package com.ainge.easycrypto.example;

import com.ainge.easycrypto.certificate.JcaX509Certificate;
import com.ainge.easycrypto.cms.signeddata.JavaMailSMIMESignedData;
import com.ainge.easycrypto.cms.signeddata.SMIMESignedData;
import com.ainge.easycrypto.cms.signeddata.SignedData;
import com.ainge.easycrypto.generators.ECKeyPairGenerator;
import com.ainge.easycrypto.generators.SM2KeypairGenerator;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMultipart;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.util.Map;

/**
 * 本测试都是简单测试，如果需要验证错误的情况。
 * 可以尝试自己按照SignedData的ASN1结构去组装数据进行验证。
 *
 * @author: Ainge
 * @Time: 2020/1/5 14:43
 */
public class SignedDataExample extends InstallBCSupport {


    // 不带原文的p7签名例子
    @Test
    public void signedDataDetached() throws Exception {
        // 原文
        byte[] msg = "hello world".getBytes("utf-8");
        // 签发证书
        Map<String, Object> infos = CertSignerExample.signCert(true);
        String alg = (String) infos.get(CertSignerExample._alg);
        X509CertificateHolder certificateHolder = (X509CertificateHolder) infos.get(CertSignerExample._userCert);
        KeyPair keyPair = (KeyPair) infos.get(CertSignerExample._userKeyPair);
        // p7签名不带原文
        CMSSignedData signedData = SignedData.createSignedData(keyPair.getPrivate(), alg, certificateHolder, msg, false);
        // p7验证不带原文的签名
        SignedData.verifySignedDetached(signedData.getEncoded(), msg);
        // 副本签名
        X509CertificateHolder subCert = (X509CertificateHolder) infos.get(CertSignerExample._subCert);
        KeyPair subKeyPair = (KeyPair) infos.get(CertSignerExample._subKeyPair);
        CMSSignedData counterSignature = SignedData.addCounterSignature(signedData, subKeyPair.getPrivate(), alg, subCert);
        // 只验证签名者签名，不验证副本签名
        SignedData.verifySignedDetached(counterSignature.getEncoded(), msg);
        // 验证所有签名，包括副本签名
        SignedData.verifyAllSigners(counterSignature);

    }

    // 带原文的P7签名
    @Test
    public void signedDataEncapsulate() throws Exception {
        // 原文
        byte[] msg = "hello world".getBytes("utf-8");
        // 签发证书
        Map<String, Object> infos = CertSignerExample.signCert(false);
        String alg = (String) infos.get(CertSignerExample._alg);
        X509CertificateHolder certificateHolder = (X509CertificateHolder) infos.get(CertSignerExample._userCert);
        KeyPair keyPair = (KeyPair) infos.get(CertSignerExample._userKeyPair);
        // p7签名不带原文
        CMSSignedData signedData = SignedData.createSignedData(keyPair.getPrivate(), alg, certificateHolder, msg, true);
        // p7验证不带原文的签名
        SignedData.verifySignedEncapsulated(signedData.getEncoded());
        // 副本签名
        X509CertificateHolder subCert = (X509CertificateHolder) infos.get(CertSignerExample._subCert);
        KeyPair subKeyPair = (KeyPair) infos.get(CertSignerExample._subKeyPair);
        CMSSignedData counterSignature = SignedData.addCounterSignature(signedData, subKeyPair.getPrivate(), alg, subCert);
        // 只验证签名者签名，不验证副本签名
        SignedData.verifySignedEncapsulated(counterSignature.getEncoded());
        // 验证所有签名，包括副本签名
        SignedData.verifyAllSigners(counterSignature);

    }

    @Test
    public void sMIMESignedData() throws Exception {
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

        KeyPair selfSignedKp = ECKeyPairGenerator.generateECKeyPair();
        X509CertificateHolder selfSignedCert = JcaX509Certificate.createTrustAnchor(selfSignedKp, "SHA256WithECDSA", rootSubject, 7 * 24);
        byte[] data = SMIMESignedData.createSignedMultipart(selfSignedKp.getPrivate(), selfSignedCert, "SHA256WithECDSA", bodyPart);

        ByteArrayOutputStream contentStream = new ByteArrayOutputStream();
        System.out.println("verified: " + SMIMESignedData.verifySignedMultipart(new ByteArrayInputStream(data), contentTransferEncoding, selfSignedCert, contentStream));
        String result = Strings.fromByteArray(contentStream.toByteArray());
        System.out.println(result);
        System.out.println("base64 decode: " + Strings.fromByteArray(Base64.decode(result.getBytes("utf-8"))));

    }
    @Test
    public void javaSMIMESignedData() throws Exception {
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

        KeyPair selfSignedKp = SM2KeypairGenerator.generateSM2KeyPair();
        X509CertificateHolder selfSignedCert = JcaX509Certificate.createTrustAnchor(selfSignedKp, "SM3withSM2", rootSubject, 7 * 24);
        MimeBodyPart mimeBodyPart = new MimeBodyPart(new ByteArrayInputStream(bodyPart));
        MimeMultipart signedMM = JavaMailSMIMESignedData.createSignedMultipart(selfSignedKp.getPrivate(), selfSignedCert, "SM3withSM2", mimeBodyPart);

        ByteArrayOutputStream contentStream = new ByteArrayOutputStream();
        System.out.println("verified: " + JavaMailSMIMESignedData.verifySignedMultipart(signedMM,selfSignedCert));
        String result = signedMM.getBodyPart(0).getContent().toString();
        System.out.println(result);
    }


}
