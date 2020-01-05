package com.ainge.easycrypto.cms.signeddata;


import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;

/**
 * @author: Ainge
 * @Time: 2020/1/5 15:35
 */
public class JavaMailSMIMESignedData {

    /**
     * Create a multipart/signed for the body part in message.
     *
     * @param signingKey  签名私钥
     * @param signingCert 私钥对应的公钥证书
     * @param alg         签名算法
     * @param message     待签名数据body
     * @return a byte[] containing a multipart/signed MIME object.
     */
    public static MimeMultipart createSignedMultipart(PrivateKey signingKey, X509CertificateHolder signingCert, String alg, MimeBodyPart message) throws OperatorCreationException, SMIMEException {
        List<X509CertificateHolder> certList = new ArrayList<>();
        certList.add(signingCert);
        Store<X509CertificateHolder> certs = new CollectionStore<>(certList);

        SMIMESignedGenerator gen = new SMIMESignedGenerator();
        gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder()
                .setProvider("BC")
                .setSignedAttributeGenerator(SMIMESignedData.generateSMIMECapabilities())
                .build(alg, signingKey, signingCert));
        gen.addCertificates(certs);
        return gen.generate(message);
    }

    /**
     * Verify a MimeMultipart containing a multipart/signed object.
     *
     * @param signedMessage 签名数据
     * @param signerCert    签名证书
     * @return 验签通过返回true，否则false
     */
    public static boolean verifySignedMultipart(MimeMultipart signedMessage, X509CertificateHolder signerCert) throws GeneralSecurityException, OperatorCreationException, CMSException, MessagingException {

        SMIMESigned signedData = new SMIMESigned(signedMessage);
        SignerInformationStore signers = signedData.getSignerInfos();
        SignerInformation signer = signers.get(new SignerId(signerCert.getIssuer(), signerCert.getSerialNumber()));
        return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(signerCert));
    }

}
