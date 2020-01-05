package com.ainge.easycrypto.cms.envelopeddata;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;

/**
 * @author: Ainge
 * @Time: 2020/1/5 21:49
 */
public class JavaMailSMIMEEnvelopedData {

    /**
     * Create an application/pkcs7-mime from the body part in message.
     *
     * @param encryptionCert 接收者的公钥证书
     * @param message        byte[] 表示要加密的主体部分。
     * @return a MimeBodyPart containing a application/pkcs7-mime MIME object.
     */
    public static MimeBodyPart createEnveloped(X509Certificate encryptionCert, MimeBodyPart message) throws GeneralSecurityException, CMSException, SMIMEException {

        SMIMEEnvelopedGenerator envGen = new SMIMEEnvelopedGenerator();

        JcaAlgorithmParametersConverter paramsConverter = new JcaAlgorithmParametersConverter();
        // 写死算法，暂时只支持RSA证书。支持SM2参考EnvelopedData实现
        AlgorithmIdentifier oaepParams = paramsConverter.getAlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP,
                new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT));

        envGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(encryptionCert, oaepParams).setProvider("BC"));


        return envGen.generate(message, new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider("BC").build());
    }

    /**
     * 数字信封解密
     *
     * @param encryptedMessage 包含数据信封
     * @param recipientCert    接收者公钥证书
     * @param recipientKey     接收者私钥
     */
    public static MimeBodyPart decryptEnveloped(MimeBodyPart encryptedMessage, X509Certificate recipientCert, PrivateKey recipientKey) throws CMSException, MessagingException, SMIMEException {
        SMIMEEnveloped envData = new SMIMEEnveloped(encryptedMessage);
        RecipientInformationStore recipients = envData.getRecipientInfos();
        RecipientInformation recipient = recipients.get(new JceKeyTransRecipientId(recipientCert));
        return SMIMEUtil.toMimeBodyPart(recipient.getContent(new JceKeyTransEnvelopedRecipient(recipientKey).setProvider("BC")));
    }


}
