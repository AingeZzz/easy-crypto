package com.ainge.easycrypto.cms.envelopeddata;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.mime.Headers;
import org.bouncycastle.mime.MimeParser;
import org.bouncycastle.mime.MimeParserContext;
import org.bouncycastle.mime.MimeParserProvider;
import org.bouncycastle.mime.smime.SMIMEEnvelopedWriter;
import org.bouncycastle.mime.smime.SMimeParserListener;
import org.bouncycastle.mime.smime.SMimeParserProvider;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;

/**
 * @author: Ainge
 * @Time: 2020/1/5 21:48
 */
public class SMIMEEnvelopedData {

    /**
     * Content-Transfer-Encoding支持以下数据格式：BASE64, QUOTED-PRINTABLE, 8BIT, 7BIT, BINARY, X-TOKEN
     */
    public static final String default_content_transfer_encoding = "7bit";


    /**
     * Create an application/pkcs7-mime for the body part in message.
     *
     * @param encryptionCert 接收者公钥证书
     * @param message        原始数据
     * @return a byte[] containing a application/pkcs7-mime MIME object.
     */
    public static byte[] createEnveloped(X509Certificate encryptionCert, byte[] message) throws GeneralSecurityException, CMSException, IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        SMIMEEnvelopedWriter.Builder envBldr = new SMIMEEnvelopedWriter.Builder();

        JcaAlgorithmParametersConverter paramsConverter = new JcaAlgorithmParametersConverter();

        AlgorithmIdentifier oaepParams = paramsConverter.getAlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP,
                new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT));

        envBldr.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(encryptionCert, oaepParams).setProvider("BC"));
        SMIMEEnvelopedWriter sigWrt = envBldr.build(bOut, new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider("BC").build());
        OutputStream out = sigWrt.getContentStream();
        out.write(message);
        out.close();
        return bOut.toByteArray();
    }

    /**
     * 在application/pkcs7-mime消息中解密加密的内容，然后将内容写入contentStream。
     *
     * @param encryptedPart           输入流，包含数字信封
     * @param contentTransferEncoding 内容传输编码
     * @param recipientCert           接收者的公钥证书
     * @param recipientKey            接收者证书对应的私钥
     * @param contentStream           输出流，接收解密的数据
     */
    public static void decryptEnveloped(InputStream encryptedPart, String contentTransferEncoding, X509Certificate recipientCert, PrivateKey recipientKey, OutputStream contentStream) throws IOException {
        if (contentTransferEncoding == null || contentTransferEncoding.trim().isEmpty()) {
            contentTransferEncoding = default_content_transfer_encoding;
        }
        MimeParserProvider provider = new SMimeParserProvider(contentTransferEncoding, new BcDigestCalculatorProvider());
        MimeParser parser = provider.createParser(encryptedPart);

        parser.parse(new SMimeParserListener() {
            public void envelopedData(MimeParserContext parserContext, Headers headers, OriginatorInformation originator, RecipientInformationStore recipients) throws IOException, CMSException {
                RecipientInformation recipInfo = recipients.get(new JceKeyTransRecipientId(recipientCert));
                byte[] content = recipInfo.getContent(new JceKeyTransEnvelopedRecipient(recipientKey));
                contentStream.write(content);
            }
        });

    }


}
