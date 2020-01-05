package com.ainge.easycrypto.cms.signeddata;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.mime.Headers;
import org.bouncycastle.mime.MimeParser;
import org.bouncycastle.mime.MimeParserContext;
import org.bouncycastle.mime.MimeParserProvider;
import org.bouncycastle.mime.smime.SMIMESignedWriter;
import org.bouncycastle.mime.smime.SMimeParserListener;
import org.bouncycastle.mime.smime.SMimeParserProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.security.PrivateKey;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * @author: Ainge
 * @Time: 2020/1/5 15:34
 */
public class SMIMESignedData {

    /**
     * Content-Transfer-Encoding支持以下数据格式：BASE64, QUOTED-PRINTABLE, 8BIT, 7BIT, BINARY, X-TOKEN
     */
    public static final String default_content_transfer_encoding = "7bit";

    /**
     * 提供S/MIME功能属性的基本方法。
     *
     * @return 具有其他属性的AttributeTable
     */
    public static AttributeTable generateSMIMECapabilities() {
        ASN1EncodableVector signedAttrs = new ASN1EncodableVector();
        SMIMECapabilityVector caps = new SMIMECapabilityVector();
        caps.addCapability(SMIMECapability.aES128_CBC);
        caps.addCapability(SMIMECapability.aES192_CBC);
        caps.addCapability(SMIMECapability.aES256_CBC);
        caps.addCapability(SMIMECapability.preferSignedData);
        signedAttrs.add(new SMIMECapabilitiesAttribute(caps));
        return new AttributeTable(signedAttrs);
    }

    /**
     * Create a multipart/signed for the body part in message.
     *
     * @param signingKey  签名私钥
     * @param signingCert 私钥对应的公钥证书
     * @param alg         签名算法
     * @param message     待签名数据body
     * @return a byte[] containing a multipart/signed MIME object.
     */
    public static byte[] createSignedMultipart(PrivateKey signingKey, X509CertificateHolder signingCert, String alg, byte[] message) throws OperatorCreationException, CMSException, IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        SMIMESignedWriter.Builder sigBldr = new SMIMESignedWriter.Builder();
        sigBldr.addCertificate(signingCert);
        sigBldr.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder()
                .setProvider("BC").setSignedAttributeGenerator(generateSMIMECapabilities())
                .build(alg, signingKey, signingCert));
        SMIMESignedWriter sigWrt = sigBldr.build(bOut);
        OutputStream out = sigWrt.getContentStream();
        out.write(message);
        out.close();
        return bOut.toByteArray();
    }

    /**
     * 验证与signerCert关联的signerInfo，然后将内容写入contentStream。
     *
     * @param multiPart               输入流，其中包含要检查的已签名multiPart
     * @param contentTransferEncoding 内容传输编码
     * @param signerCert              签名私钥对应的公钥证书
     * @param contentStream           输出流，用于接收签名的内容
     * @return 验证通过返回true，否则false
     */
    public static boolean verifySignedMultipart(InputStream multiPart, String contentTransferEncoding, X509CertificateHolder signerCert, OutputStream contentStream) throws IOException {
        if (contentTransferEncoding == null || contentTransferEncoding.trim().isEmpty()) {
            contentTransferEncoding = default_content_transfer_encoding;
        }
        AtomicBoolean isVerified = new AtomicBoolean(false);
        MimeParserProvider provider = new SMimeParserProvider(contentTransferEncoding, new BcDigestCalculatorProvider());
        MimeParser parser = provider.createParser(multiPart);

        parser.parse(new SMimeParserListener() {
            public void content(MimeParserContext parserContext, Headers headers, InputStream inputStream) throws IOException {
                byte[] content = Streams.readAll(inputStream);
                contentStream.write(content);
            }

            public void signedData(MimeParserContext parserContext, Headers headers, Store certificates, Store CRLs, Store attributeCertificates, SignerInformationStore signers) throws CMSException {
                SignerInformation signerInfo = signers.get(new SignerId(signerCert.getIssuer(), signerCert.getSerialNumber()));
                try {
                    isVerified.set(signerInfo.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(signerCert)));
                } catch (Exception e) {
                    throw new CMSException("unable to process signerInfo: " + e.getMessage(), e);
                }
            }
        });

        return isVerified.get();
    }

}
