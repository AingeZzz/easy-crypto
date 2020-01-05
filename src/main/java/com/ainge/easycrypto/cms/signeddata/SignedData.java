package com.ainge.easycrypto.cms.signeddata;

import com.ainge.easycrypto.exception.CryptoException;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.util.*;

/**
 * Cryptographic Message Syntax (CMS)
 * 规范： https://tools.ietf.org/html/rfc5652
 *
 * @author: Ainge
 * @Time: 2020/1/4 19:02
 */
public class SignedData {


    /**
     * 创建一个简单的SignedData结构
     *
     * @param signingKey  签名私钥
     * @param alg         签名算法
     * @param signingCert 签名私钥对应的公钥证书
     * @param msg         原始消息数据
     * @param encapsulate 是否将消息原文封装到签名当中，若这一参数为false，通常称生成的是 detached signature，表示签名和消息是分开存放的。
     * @return 包含SignedData的CMSSignedData对象
     */
    public static CMSSignedData createSignedData(PrivateKey signingKey, String alg, X509CertificateHolder signingCert, byte[] msg, boolean encapsulate) throws CMSException, OperatorCreationException {
        ContentSigner contentSigner = new JcaContentSignerBuilder(alg).setProvider("BC").build(signingKey);
        DigestCalculatorProvider digestCalcProvider = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        // 创建SignerInfoGenerator
        SignerInfoGenerator signerInfoGenerator = new SignerInfoGeneratorBuilder(digestCalcProvider).build(contentSigner, signingCert);
        // generator
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        gen.addSignerInfoGenerator(signerInfoGenerator);
        Store<X509CertificateHolder> certs = new CollectionStore<>(Collections.singletonList(signingCert));
        gen.addCertificates(certs);
        // 封装原始数据
        CMSTypedData typedMsg = new CMSProcessableByteArray(msg);
        return gen.generate(typedMsg, encapsulate);
    }

    /**
     * 创建一个SignedData结构，将其创建时使用的默认签名属性更改。
     *
     * @param signingKey  签名私钥
     * @param alg         签名算法
     * @param signingCert 签名私钥对应的公钥证书
     * @param msg         原始消息数据
     * @param encapsulate 是否将消息原文封装到签名当中，若这一参数为false，通常称生成的是 detached signature，表示签名和消息是分开存放的。
     * @return 包含SignedData的CMSSignedData对象
     */
    public static CMSSignedData createSignedDataWithAttributesEdit(PrivateKey signingKey, String alg, X509CertificateHolder signingCert, byte[] msg, boolean encapsulate) throws CMSException, OperatorCreationException {
        ContentSigner contentSigner = new JcaContentSignerBuilder(alg).setProvider("BC").build(signingKey);
        DigestCalculatorProvider digestCalcProvider = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();

        SignerInfoGenerator signerInfoGenerator = new SignerInfoGeneratorBuilder(digestCalcProvider)
                .setSignedAttributeGenerator(parameters -> {
                    // 创建一个默认签名属性，去除了 CMSAttributes.cmsAlgorithmProtect
                    AttributeTable table = new DefaultSignedAttributeTableGenerator().getAttributes(parameters);
                    return table.remove(CMSAttributes.cmsAlgorithmProtect);
                })
                .build(contentSigner, signingCert);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        gen.addSignerInfoGenerator(signerInfoGenerator);
        Store<X509CertificateHolder> certs = new CollectionStore<>(Collections.singletonList(signingCert));
        gen.addCertificates(certs);
        CMSTypedData typedMsg = new CMSProcessableByteArray(msg);
        return gen.generate(typedMsg, encapsulate);
    }

    /**
     * 使用JcaSimpleSignerInfoGeneratorBuilder创建一个SignedData。
     *
     * @param signingKey  签名私钥
     * @param alg         签名算法
     * @param signingCert 签名私钥对应的公钥证书
     * @param msg         原始消息数据
     * @param encapsulate 是否将消息原文封装到签名当中，若这一参数为false，通常称生成的是 detached signature，表示签名和消息是分开存放的。
     * @return 包含SignedData的CMSSignedData对象
     */
    public static CMSSignedData createSignedDataSimple(PrivateKey signingKey, String alg, X509CertificateHolder signingCert, byte[] msg, boolean encapsulate) throws CMSException, OperatorCreationException {
        SignerInfoGenerator signerInfoGenerator = new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC").build(alg, signingKey, signingCert);
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        gen.addSignerInfoGenerator(signerInfoGenerator);
        Store<X509CertificateHolder> certs = new CollectionStore<>(Collections.singletonList(signingCert));
        gen.addCertificates(certs);
        CMSTypedData typedMsg = new CMSProcessableByteArray(msg);
        return gen.generate(typedMsg, encapsulate);
    }

    /**
     * 添加签名副本
     *
     * @param original        原P7签名信息
     * @param alg             签名算法
     * @param counterSignKey  签名私钥
     * @param counterSignCert 签名私钥对应的公钥证书
     * @return 一个更新了的P7签名信息（增加了副本签名）
     */
    public static CMSSignedData addCounterSignature(CMSSignedData original, PrivateKey counterSignKey, String alg, X509CertificateHolder counterSignCert) throws CMSException, OperatorCreationException {
        SignerInfoGenerator signerInfoGenerator = new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC").build(alg, counterSignKey, counterSignCert);
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        gen.addSignerInfoGenerator(signerInfoGenerator);

        // 获取原P7所有的签名者信息
        SignerInformationStore signers = original.getSignerInfos();
        // 获取其中一个签名者信息
        SignerInformation signerInfo = signers.iterator().next();
        // 将其中一个签名者信息属性复制--》counterSigner
        signerInfo = SignerInformation.addCounterSigners(signerInfo, gen.generateCounterSigners(signerInfo));
        // 获取P7签名原来所有签名者证书
        Collection originalCerts = original.getCertificates().getMatches(null);
        Set totalCerts = new HashSet();
        totalCerts.addAll(originalCerts);
        // 添加多一个签名证书
        totalCerts.add(counterSignCert);
        // 在原来P7签名信息的基础上，添加多一个签名信息
        CMSSignedData counterSigned = CMSSignedData.replaceSigners(original, new SignerInformationStore(signerInfo));
        // 更新添加多一个签名证书
        counterSigned = CMSSignedData.replaceCertificatesAndCRLs(counterSigned, new CollectionStore(totalCerts), null, null);

        return counterSigned;
    }

    /**
     * 验证带原文的P7签名数据
     *
     * @param encodedSignedData BER编码的SignedData
     * @throws com.ainge.easycrypto.exception.CryptoException 有签名验证不通过的情况，则抛出该异常
     */
    public static void verifySignedEncapsulated(byte[] encodedSignedData) throws CMSException, CertificateException, OperatorCreationException, CryptoException {
        CMSSignedData signedData = new CMSSignedData(encodedSignedData);
        SignerInformationStore signers = signedData.getSignerInfos();
        Store certs = signedData.getCertificates();

        for (SignerInformation signerInfo : signers) {
            Collection<X509CertificateHolder> certCollection = certs.getMatches(signerInfo.getSID());
            X509CertificateHolder cert = certCollection.iterator().next();
            boolean verify = signerInfo.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert));
            if (!verify) {
                throw new CryptoException(String.format("该证书（主题为：%s）的签名验证失败", cert.getSubject()));
            }
        }
    }

    /**
     * 验证不带原文的P7签名数据
     *
     * @param encodedSignedData BER编码的SignedData
     * @param msg               原文数据msg
     * @throws com.ainge.easycrypto.exception.CryptoException 有签名验证不通过的情况，则抛出该异常
     */
    public static void verifySignedDetached(byte[] encodedSignedData, byte[] msg) throws CMSException, CertificateException, OperatorCreationException, CryptoException {
        CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(msg), encodedSignedData);
        SignerInformationStore signers = signedData.getSignerInfos();
        Store<X509CertificateHolder> certs = signedData.getCertificates();
        for (SignerInformation signerInfo : signers) {
            Collection<X509CertificateHolder> certCollection = certs.getMatches(signerInfo.getSID());
            X509CertificateHolder cert = certCollection.iterator().next();
            boolean verify = signerInfo.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert));
            if (!verify) {
                throw new CryptoException(String.format("该证书（主题为：%s）的签名验证失败", cert.getSubject()));
            }
        }
    }

    /**
     * 验证所有签名信息
     *
     * @param signedData BER编码的SignedData
     * @return 所有签名验证成功才返回true，否则false
     */
    public static boolean verifyAllSigners(CMSSignedData signedData) throws CMSException {
        final Store<X509CertificateHolder> certs = signedData.getCertificates();
        // 验证所有签名
        return signedData.verifySignatures(signerId -> {
            try {
                X509CertificateHolder cert = (X509CertificateHolder) certs.getMatches(signerId).iterator().next();
                return new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert);
            } catch (CertificateException e) {
                throw new OperatorCreationException("verifier provider failed: " + e.getMessage(), e);
            }
        });
    }


    /**
     * 流的方式构造P7带原文签名，不带原文的参考实现就可以
     *
     * @param signingKey
     * @param alg
     * @param signingCert
     * @param msg
     * @return
     * @throws CMSException
     * @throws OperatorCreationException
     * @throws IOException
     */
    public static byte[] createSignedDataStreaming(PrivateKey signingKey, String alg, X509CertificateHolder signingCert, byte[] msg) throws CMSException, OperatorCreationException, IOException {
        SignerInfoGenerator signerInfoGenerator = new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC").build(alg, signingKey, signingCert);
        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();
        gen.addSignerInfoGenerator(signerInfoGenerator);
        Store<X509CertificateHolder> certs = new CollectionStore<>(Collections.singletonList(signingCert));
        gen.addCertificates(certs);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream sOut = gen.open(bOut, true);
        sOut.write(msg);
        sOut.close();
        return bOut.toByteArray();
    }


    /**
     * 流的方式验证带原文的签名
     *
     * @param encodedSignedData
     * @throws CMSException
     * @throws OperatorCreationException
     * @throws IOException
     * @throws CertificateException
     * @throws CryptoException
     */
    public static void verifySignedEncapsulatedStreaming(byte[] encodedSignedData) throws CMSException, OperatorCreationException, IOException, CertificateException, CryptoException {
        CMSSignedDataParser signedDataParser = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build(), new ByteArrayInputStream(encodedSignedData));
        signedDataParser.getSignedContent().drain();
        SignerInformationStore signers = signedDataParser.getSignerInfos();
        Store certs = signedDataParser.getCertificates();
        for (SignerInformation signerInfo : signers) {
            Collection<X509CertificateHolder> certCollection = certs.getMatches(signerInfo.getSID());
            X509CertificateHolder cert = certCollection.iterator().next();
            boolean verify = signerInfo.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert));
            if (!verify) {
                throw new CryptoException(String.format("该证书（主题为：%s）的签名验证失败", cert.getSubject()));
            }
        }
    }

}
