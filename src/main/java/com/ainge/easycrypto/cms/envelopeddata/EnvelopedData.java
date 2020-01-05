package com.ainge.easycrypto.cms.envelopeddata;


import com.ainge.easycrypto.exception.UncheckedException;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;

import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;

/**
 * 数字信封
 * Cryptographic Message Syntax (CMS)
 * 规范： https://tools.ietf.org/html/rfc5652
 *
 * @author: Ainge
 * @Time: 2020/1/4 18:53
 */
public class EnvelopedData {

    /**
     * 将KeyTransRecipientInfo添加到传入的CMSEnvelopedGenerator中
     * (KeyTransRecipientInfo Type)
     *
     * @param envGen         CMSEnvelopedGenerator
     * @param encryptionCert 接收者的公钥证书（用于加密）
     */
    public static void addKeyTransRecipient(CMSEnvelopedGenerator envGen, X509Certificate encryptionCert) throws GeneralSecurityException {
        JcaAlgorithmParametersConverter paramsConverter = new JcaAlgorithmParametersConverter();
        AlgorithmIdentifier oaepParams = paramsConverter.getAlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP,
                new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT));
        envGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(encryptionCert, oaepParams).setProvider("BC"));
    }

    /**
     * 使用keyIdentifier（公钥的标识符）将KeyTransRecipientInfo添加到传入的CMSEnvelopedGenerator中
     * (KeyTransRecipientInfo Type)
     *
     * @param envGen        CMSEnvelopedGenerator
     * @param keyIdentifier 公钥的标识符
     * @param wrappingKey   接收者的公钥（用于加密）
     */
    public static void addKeyTransRecipient(CMSEnvelopedGenerator envGen, byte[] keyIdentifier, PublicKey wrappingKey) throws GeneralSecurityException {
        JcaAlgorithmParametersConverter paramsConverter = new JcaAlgorithmParametersConverter();

        AlgorithmIdentifier oaepParams = paramsConverter.getAlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP,
                new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT));
        envGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(keyIdentifier, oaepParams, wrappingKey).setProvider("BC"));
    }

    /**
     * 从EnvelopedData中提取加密的原始数据
     *
     * @param encEnvelopedData BER编码的数字信封结构
     * @param privateKey       私钥（一般用于解开真正加密数据的对称密钥cek）
     * @param encryptionCert   公钥证书（用于查询recipient）
     * @return 原始数据
     */
    public static byte[] extractUsingKeyTransRecipient(byte[] encEnvelopedData, PrivateKey privateKey, X509Certificate encryptionCert) throws CMSException {
        CMSEnvelopedData envelopedData = new CMSEnvelopedData(encEnvelopedData);
        RecipientInformationStore recipients = envelopedData.getRecipientInfos();
        RecipientInformation recipient = recipients.get(new JceKeyTransRecipientId(encryptionCert));
        if (recipient != null) {
            return recipient.getContent(
                    new JceKeyTransEnvelopedRecipient(privateKey)
                            .setProvider("BC"));
        }
        throw new IllegalArgumentException("recipient for certificate not found");
    }

    /**
     * 从EnvelopedData中提取加密的原始数据（流的方式）
     *
     * @param encEnvelopedData BER编码的数字信封结构
     * @param privateKey       私钥（一般用于解开真正加密数据的对称密钥cek）
     * @param encryptionCert   公钥证书（用于查询recipient）
     * @return 原始数据
     */
    public static CMSTypedStream streamExtractUsingKeyTransRecipient(byte[] encEnvelopedData, PrivateKey privateKey, X509Certificate encryptionCert) throws CMSException, IOException {
        CMSEnvelopedDataParser envelopedData = new CMSEnvelopedDataParser(encEnvelopedData);
        RecipientInformationStore recipients = envelopedData.getRecipientInfos();
        RecipientInformation recipient = recipients.get(new JceKeyTransRecipientId(encryptionCert));
        if (recipient != null) {
            return recipient.getContentStream(
                    new JceKeyTransEnvelopedRecipient(privateKey)
                            .setProvider("BC"));
        }
        throw new IllegalArgumentException("recipient for certificate not found");
    }

    /**
     * 添加KeyAgreeRecipientInfo到CMSEnvelopedGenerator中
     * （KeyAgreeRecipientInfo Type）
     *
     * @param envGen        CMSEnvelopedGenerator
     * @param initiatorKey  封装数据发送者的私钥
     * @param initiatorCert 封装数据发送者私钥对应的公钥证书
     * @param recipientCert 接收者公钥证书
     */
    public static void addKeyAgreeRecipient(CMSEnvelopedGenerator envGen, PrivateKey initiatorKey, X509Certificate initiatorCert, X509Certificate recipientCert) throws GeneralSecurityException {
        envGen.addRecipientInfoGenerator(
                new JceKeyAgreeRecipientInfoGenerator(
                        CMSAlgorithm.ECCDH_SHA384KDF,
                        initiatorKey,
                        initiatorCert.getPublicKey(),
                        CMSAlgorithm.AES256_WRAP)
                        .addRecipient(recipientCert).setProvider("BC"));
    }

    /**
     * 从EnvelopedData中提取加密的原始数据
     *
     * @param encEnvelopedData BER编码的数字信封结构
     * @param recipientKey     接收者私钥（用于协商）
     * @param recipientCert    接收者相应到公钥证书
     * @return 原始数据
     */
    public static byte[] extractUsingKeyAgreeRecipient(byte[] encEnvelopedData, PrivateKey recipientKey, X509Certificate recipientCert) throws CMSException {
        CMSEnvelopedData envelopedData = new CMSEnvelopedData(encEnvelopedData);
        RecipientInformationStore recipients = envelopedData.getRecipientInfos();
        RecipientId rid = new JceKeyAgreeRecipientId(recipientCert);
        RecipientInformation recipient = recipients.get(rid);
        return recipient.getContent(new JceKeyAgreeEnvelopedRecipient(recipientKey).setProvider("BC"));
    }

    /**
     * 添加PasswordRecipientInfo到CMSEnvelopedGenerator中
     * （PasswordRecipientInfo type）
     *
     * @param envGen         CMSEnvelopedGenerator
     * @param passwd         产生PBE key的基础口令
     * @param salt           产生PBE key的盐
     * @param iterationCount 产生PBE key的迭代次数
     */
    public static void addPasswordRecipient(CMSEnvelopedGenerator envGen, char[] passwd, byte[] salt, int iterationCount) {
        envGen.addRecipientInfoGenerator(
                new JcePasswordRecipientInfoGenerator(CMSAlgorithm.AES256_CBC, passwd)
                        .setProvider("BC")
                        .setPasswordConversionScheme(PasswordRecipient.PKCS5_SCHEME2_UTF8)
                        .setPRF(PasswordRecipient.PRF.HMacSHA384)
                        .setSaltAndIterationCount(salt, iterationCount));
    }

    /**
     * 从EnvelopedData中提取加密的原始数据
     *
     * @param encEnvelopedData BER编码的数字信封
     * @param passwd           产生PBE key的原始口令
     * @return 原始数据
     */
    public static byte[] extractUsingPasswordRecipient(byte[] encEnvelopedData, char[] passwd) throws CMSException {
        CMSEnvelopedData envelopedData = new CMSEnvelopedData(encEnvelopedData);
        RecipientInformationStore recipients = envelopedData.getRecipientInfos();
        RecipientId rid = new PasswordRecipientId();
        RecipientInformation recipient = recipients.get(rid);
        return recipient.getContent(
                new JcePasswordEnvelopedRecipient(passwd)
                        .setProvider("BC")
                        .setPasswordConversionScheme(PasswordRecipient.PKCS5_SCHEME2_UTF8));
    }

    /**
     * 添加KEKRecipientInfo到CMSEnvelopedGenerator中
     * （KEKRecipientInfo Type）
     *
     * @param envGen      CMSEnvelopedGenerator
     * @param keyID       要存储以供接收者匹配的keyID
     * @param wrappingKey 与keyID对应的包装密钥。
     */
    public static void addKEKRecipient(CMSEnvelopedGenerator envGen, byte[] keyID, SecretKey wrappingKey) {
        envGen.addRecipientInfoGenerator(
                new JceKEKRecipientInfoGenerator(keyID, wrappingKey)
                        .setProvider("BC"));
    }

    /**
     * 从EnvelopedData中提取加密的原始数据
     *
     * @param encEnvelopedData BER编码的数字信封
     * @param keyID            接收者到KeyId
     * @param wrappingKey      与keyID对应的包装密钥。
     * @return 原始数据
     */
    public static byte[] extractUsingKEKRecipient(byte[] encEnvelopedData, byte[] keyID, SecretKey wrappingKey) throws CMSException {
        CMSEnvelopedData envelopedData = new CMSEnvelopedData(encEnvelopedData);
        RecipientInformationStore recipients = envelopedData.getRecipientInfos();
        RecipientId rid = new KEKRecipientId(keyID);
        RecipientInformation recipient = recipients.get(rid);

        return recipient.getContent(
                new JceKEKEnvelopedRecipient(wrappingKey)
                        .setProvider("BC"));
    }


    /**
     * （数字信封加密）
     * 1. 获取CMSEnvelopedDataGenerator实例
     * 2. add RecipientInfo Type（可多次调用）
     * 3. 调用此方法构建CMSEnvelopedData
     *
     * @param envGen CMSEnvelopedDataGenerator
     * @param msg    原始数据
     * @return 数据信封
     * @throws CMSException
     */
    public static CMSEnvelopedData envelopedDataMsg(CMSEnvelopedDataGenerator envGen, byte[] msg) throws CMSException {
        return envGen.generate(
                new CMSProcessableByteArray(msg),
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC)
                        .setProvider("BC")
                        .build());
    }

    /**
     * （数字信封加密-流API）
     * 1. 获取CMSEnvelopedDataGenerator实例
     * 2. add RecipientInfo Type（可多次调用）
     * 3. 调用此方法加密
     *
     * @param envStreamGen CMSEnvelopedDataStreamGenerator
     * @param msg    原始数据
     * @return 数据信封
     * @throws CMSException
     */
    public static byte[] envelopedDataMsg(CMSEnvelopedDataStreamGenerator envStreamGen, byte[] msg) throws CMSException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream out = null;
        try {
            out = envStreamGen.open(bOut, new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider("BC").build());
            out.write(msg);
            out.close();
            return bOut.toByteArray();
        } catch (IOException e) {
            throw new UncheckedException("IO Exception:" + e.getMessage(), e);
        }

    }


    public static CMSEnvelopedDataGenerator getCMSEnvelopedDataGenerator() {
        return new CMSEnvelopedDataGenerator();
    }

    public static CMSEnvelopedDataStreamGenerator getCMSEnvelopedDataStreamGenerator() {
        return new CMSEnvelopedDataStreamGenerator();
    }

}
