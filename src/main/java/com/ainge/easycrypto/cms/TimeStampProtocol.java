package com.ainge.easycrypto.cms;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.*;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;

/**
 * 时间戳规范：
 * https://tools.ietf.org/html/rfc3161
 *
 * @author: Ainge
 * @Time: 2020/1/6 23:28
 */
public class TimeStampProtocol {

    /**
     * 创建一个简单的时间戳请求
     *
     * @param sha256hash 产生时间戳请求的摘要值
     * @return 生成的时间戳请求的DER编码。
     */
    public static byte[] createTspRequest(byte[] sha256hash) throws IOException {
        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        return reqGen.generate(TSPAlgorithms.SHA256, sha256hash).getEncoded();
    }

    /**
     * 创建TSP请求（带随机数，返回时间戳机构证书）
     *
     * @param sha256hash     SHA256摘要值
     * @param nonce          与此请求相关的随机数
     * @param requestTsaCert 如果为true，则时间戳机构应发回其证书的副本（指示证书是否出现在SignedData的certificate字段中）
     * @return 生成的时间戳请求的DER编码。
     */
    public static byte[] createNoncedTspRequest(byte[] sha256hash, BigInteger nonce, boolean requestTsaCert)
            throws IOException {
        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        reqGen.setCertReq(requestTsaCert);
        return reqGen.generate(TSPAlgorithms.SHA256, sha256hash, nonce).getEncoded();
    }

    /**
     * 创建时间戳响应
     *
     * @param tsaSigningKey  时间戳签发私钥
     * @param tsaSigningCert 时间戳机构证书
     * @param serialNumber   响应序列号
     * @param tsaPolicy      时间戳策略
     * @param encRequest     时间戳请求
     */
    public static byte[] createTspResponse(PrivateKey tsaSigningKey, X509Certificate tsaSigningCert,
                                           BigInteger serialNumber, ASN1ObjectIdentifier tsaPolicy, byte[] encRequest) throws Exception {
        AlgorithmIdentifier digestAlgorithm = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        DigestCalculatorProvider digProvider = new JcaDigestCalculatorProviderBuilder().setProvider("BCFIPS").build();
        TimeStampRequest tspRequest = new TimeStampRequest(encRequest);
        SignerInfoGenerator tsaSigner = new JcaSimpleSignerInfoGeneratorBuilder().build("SHA256withRSA", tsaSigningKey, tsaSigningCert);
        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(tsaSigner, digProvider.get(digestAlgorithm), tsaPolicy);

        // 客户端已请求签名证书的副本
        if (tspRequest.getCertReq()) {
            tsTokenGen.addCertificates(new JcaCertStore(Collections.singleton(tsaSigningCert)));
        }

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        return tsRespGen.generate(tspRequest, serialNumber, new Date()).getEncoded();
    }

    /**
     * 通过时间戳机构的证书验证其返回的响应状态
     *
     * @param tsaCertificate 时间戳机构的证书
     * @param encResponse    时间戳响应的ASN.1二进制编码
     * @return 验证成功返回true，抛出异常则为验证失败
     */
    public static boolean verifyTspResponse(X509Certificate tsaCertificate, byte[] encResponse) throws IOException, TSPException, OperatorCreationException {
        TimeStampResponse tsResp = new TimeStampResponse(encResponse);
        TimeStampToken tsToken = tsResp.getTimeStampToken();

        // 存在问题则会抛出异常
        tsToken.validate(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BCFIPS").build(tsaCertificate));

        return true;
    }


}
