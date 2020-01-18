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
 * <p>
 * 时间戳产生的过程主要包括以下几个步骤:
 * ①用户(时间戳需求方)将电子数据(文件)使用摘要算法计算出摘要值，然后组成时间戳请求包TimeStampReq。
 * ②用户将请求包TimeStampReq发送给TSA。
 * ③TSA接收到请求包TimeStampReq,
 * ④TSA需要验证TimeStampReq的时效性,通过判断nonce是否重复来防止重放攻击。
 * TSA使用私钥对请求包中的摘要进行数字签名后,组成时间戳响应包TimeStampResp。
 * TSA可以拥有多个私钥，针对不同策略、不同算法等，可使用不同的私钥。
 * TSA数字证书的extendedKeyUsage扩展项必须设置为关键扩展项，且必须包含id一kp一timeStamping 扩展密钥用途。
 * ⑤TSA将响应包TimeStampResp发送给用户。
 * ⑥用户接收到响应包TimeStampResp。
 * ⑦用户首先判断TimeStampResp 中的状态信息，如果为错误状态，则表示本次时间戳申请失败;
 * 如果为正确状态，则验证响应包中各种字段信息和TSA签名是否正确:如果字段信息或签名不正确，则拒绝该响应包。
 * 用户需要通过OCSP或CRL验证TSA证书是否作废或有效。
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
        DigestCalculatorProvider digProvider = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
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
        tsToken.validate(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(tsaCertificate));

        return true;
    }


}
