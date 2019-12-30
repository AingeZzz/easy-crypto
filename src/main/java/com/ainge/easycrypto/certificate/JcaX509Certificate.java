package com.ainge.easycrypto.certificate;

import com.ainge.easycrypto.exception.CryptoException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;


/**
 * 简单签发证书的方法，只包含基本的扩展
 *
 * @author: Ainge
 * @Time: 2019/12/22 16:03
 */
public class JcaX509Certificate {

    /**
     * Base序列号
     */
    private static long serialNumberBase = System.currentTimeMillis();


    /**
     * 以秒为单位计算日期（满足 RFC 5280规范要求）
     *
     * @param hoursInFuture 几个小时，可以为负
     * @return 日前设置为：now + (hoursInFuture * 60 * 60) seconds
     */
    public static Date calculateDate(int hoursInFuture) {
        long secs = System.currentTimeMillis() / 1000;

        return new Date((secs + (hoursInFuture * 60 * 60)) * 1000);
    }


    /**
     * 递增计算序列号（同一root ca签发出来的证书，序列号必须唯一）
     *
     * @return 一个大数，作为序列号
     */
    public static synchronized BigInteger calculateSerialNumber() {
        return BigInteger.valueOf(serialNumberBase++);
    }


    /**
     * 将X509CertificateHolder转化为X509Certificate
     *
     * @param certHolder
     * @return
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public static X509Certificate convertX509CertificateHolder(X509CertificateHolder certHolder) throws GeneralSecurityException, IOException {
        CertificateFactory cFact = CertificateFactory.getInstance("X.509", "BC");
        return (X509Certificate) cFact.generateCertificate(new ByteArrayInputStream(certHolder.getEncoded()));
    }

    /**
     * Convert an X500Name to use the IETF style.
     */
    public static X500Name toIETFName(X500Name name) {
        return X500Name.getInstance(RFC4519Style.INSTANCE, name);
    }


    /**
     * 构建一个自签名V3证书，可以用作信任锚或根证书。
     *
     * @param keyPair      用于签名和提供公钥的密钥对
     * @param sigAlg       用于与证书签名的签名算法（算法需要与密钥对匹配，例如RSA密钥对，需要传人RSA算法，SM2传入SM2算法，EC密钥对传入EC算法）
     * @param subject      用户主题
     * @param certValidity 证书有效期（单位小时）
     * @return 包含V3证书的X509CertificateHolder
     */
    public static X509CertificateHolder createTrustAnchor(KeyPair keyPair, String sigAlg, X500Name subject, int certValidity) throws OperatorCreationException, NoSuchAlgorithmException, CertIOException {

        X509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(subject, calculateSerialNumber(), calculateDate(0), calculateDate(certValidity), subject, keyPair.getPublic());
        // 添加证书扩展
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
        // 授权密钥标识
        certBldr.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(subjectPublicKeyInfo))
                // 主题密钥标识 （root ca对话，与 授权密钥标识一致，自己给自己授权，自己签发自己）
                .addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(keyPair.getPublic()))
                // 基本约束=ca证书,pathLenConstraint=None,没有限制
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                // 添加CA证书的扩展，密钥用法，签名，签发证书，签CRL
                .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(keyPair.getPrivate());
        return certBldr.build(signer);
    }


    /**
     * 签发中间CA证书
     *
     * @param signerCert       签发者证书（带有公钥的证书，以后将用于验证此证书的签名）
     * @param signerKey        签发者的私钥，用于对中间CA证书进行签名
     * @param sigAlg           签发此证书的签名算法，密钥对匹配（如RSA密钥对使用RSA算法）
     * @param certKey          要安装在此CA证书中的公钥
     * @param subject          用户主题
     * @param certValidity     证书有效期（单位小时）
     * @param followingCACerts 此签发的中间CA证书还能签发的下级CA数（大于等于0，为0则说明，该CA证书只能签发实体证书）
     * @return 包含V3证书的X509CertificateHolder。
     */
    public static X509CertificateHolder createIntermediateCertificate(X509CertificateHolder signerCert, PrivateKey signerKey, String sigAlg,
                                                                      PublicKey certKey, X500Name subject, int certValidity, int followingCACerts) throws CertIOException, GeneralSecurityException, OperatorCreationException {
        // 构建证书信息
        X509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(signerCert.getSubject(), calculateSerialNumber(), calculateDate(0), calculateDate(certValidity), subject, certKey);

        // 添加证书扩展
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        // 授权密钥标识ID（从签发者私钥可以获取）
        certBldr.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(signerCert))
                // 主题密钥标识
                .addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(certKey))
                // 基本约束，ca证书和路径长度限制pathLenConstraint（followingCACert必须大于等于0，为0说明不能再签发ca证书了，只能签发终端实体证书）详情见RFC 5280
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(followingCACerts))
                // 添加CA证书的扩展，密钥用法，签名，签发证书，签CRL
                .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(signerKey);
        return certBldr.build(signer);
    }


    /**
     * 签发用于数字签名的实体用户证书
     *
     * @param signerCert   签发者对证书（带公钥），该证书在以后可以用来验证此用户证书的签名
     * @param signerKey    用于对该用户证书进行签名的私钥
     * @param sigAlg       签名算法，与signerKey相匹配（RSA私钥-RSA算法，SM2私钥-SM2算法）
     * @param certKey      将要安装到用户证书中到公钥
     * @param subject      用户主题
     * @param certValidity 证书有效期（单位小时）
     * @return 包含V3证书的X509CertificateHolder
     */
    public static X509CertificateHolder createEndEntity(X509CertificateHolder signerCert, PrivateKey signerKey, String sigAlg, PublicKey certKey, X500Name subject, int certValidity) throws CertIOException, GeneralSecurityException, OperatorCreationException {

        X509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(signerCert.getSubject(), calculateSerialNumber(), calculateDate(0), calculateDate(certValidity), subject, certKey);
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        // 授权密钥标识，也就是签发者的密钥标识ID
        certBldr.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(signerCert))
                // 主题密钥标识，类似该证书公钥的一个标识ID
                .addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(certKey))
                // 基本约束，实体证书，就不属于CA证书了
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                // 密钥用法扩展，说明该证书对应的私钥可以用于数字签名
                .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(signerKey);

        return certBldr.build(signer);
    }

    /**
     * 通过csr证书请求文件，签发实体证书
     *
     * @param signerCert   签发者证书
     * @param signerKey    签发者私钥
     * @param sigAlg       签发算法
     * @param certValidity 证书周期
     * @param certReq      证书请求内容
     * @return 返回实体证书
     * @throws Exception 签发过程失败
     */
    public static X509CertificateHolder createEndEntity(X509CertificateHolder signerCert, PrivateKey signerKey, String sigAlg, int certValidity, byte[] certReq) throws Exception {

        JcaPKCS10CertificationRequest jcaRequest = new JcaPKCS10CertificationRequest(certReq).setProvider("BC");
        // 先验证一下csr文件签名
        PublicKey key = jcaRequest.getPublicKey();
        ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder().setProvider("BC").build(key);
        boolean signatureValid = jcaRequest.isSignatureValid(verifierProvider);
        if (!signatureValid) {
            throw new CryptoException("certReq signature valid fail...");
        }
        X500Name subject = jcaRequest.getSubject();
        if (subject == null) {
            throw new CryptoException("get subject from certReq fail...");
        }
        // 准备签发证书
        X509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(signerCert.getSubject(), calculateSerialNumber(), calculateDate(0), calculateDate(certValidity), subject, key);
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        // 授权密钥标识，也就是签发者的密钥标识ID
        certBldr.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(signerCert))
                // 主题密钥标识，类似该证书公钥的一个标识ID
                .addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(key))
                // 基本约束，实体证书，就不属于CA证书了
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                // 密钥用法扩展，说明该证书对应的私钥可以用于数字签名
                .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));


        Attribute[] attributes = jcaRequest.getAttributes();
        for (Attribute attribute : attributes) {
            if (PKCSObjectIdentifiers.pkcs_9_at_extensionRequest.equals(attribute.getAttrType())) {
                // 来源证书请求的扩展
                ASN1Encodable asn1Encodable = attribute.getAttrValues().getObjectAt(0);
                Extensions instance = Extensions.getInstance(asn1Encodable);
                ASN1ObjectIdentifier[] extensionOIDs = instance.getExtensionOIDs();
                for (ASN1ObjectIdentifier identifier : extensionOIDs) {
                    Extension extension = instance.getExtension(identifier);
                    String oid = extension.getExtnId().getId();
                    // 基本常用扩展应该由证书签发者自己控制
                    if (Extension.authorityKeyIdentifier.getId().equals(oid) ||
                            Extension.subjectKeyIdentifier.getId().equals(oid) ||
                            Extension.basicConstraints.getId().equals(oid) ||
                            Extension.keyUsage.getId().equals(oid)) {
                        continue;
                    }
                    // 添加csr，certReq中包含的扩展，此处暂时不对扩展做校验了
                    certBldr.addExtension(extension);
                }
            }
        }
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(signerKey);
        return certBldr.build(signer);
    }


    /**
     * 创建特定用途的用户证书
     * 如：代码签名证书，OCSP证书，SSL服务器证书，SSL客户端证书，时间戳服务器证书，邮箱服务器等
     * 根据KeyPurposeId（RFC5280规范）来确定用途扩展
     *
     * @param signerCert   签发者对证书（带公钥），该证书在以后可以用来验证此用户证书的签名
     * @param signerKey    用于对该用户证书进行签名的私钥
     * @param sigAlg       签名算法，与signerKey相匹配（RSA私钥-RSA算法，SM2私钥-SM2算法）
     * @param certKey      将要安装到用户证书中到公钥
     * @param subject      用户主题
     * @param certValidity 证书有效期（单位小时）
     * @param keyPurpose   要与此证书的公钥关联的特定KeyPurposeId。
     * @return 包含V3证书的X509CertificateHolder
     */
    public static X509CertificateHolder createSpecialPurposeEndEntity(X509CertificateHolder
                                                                              signerCert, PrivateKey signerKey, String sigAlg,
                                                                      PublicKey certKey, X500Name subject, int certValidity, KeyPurposeId keyPurpose) throws
            OperatorCreationException, CertIOException, GeneralSecurityException {

        X509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(signerCert.getSubject(), calculateSerialNumber(), calculateDate(0), calculateDate(certValidity), subject, certKey);
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certBldr.addExtension(Extension.authorityKeyIdentifier,
                false, extUtils.createAuthorityKeyIdentifier(signerCert))
                .addExtension(Extension.subjectKeyIdentifier,
                        false, extUtils.createSubjectKeyIdentifier(certKey))
                .addExtension(Extension.basicConstraints,
                        true, new BasicConstraints(false))
                // 扩展密钥用法
                .addExtension(Extension.extendedKeyUsage,
                        true, new ExtendedKeyUsage(keyPurpose));

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(signerKey);
        return certBldr.build(signer);
    }

    /**
     * 从X509证书中提取DER编码的扩展值
     *
     * @param cert         证书
     * @param extensionOID 扩展的OID（每个扩展都有一个唯一的OID，这是规范定义的）
     * @return 返回DER编码的扩展值，如果获取不到则返回null
     */
    public static byte[] extractExtensionValue(X509Certificate cert, ASN1ObjectIdentifier extensionOID) {
        byte[] octString = cert.getExtensionValue(extensionOID.getId());
        if (octString == null) {
            return null;
        }
        return ASN1OctetString.getInstance(octString).getOctets();
    }

}
