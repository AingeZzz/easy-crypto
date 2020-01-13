package com.ainge.easycrypto.pgp;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSequence;

import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcDSAContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;

/**
 * @author: Ainge
 * @Time: 2020/1/12 12:56
 */
public class X509Bridge {

    private X509Bridge() {
    }


    public static X509Certificate createCertificate(X500NameBuilder x500NameBuilder,PGPKeyPair keyPair, byte[] publicKeyRingData) throws Exception {
        if (x500NameBuilder == null) {
            x500NameBuilder = new X500NameBuilder();
        }

        PGPPublicKey publicKey = keyPair.getPublicKey();
        List<String> subjectAltNames = new LinkedList<>();
        for (Iterator<String> it = publicKey.getUserIDs(); it.hasNext(); ) {
            String attrib = it.next();
            x500NameBuilder.addRDN(BCStyle.CN, attrib);
            // extract email for the subjectAltName
            String email = PGPUtils.parseUID(attrib)[2];
            if (!email.isEmpty()) {
                subjectAltNames.add(email);
            }
        }
        X500Name x509name = x500NameBuilder.build();
        // 密钥环的创建时间
        Date creationTime = publicKey.getCreationTime();
        Date validTo = null;
        if (publicKey.getValidSeconds() > 0) {
            validTo = new Date(creationTime.getTime() + 1000L * publicKey.getValidSeconds());
        }

        return createCertificate(PGPUtils.convertPublicKey(publicKey), PGPUtils.convertPrivateKey(keyPair.getPrivateKey()), x509name, creationTime, validTo, subjectAltNames, publicKeyRingData);
    }

    /**
     * 创建自签名证书
     *
     * @param pubKey          公钥
     * @param privKey         私钥
     * @param subject         证书主题
     * @param startDate       开始日期（为空则表示从当前日期开始）
     * @param endDate         证书结束日期（为空则表示等于开始日期，即签发一个有效期间隔为0的证书）
     * @param subjectAltNames 主题备用名称（扩展）
     * @return self-signed certificate
     */
    public static X509Certificate createCertificate(PublicKey pubKey, PrivateKey privKey, X500Name subject, Date startDate, Date endDate, List<String> subjectAltNames, byte[] publicKeyData) throws Exception {
        /*
         * Sets the signature algorithm.
         */
        BcContentSignerBuilder signerBuilder;
        String pubKeyAlgorithm = pubKey.getAlgorithm();
        switch (pubKeyAlgorithm) {
            case "DSA": {
                AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
                        .find("SHA1WithDSA");
                AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder()
                        .find(sigAlgId);
                signerBuilder = new BcDSAContentSignerBuilder(sigAlgId, digAlgId);
                break;
            }
            case "RSA": {
                AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
                        .find("SHA1WithRSAEncryption");
                AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder()
                        .find(sigAlgId);
                signerBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
                break;
            }
            default:
                throw new RuntimeException("Algorithm not recognised: " + pubKeyAlgorithm);
        }
        AsymmetricKeyParameter keyp = PrivateKeyFactory.createKey(privKey.getEncoded());
        ContentSigner signer = signerBuilder.build(keyp);
        /*
         * 设置证书有效期
         */
        if (startDate == null) {
            startDate = new Date(System.currentTimeMillis());
        }
        if (endDate == null) {
            endDate = startDate;
        }
        /*
         * X509 V3证书 构建者
         */
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(subject, BigInteger.ONE, startDate, endDate, subject, SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()));
        /*
         * 基本约束，CA=true，CA证书
         */
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        /*
         * 密钥用法扩展
         */
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.keyEncipherment | KeyUsage.keyAgreement | KeyUsage.keyCertSign));

        /*
         * 证书类型扩展
         */
        certBuilder.addExtension(MiscObjectIdentifiers.netscapeCertType, false, new NetscapeCertType(NetscapeCertType.objectSigning | NetscapeCertType.sslClient | NetscapeCertType.smime));

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        /*
         * 主题密钥标识扩展
         */
        SubjectKeyIdentifier subjectKeyIdentifier = extUtils.createSubjectKeyIdentifier(pubKey);
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);
        /*
         * 签发者密钥标识（自签=主题密钥标识）
         */
        AuthorityKeyIdentifier authorityKeyIdentifier = extUtils.createAuthorityKeyIdentifier(pubKey);
        certBuilder.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);
        /*
         * 主题备用名扩展
         */
        if (subjectAltNames != null && subjectAltNames.size() > 0) {
            GeneralName[] names = new GeneralName[subjectAltNames.size()];
            for (int i = 0; i < names.length; i++) {
                names[i] = new GeneralName(GeneralName.otherName, new XmppAddrIdentifier(subjectAltNames.get(i)));
            }
            certBuilder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names));
        }
        /*
         * 自定义的PGP公钥扩展，用于标识该公钥
         */
        SubjectPGPPublicKeyInfo publicKeyExtension = new SubjectPGPPublicKeyInfo(publicKeyData);
        certBuilder.addExtension(SubjectPGPPublicKeyInfo.OID, false, publicKeyExtension);
        /*
         * 自签证书
         */
        X509CertificateHolder holder = certBuilder.build(signer);
        /*
         * 转换为X509证书，并且检查此证书确实已正确签名
         */
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
        cert.verify(pubKey);
        return cert;
    }


    private static class XmppAddrIdentifier extends DLSequence {
        static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.8.5");
        XmppAddrIdentifier(String jid) {
            super(new ASN1Encodable[]{
                    OID,
                    new DERUTF8String(jid)
            });
        }
    }


}
