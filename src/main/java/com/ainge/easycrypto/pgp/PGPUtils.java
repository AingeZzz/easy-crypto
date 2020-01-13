package com.ainge.easycrypto.pgp;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Iterator;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.ainge.easycrypto.util.IOUtils;
import com.ainge.easycrypto.util.StringUtils;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyFlags;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPMarker;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.util.encoders.Hex;


/**
 * @author: Ainge
 * @Time: 2020/1/12 13:02
 */
public class PGPUtils {

    private static final Logger LOGGER = Logger.getLogger(PGPUtils.class.getName());
    /**
     * 用户ID正则表达式
     */
    private static final Pattern UID_PATTERN = Pattern.compile("(^.+?)( \\((.+)\\))?( <([A-Za-z0-9\\._%+-]+@[A-Za-z0-9\\.-]+)>$)?");
    /**
     * 密钥指纹计算器。
     */
    static final KeyFingerPrintCalculator FP_CALC = new BcKeyFingerprintCalculator();

    /**
     * 单例的JcaPGPKeyConverter转化器
     */
    private static JcaPGPKeyConverter sKeyConverter = new JcaPGPKeyConverter().setProvider("BC");

    private PGPUtils() {
    }


    /**
     * 从字符串中读取公钥环数据
     *
     * @param pubKeyStr
     * @return
     */
    public static Optional<PGPKeyHolder> readPublicKey(String pubKeyStr) {
        try {
            return readPublicKey(IOUtils.toByteArray(PGPUtil.getDecoderStream(IOUtils.toInputStream(pubKeyStr, "UTF-8"))));
        } catch (IOException ex) {
            LOGGER.log(Level.WARNING, "can't read pubKeyStr", ex);
            return Optional.empty();
        }
    }

    /**
     * 从公钥环字节数组中读取公钥数据
     *
     * @param publicKeyring 公钥环字节数组
     * @return
     */
    public static Optional<PGPKeyHolder> readPublicKey(byte[] publicKeyring) {
        PGPPublicKey encryptKey = null;
        PGPPublicKey signKey = null;
        // 用于旧式密钥环
        PGPPublicKey authKey = null;
        String uid = null;
        String fp = null;

        PGPPublicKeyRing keyRing = keyRingOrNull(publicKeyring);
        if (keyRing == null)
            return Optional.empty();

        Iterator<PGPPublicKey> keyIter = keyRing.getPublicKeys();
        while (keyIter.hasNext()) {
            PGPPublicKey key = keyIter.next();
            if (key.isMasterKey()) {
                authKey = key;
                fp = Hex.toHexString(key.getFingerprint());
                Iterator<?> uidIt = key.getUserIDs();
                if (uidIt.hasNext())
                    uid = (String) uidIt.next();
            } else if (isSigningKey(key)) {
                signKey = key;
            } else if (key.isEncryptionKey()) {
                encryptKey = key;
            }
        }

        // 传统：身份验证密钥实际上是签名密钥
        if (signKey == null && authKey != null) {
            LOGGER.info("loading legacy public key, uid: " + uid);
            signKey = authKey;
        }
        if (encryptKey == null || signKey == null || uid == null) {
            LOGGER.warning("can't find public keys in key ring, uid: " + uid);
            return Optional.empty();
        }
        return Optional.of(new PGPKeyHolder(encryptKey, signKey, uid, fp, publicKeyring));
    }


    /**
     * 将PGP私钥转为Jca私钥
     *
     * @param key
     * @return
     * @throws PGPException
     */
    public static PrivateKey convertPrivateKey(PGPPrivateKey key) throws PGPException {
        return sKeyConverter.getPrivateKey(key);
    }

    /**
     * 将PGP公钥钥转为Jca公钥
     *
     * @param key
     * @return
     * @throws PGPException
     */
    public static PublicKey convertPublicKey(PGPPublicKey key) throws PGPException {
        return sKeyConverter.getPublicKey(key);
    }

    /**
     * @param key
     * @return
     */
    public static int getKeyFlags(PGPPublicKey key) {
        Iterator<PGPSignature> signatures = key.getSignatures();
        while (signatures.hasNext()) {
            PGPSignature sig = signatures.next();
            PGPSignatureSubpacketVector subpackets = sig.getHashedSubPackets();
            if (subpackets != null)
                return subpackets.getKeyFlags();
        }
        return 0;
    }

    /**
     * 判断是否是签名密钥
     *
     * @param key
     * @return
     */
    public static boolean isSigningKey(PGPPublicKey key) {
        int keyFlags = getKeyFlags(key);
        return (keyFlags & PGPKeyFlags.CAN_SIGN) == PGPKeyFlags.CAN_SIGN;
    }

    /**
     * 从PGPSecretKey提取PGPKeyPair
     *
     * @param secretKey
     * @param dec
     * @return
     * @throws Exception
     */
    public static PGPKeyPair decrypt(PGPSecretKey secretKey, PBESecretKeyDecryptor dec) throws Exception {
        try {
            return new PGPKeyPair(secretKey.getPublicKey(), secretKey.extractPrivateKey(dec));
        } catch (PGPException ex) {
            LOGGER.log(Level.WARNING, "failed", ex);
            throw new Exception(ex.getMessage(), ex);
        }
    }

    /**
     * 复制私钥环，并且使用新的密码
     *
     * @param privateKeyData 私钥环
     * @param oldPassphrase  旧密码
     * @param newPassphrase  复制后的新密码
     * @return PGPSecretKeyRing
     * @throws Exception 可能是旧密码错误会抛出异常
     */
    public static PGPSecretKeyRing copySecretKeyRingWithNewPassword(byte[] privateKeyData, char[] oldPassphrase, char[] newPassphrase) throws Exception {

        // load the secret key ring
        PGPSecretKeyRing secRing = new PGPSecretKeyRing(privateKeyData, FP_CALC);
        PGPDigestCalculatorProvider calcProv = new JcaPGPDigestCalculatorProviderBuilder().build();
        PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder(calcProv)
                .setProvider("BC")
                .build(oldPassphrase);

        PGPDigestCalculator calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA256);
        PBESecretKeyEncryptor encryptor = new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, calc)
                .setProvider("BC").build(newPassphrase);

        try {
            return PGPSecretKeyRing.copyWithNewPassword(secRing, decryptor, encryptor);
        } catch (PGPException ex) {
            // 最可能是密码错误的异常
            throw new Exception(ex.getMessage(), ex);
        }
    }

    /**
     * 解析KeyID
     *
     * @param signatureData 签名字符串（UTF-8）
     * @return long KeyID
     */
    public static long parseKeyIDFromSignature(String signatureData) {
        Object o;
        try {
            JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(
                    PGPUtil.getDecoderStream(IOUtils.toInputStream(signatureData, "UTF-8")));
            o = pgpFact.nextObject();
            if (o instanceof PGPCompressedData) {
                PGPCompressedData data = (PGPCompressedData) o;
                pgpFact = new JcaPGPObjectFactory(data.getDataStream());
                o = pgpFact.nextObject();
            }
        } catch (IOException | PGPException ex) {
            LOGGER.log(Level.WARNING, "can't get signature object", ex);
            return 0;
        }

        // somehow two signature lists possible
        if (o instanceof PGPSignatureList) {
            PGPSignatureList signList = (PGPSignatureList) o;
            if (signList.size() > 1) {
                LOGGER.warning("more than one signature in signature list");
            } else if (signList.isEmpty()) {
                LOGGER.warning("signature list is empty");
                return 0;
            }
            return signList.get(0).getKeyID();
        } else if (o instanceof PGPOnePassSignatureList) {
            PGPOnePassSignatureList signList = (PGPOnePassSignatureList) o;
            if (signList.size() > 1) {
                LOGGER.warning("more than one signature in signature list");
            } else if (signList.isEmpty()) {
                LOGGER.warning("signature list is empty");
                return 0;
            }
            return signList.get(0).getKeyID();
        } else {
            LOGGER.warning("object not signature list: " + o);
            return 0;
        }
    }

    private static PGPPublicKeyRing keyRingOrNull(byte[] keyData) {
        PGPPublicKeyRingCollection keyRingCollection;
        try {
            keyRingCollection = new PGPPublicKeyRingCollection(keyData, FP_CALC);
        } catch (IOException | PGPException ex) {
            LOGGER.log(Level.WARNING, "can't read public key ring", ex);
            return null;
        }

        if (keyRingCollection.size() > 1) {
            LOGGER.warning("more than one key ring in collection");
        }

        Iterator<PGPPublicKeyRing> keyRingIter = keyRingCollection.getKeyRings();
        if (!keyRingIter.hasNext()) {
            LOGGER.warning("no key ring in collection");
            return null;
        }
        return keyRingIter.next();
    }


    /**
     * 解析UserID，并且按顺序返回三个字段：
     * 1）用户名（2）备注（3）电子邮件地址
     *
     * @param userID 用户ID标识
     * @return
     */
    public static String[] parseUID(String userID) {
        Matcher matcher = UID_PATTERN.matcher(userID);
        if (!matcher.matches() || matcher.groupCount() < 5)
            return new String[]{"", "", ""};

        return new String[]{StringUtils.defaultString(matcher.group(1)),
                StringUtils.defaultString(matcher.group(3)),
                StringUtils.defaultString(matcher.group(5))};
    }

    /**
     * 判断是否是被加密的文件
     *
     * @param file
     * @return
     */
    public static boolean isEncryptedFile(Path file) {
        try (FileInputStream input = new FileInputStream(file.toFile())) {
            PGPObjectFactory factory = new PGPObjectFactory(input, FP_CALC);
            Object o = factory.nextObject();
            return o instanceof PGPEncryptedDataList || o instanceof PGPMarker;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * @param input PGP文件输入流
     * @return
     * @throws IOException
     */
    public static byte[] pgpStream2Bytes(InputStream input) throws IOException {
        InputStream decoderStream = PGPUtil.getDecoderStream(input);
        return IOUtils.toByteArray(decoderStream);
    }

}
