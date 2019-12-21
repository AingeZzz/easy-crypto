package com.ainge.easycrypto.digest;

import com.ainge.easycrypto.exception.CryptoException;
import com.ainge.easycrypto.exception.UncheckedException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * 消息摘要加密
 * ---MD系列
 * ---SHA系列
 *
 * @author: Ainge
 * @Time: 2019/12/21 15:46
 */
public class MessageDigestCrypter {


    /**
     * 通过摘要算法，计算data的摘要值
     *
     * @param digestName 摘要算法
     * @param data       数据
     * @return 对数据data进行digestName算法的摘要计算
     */
    public static byte[] computeDigest(String digestName, byte[] data) throws CryptoException {
        try {
            MessageDigest digest = MessageDigest.getInstance(digestName, BouncyCastleProvider.PROVIDER_NAME);
            digest.update(data);
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(e.getMessage(), e);
        } catch (NoSuchProviderException e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    /**
     * 通过摘要算法，计算data的摘要值
     *
     * @param digestName 摘要算法
     * @param data       数据
     * @return 对数据data进行digestName算法的摘要计算
     */
    public static byte[] calculateDigest(String digestName, byte[] data) throws CryptoException {
        DigestCalculator digCalc = null;
        try {
            digCalc = createDigestCalculator(digestName);
        } catch (OperatorCreationException e) {
            throw new CryptoException(e.getMessage(), e);
        }
        OutputStream dOut = digCalc.getOutputStream();
        try {
            dOut.write(data);
            return digCalc.getDigest();
        } catch (IOException e) {
            throw new UncheckedException(e.getMessage(), e);
        } finally {
            try {
                dOut.close();
            } catch (IOException e) {
                throw new UncheckedException(e.getMessage(), e);
            }
        }
    }


    /**
     * 返回指定算法的摘要计算器
     *
     * @param digestName 摘要算法
     * @return 摘要计算器
     */
    private static DigestCalculator createDigestCalculator(String digestName) throws OperatorCreationException {
        DigestAlgorithmIdentifierFinder algFinder = new DefaultDigestAlgorithmIdentifierFinder();
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build();
        return digCalcProv.get(algFinder.find(digestName));
    }

}
