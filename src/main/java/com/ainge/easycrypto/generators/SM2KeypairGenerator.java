package com.ainge.easycrypto.generators;

import java.security.GeneralSecurityException;
import java.security.KeyPair;

/**
 * SM2国密标准曲线是属于ECC椭圆曲线的一种
 *
 * @author: Ainge
 * @Time: 2019/12/21 18:08
 */
public class SM2KeypairGenerator {

    /**
     * SM2曲线的名称
     */
    private final static String SM2_CURVE_NAME = "sm2p256v1";

    /**
     * 产生SM2密钥对
     *
     * @return SM2密钥对
     * @throws GeneralSecurityException 产生失败抛弃异常
     */
    public static KeyPair generateSM2KeyPair() throws GeneralSecurityException {
        return ECKeyPairGenerator.generateECKeyPair(SM2_CURVE_NAME);
    }


}
