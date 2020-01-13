package com.ainge.easycrypto.pgp;

import org.bouncycastle.openpgp.PGPPublicKey;

/**
 * @author: Ainge
 * @Time: 2020/1/13 23:07
 */
public class PGPKeyHolder {
    /**
     * 加密公钥
     */
    private final PGPPublicKey encryptKey;
    /**
     * 签名公钥
     */
    private final PGPPublicKey signKey;
    /**
     * 用户标识UserID
     */
    private final String userID;
    /**
     * 指纹
     */
    private final String fingerprint;
    /**
     * 原始密钥
     */
    private final byte[] rawKey;

    PGPKeyHolder(PGPPublicKey encryptKey, PGPPublicKey signKey, String userID, String fingerprint, byte[] rawKey) {
        this.encryptKey = encryptKey;
        this.signKey = signKey;
        this.userID = userID;
        this.fingerprint = fingerprint;
        this.rawKey = rawKey;
    }


    public PGPPublicKey getEncryptKey() {
        return encryptKey;
    }

    public PGPPublicKey getSignKey() {
        return signKey;
    }

    public String getUserID() {
        return userID;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public byte[] getRawKey() {
        return rawKey;
    }
}