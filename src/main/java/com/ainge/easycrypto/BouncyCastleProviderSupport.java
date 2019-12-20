package com.ainge.easycrypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

/**
 * @author: Ainge
 * @Time: 2019/12/20 23:12
 */
public class BouncyCastleProviderSupport {

    private static volatile boolean isSupport = false;
    /**
     * install BouncyCastleProviderSupport
     */
    public static void support() {
        if (!isSupport) {
            synchronized (BouncyCastleProviderSupport.class) {
                if (!isSupport) {
                    if (Security.getProvider("BC") == null) {
                        Security.addProvider(new BouncyCastleProvider());
                    }
                    isSupport = true;
                }
            }
        }
    }
}
