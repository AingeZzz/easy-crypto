package com.ainge.easycrypto;

import org.junit.Assert;
import org.junit.Test;

import java.security.Provider;
import java.security.Security;

/**
 * @author: Ainge
 * @Time: 2019/12/21 01:44
 */
public class BCSupportsTest {

    @Test
    public void supportTest() {
        BouncyCastleProviderSupport.support();
        Provider bc = Security.getProvider("BC");
        Assert.assertNotNull(bc);
    }
}
