package com.ainge.easycrypto.example;

import com.ainge.easycrypto.asn1.SimpleStructure;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.junit.Test;

import java.util.Date;

/**
 * @author: Ainge
 * @Time: 2019/12/30 23:44
 */
public class SimpleStructureExample {


    @Test
    public void simpleStructure() throws Exception {
        int version = 12;
        Date date = new Date();
        byte[] name = "AingeZhu".getBytes("utf-8");
        String comment = "this is a test";
        String extraData = "192.168.1.1";
        SimpleStructure simpleStructure = new SimpleStructure(version,date,name,comment,extraData);
        SimpleStructure instance = SimpleStructure.getInstance(simpleStructure.toASN1Primitive());
        System.out.println(instance.getVersion());
        System.out.println(instance.getCreated());
        System.out.println(new String(instance.getData(),"utf-8"));
        System.out.println(instance.getComment());
        System.out.println(instance.getExtraData());
        System.out.println("===========================");
        System.out.println(ASN1Dump.dumpAsString(simpleStructure,true));
    }


}
