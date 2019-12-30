package com.ainge.easycrypto.asn1;

import org.bouncycastle.asn1.*;
import org.bouncycastle.util.Arrays;

import java.math.BigInteger;
import java.text.ParseException;
import java.util.Date;

/**
 * 一个简单ASN.1对象的实现
 *
 * <pre>
 *     SimpleStructure ::= SEQUENCE {
 *         version INTEGER DEFAULT 0,
 *         created GeneralizedTime,
 *         data OCTET STRING,
 *         comment [0] UTF8String OPTIONAL,
 *         extraData [1] IA5String OPTIONAL,
 *     }
 * </pre>
 *
 * @author: Ainge
 * @Time: 2019/12/30 00:43
 */
public class SimpleStructure extends ASN1Object {

    private BigInteger version;
    private Date created;
    private byte[] data;
    private String comment;
    private String extraData;


    // 内部解析，不对外暴露
    private SimpleStructure(ASN1Sequence seq) {
        int index = 0;
        if (seq.getObjectAt(index) instanceof ASN1Integer) {
            this.version = ASN1Integer.getInstance(seq.getObjectAt(index)).getValue();
            index++;
        } else {
            this.version = BigInteger.ZERO;
        }
        try {
            this.created = ASN1GeneralizedTime.getInstance(seq.getObjectAt(index++)).getDate();
        } catch (ParseException e) {
            throw new IllegalArgumentException("exception parsing created: " + e.getMessage(), e);
        }
        this.data = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(index++)).getOctets());

        for (int i = index; i != seq.size(); i++) {
            ASN1TaggedObject t = ASN1TaggedObject.getInstance(seq.getObjectAt(i));
            if (t.getTagNo() == 0) {
                this.comment = DERUTF8String.getInstance(t, false).getString();
            }
            if (t.getTagNo() == 1) {
                this.extraData = DERIA5String.getInstance(t, false).getString();
            }
        }
    }

    /**
     * 将obj对象转换或强转为SimpleStructure对象
     *
     * @param obj
     * @return 如果obj为null则返回null
     */
    public static SimpleStructure getInstance(Object obj) {
        if (obj instanceof SimpleStructure) {
            return (SimpleStructure) obj;
        }
        if (obj != null) {
            return new SimpleStructure(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public SimpleStructure(Date created, byte[] data) {
        this(0, created, data, null, null);
    }

    public SimpleStructure(Date created, byte[] data, String comment, String extraData) {
        this(0, created, data, comment, extraData);
    }

    /**
     * 全参数构造器
     *
     * @param version
     * @param created
     * @param data
     * @param comment
     * @param extraData
     */
    public SimpleStructure(int version, Date created, byte[] data, String comment, String extraData) {
        this.version = BigInteger.valueOf(version);
        this.created = new Date(created.getTime());
        this.data = Arrays.clone(data);
        if (comment != null) {
            this.comment = comment;
        }
        if (extraData != null) {
            this.extraData = extraData;
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        // DER编码会忽略默认值
        if (!BigInteger.ZERO.equals(version)) {
            vector.add(new ASN1Integer(version));
        }
        vector.add(new DERGeneralizedTime(created));
        vector.add(new DEROctetString(data));
        if (comment != null) {
            vector.add(new DERTaggedObject(false, 0, new DERUTF8String(comment)));
        }
        if (extraData != null) {
            vector.add(new DERTaggedObject(false, 1, new DERIA5String(extraData)));
        }
        return new DERSequence(vector);
    }

    public BigInteger getVersion() {
        return version;
    }
    public Date getCreated() {
        return new Date(created.getTime());
    }
    public byte[] getData() {
        return Arrays.clone(data);
    }
    public String getComment() {
        return comment;
    }
    public String getExtraData() {
        return extraData;
    }
}
