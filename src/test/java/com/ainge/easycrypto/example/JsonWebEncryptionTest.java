package com.ainge.easycrypto.example;

import com.ainge.easycrypto.generators.RSAKeyPairGenerator;
import com.ainge.easycrypto.jose.jwe.JsonWebEncryption;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import sun.misc.BASE64Decoder;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;


/**
 * Created by Ainge on 2019/11/24
 */
public class JsonWebEncryptionTest extends InstallBCSupport {

    private String privateKey;
    private String publicKey;

    @Before
    public void setup() {
        // 与公钥加密对应的私钥(特别注意一定要是PKCS8格式的)
        privateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDEdHIR1TwwSR4m\n" +
                "pzHuK5yVUT2KuWywRAMcRshDn4DSo2DESY+T6UJj2GVVTetF9NcqFtzcknY2g6Ho\n" +
                "A2nJ3tx9YJ9UbfSLKA2tW9hlCYN98ByEZvJl/v6L2k4AIe7TW6li6TVfcbpCia66\n" +
                "qX7UfVMFqIGGwMJNiBLpjDNo5hjC7S6+2FNrYAhc17Kal6NKhyr46Kbsqrt2cvkD\n" +
                "/ZmWl8zjyZGGkycaKMnTo1GsQrrteoP8wuNq/s9IC/2XfYnP5moSVdekgLOIfYYj\n" +
                "3K413LG567mQj3c+ELWm/zuAplnP3pS/g3dsD1aUzxy5WvPhNAxoAY4M9YqHZ4o4\n" +
                "9pMek2rfAgMBAAECggEAZyUgUv6a+Fsban30ODFLqBYccr6CM1WyMGF1ehO/xlgj\n" +
                "UUuyB527zsJqCcy8T2GKqr2QPnrjeCHKmw9Xtra9G1LktKZ6c6mW7MNBLWM+V5v+\n" +
                "zQFkGWs1aGY499bZFr2UhKse67rBaXfydmzRe21Fbr4XK5H/MkfUbiy/PT86FvUW\n" +
                "9w6QDoGiCuLylxA5ncTyHGPNzFTNlSJahnfyDbkFXc4gACxwyZsYX0OICqh4KmPw\n" +
                "OkIMKtj8PJP+nz2HCe4uWLn5F/xo9ZLPQV8DM0yCevUH1aakr12Db0httEv+xI8A\n" +
                "4rBhp7ZXdOhDtuvTbRJ0fsu0M9RT6qaqwVxtCqntOQKBgQDslmo81mSS/0Z/sRfs\n" +
                "C5+2m6yx9OmPBSo87Sm4cbc3ZJ2/Z/8d9TGIoT2Cu/L6e84gtXVklWdKVWtSIDdK\n" +
                "O4SE2Om/z+reh6FUnRW7ei+MPv4WMPKTSA5O+e+mBhuiOaB0m8F4yYxAO+Vv8ere\n" +
                "Y4/pTgyqe8kj3WW7j7krYixNewKBgQDUkwhanpUBuwFQmOdXYAHvILI+IYKmMnoS\n" +
                "QnOpoT/w0MiLRFUhrGckyeHrMbCPq0PWaORSWC0VUpIuyyS41uDzwzjRi7zCEaOM\n" +
                "F1j5fHn4CKHseRdMACu7NbfeDpz/HC9mDgnoBEt80L37rY7LF6fcO/4jAr1icDlu\n" +
                "tzuleqgQ7QKBgQDkaTOYGMRwxtQhY7Bcy7weaJ2KEZGL6sikmbO1xtPEPvetW5IK\n" +
                "MjboWgMwvJQREIYpPgdgXH2kXmOGnmPC30NJnsHN1cZDoV44epAIuCY/mHFmq0sG\n" +
                "toJZ7SNZfnwfWtN2wQlAvBUTzr/sG/tNSYIfFKNV1LyUS6N0OYXkRJvREQKBgF8f\n" +
                "BCf4ulix4567LRoOHg9xJBFlUV8pSzKMhdEsFL6fzn1zMF0HFoiBxhRGgeloC80P\n" +
                "1st6JYJbForV4DLOBI9Plkc+LlLxLavsbqYFK1bwFfUJIoGhue/l08cL5vjJFfSm\n" +
                "54vpEBZkGf9a5IDArx5/wfLMsQ4xhaGjYI9l2XrpAoGAU3KA6CEPbwlzz6bgqmZ0\n" +
                "dh1KLNICFjex8GiKvnHvQVi7oeGafkjFdpkOdXrRff7N7yWlCtbV9H8BOzRg+sN7\n" +
                "wCMsysoMNkvvl02aqdPhfvu70UxMJJ8WaLvT2USBZAjLcEM9qwjfpmLOnPXF8wxX\n" +
                "usZa+XBtnS3Iepa0gMYGfts=";

        // 客户端公钥
        publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxHRyEdU8MEkeJqcx7iuc\n" +
                "lVE9irlssEQDHEbIQ5+A0qNgxEmPk+lCY9hlVU3rRfTXKhbc3JJ2NoOh6ANpyd7c\n" +
                "fWCfVG30iygNrVvYZQmDffAchGbyZf7+i9pOACHu01upYuk1X3G6Qomuuql+1H1T\n" +
                "BaiBhsDCTYgS6YwzaOYYwu0uvthTa2AIXNeympejSocq+Oim7Kq7dnL5A/2ZlpfM\n" +
                "48mRhpMnGijJ06NRrEK67XqD/MLjav7PSAv9l32Jz+ZqElXXpICziH2GI9yuNdyx\n" +
                "ueu5kI93PhC1pv87gKZZz96Uv4N3bA9WlM8cuVrz4TQMaAGODPWKh2eKOPaTHpNq\n" +
                "3wIDAQAB";

    }

    @Test
    public void testNodeJs() throws Exception {
        // 客户端传过来的JWE内容
        String compactSerialization = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.XCRLOkH-P9BxLjtB6sHOWZPsmowcMMbTcftGrvpiqfU96k-p1EVkpem45S_HSSwPAnRNOBCQWqr2JyVKG3wsVyJkkPxZWlkNDChSXzdOzHmWlEHZ9x8Rin3tVbZjUd7n5JUSkFawoeaKij0GNHYxREI6EOa-CMbVyc6VBvzwAGki_4vktK_UkDVFZvdpA_AFlUJwMAPBsG8Y_3ZiNa-au6a9U-DQnWUhHxA2i4Tyblt0iYhUQwuaauj8IiE_DHoP0ZeB-hkNbUbyLzjlt1394aRseJTGp6shY5Nn4L1Fyj2s-Zx_z-KB-Yrl95KUkSVCcSuNOofI1qAACcfI0tzh5Q.v_Fl03UvI5cJvoav.U3u-ZiRtm6w1wDVg8PWE78kmeH-KC6ENH-Whz03eK9y-idGmYSdzh4OQGUgXzFgbxUZlgntQXxg6RG_JDhgJyKqpaKLRSMFBkJyrSXTWzcsZDiB4S6jzxPXc8ZXERJxCp88ndq7edNJ26LoA04ZC9BctPrh1FQw_r45tmeDEnlyM4MxGWb7dZmoXd-v5MYP8rBFW8tAnQ1iNgOFlcyFZjF86F4oTK-yD7u9fDErBFnmlePT6NN2j_hVxXVY.a5VWh8eWO4_fYSzUsVQcTQ";
        // 构造对象(目前只用于解开JWE内容)
        JsonWebEncryption jwe = new JsonWebEncryption(compactSerialization, new BASE64Decoder().decodeBuffer(privateKey));
        // 获取我们需要的数据
        System.out.println("plaintext:" + jwe.getPlaintextAsUtf8String());

        byte[] reqData = "我是请求参数，我不想让中间人拦截知道，我想被加密再传输".getBytes(StandardCharsets.UTF_8);
        // 公钥加密
        JsonWebEncryption jsonWebEncryption = new JsonWebEncryption(reqData, new BASE64Decoder().decodeBuffer(publicKey));
        // 加密后的请求参数
        String content = jsonWebEncryption.getJWEContent();
        System.out.println("加密后的请求参数复制到NodeJS进行解密：" + content);
    }

    @Test
    public void testSelf() throws Exception {
        // 产生一对RSA密钥对
        KeyPair keyPair = RSAKeyPairGenerator.generateRSAKeyPair(2048);

        // 自测，服务端自己jwe加解密
        byte[] reqData = "我是请求参数，我不想让中间人拦截知道，我想被加密再传输".getBytes(StandardCharsets.UTF_8);
        // 公钥加密
        JsonWebEncryption jsonWebEncryption = new JsonWebEncryption(reqData, keyPair.getPublic().getEncoded());
        // 加密后的请求参数
        String content = jsonWebEncryption.getJWEContent();
        System.out.println("加密后的请求参数：" + content);

        // 解密,需要私钥
        JsonWebEncryption jwe = new JsonWebEncryption(content, keyPair.getPrivate().getEncoded());
        byte[] plaintextBytes = jwe.getPlaintextBytes();
        // 解密后的数据与原文一致
        Assert.assertArrayEquals(reqData, plaintextBytes);
    }

}
