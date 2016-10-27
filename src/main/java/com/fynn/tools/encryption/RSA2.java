package com.fynn.tools.encryption;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
import java.io.*;
import java.math.*;
public class RSA2 {
	public RSA2() {
	}
	
	public static void generateKey() {
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(1024);
			KeyPair kp = kpg.genKeyPair();
			PublicKey pbkey = kp.getPublic();
			PrivateKey prkey = kp.getPrivate();
			
			// 保存公钥
			FileOutputStream f1 = new FileOutputStream("D:/pubkey.txt");
			ObjectOutputStream b1 = new ObjectOutputStream(f1);
			b1.writeObject(pbkey);
			// 保存私钥
			FileOutputStream f2 = new FileOutputStream("D:/privatekey.txt");
			ObjectOutputStream b2 = new ObjectOutputStream(f2);
			b2.writeObject(prkey);
		} catch (Exception e) {
		}
	}
	
	public static String encrypt(String text,String pubKey,String salt) throws Exception {
		// 获取公钥及参数e,n
		RSAPublicKey pbk = getPublicKey(salt, pubKey);
		
		BigInteger e = pbk.getPublicExponent();
		BigInteger n = pbk.getModulus();

		// 获取明文m
		byte ptext[] = text.getBytes("UTF-8");
		BigInteger m = new BigInteger(ptext);
		
		// 计算密文c
		BigInteger c = m.modPow(e, n);
		
		// 保存密文
		String cs = c.toString();
		
		return cs;
	}
	
	public static String decrypt(String encrptText,String priKey,String salt) throws Exception {
		// 读取私钥
		RSAPrivateKey prk = getPrivateKey(salt,priKey);
		
		BigInteger d = prk.getPrivateExponent();
		BigInteger n = prk.getModulus();
		
		// 获取私钥参数及解密
		BigInteger c = new BigInteger(encrptText);
		BigInteger m = c.modPow(d, n);
		
		String text =  m.toString();
		return text;
	}
	
	/** 
     * 使用模和指数生成RSA公钥 
     * 注意：【此代码用了默认补位方式，为RSA/None/PKCS1Padding，不同JDK默认的补位方式可能不同，如Android默认是RSA 
     * /None/NoPadding】 
     *  
     * @param modulus 
     *            模 
     * @param exponent 
     *            指数 
     * @return 
     */  
    public static RSAPublicKey getPublicKey(String modulus, String exponent) {  
        try {  
            BigInteger b1 = new BigInteger(modulus);  
            BigInteger b2 = new BigInteger(exponent);  
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");  
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(b1, b2);  
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);  
        } catch (Exception e) {  
            e.printStackTrace();  
            return null;  
        }  
    }
	
    /** 
     * 使用模和指数生成RSA私钥 
     * 注意：【此代码用了默认补位方式，为RSA/None/PKCS1Padding，不同JDK默认的补位方式可能不同，如Android默认是RSA 
     * /None/NoPadding】 
     *  
     * @param modulus 
     *            模 
     * @param exponent 
     *            指数 
     * @return 
     */  
    public static RSAPrivateKey getPrivateKey(String modulus, String exponent) {  
        try {  
            BigInteger b1 = new BigInteger(modulus);  
            BigInteger b2 = new BigInteger(exponent);  
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");  
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(b1, b2);  
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);  
        } catch (Exception e) {  
            e.printStackTrace();  
            return null;  
        }  
    }
    
	public static void main(String args[]) {
		generateKey();
		
		String pubKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7KEnI2UJVl/S1YbD1TMbzAsM2HP+VHXRIq8cRGC9cZcT/YgQNtc7lJtvatsshZaC8dPulcUlii8KZ06hFk+zpWeAdvZ+6m/yqZajNkkeNB8BhP2MlVlX80OPhfAmw07ygj7UGWmGwXhTWeutCPRmZipK9TWWw92dPfmHf8s432wIDAQAB";
		String priKey = "MIICxjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQI+OmFzyYraU4CAggAMBQGCCqGSIb3DQMHBAicfzIY4n6JQgSCAoDweFbYyc8E1H02rXbCUAW6TNDZWYh6myq0GKwky1YeLDue1xSdKcb8tT1zvalARlT71NtrSTAHpGXuyzo55QNemToUaexO7zXEq/i8jsrq2R2l7rht1FxkTTu7OHZe1QEhOxO6hNvVARELNmbYHme92dDlPsmjizl32q97ptZcSVT0SeNl081TNywclvfzVcnQ/jb4PapqHDHL3XWduU7BD3aIuqm5FgOBodnUJT/EGXuiCuxpwqquNHEMGeZGBpzq+S7xBZQr/SXFvPxgAqlegNYgCr1icfi9jmMHIKKv5q7U0AgSA2DyWVtgKTWfrGx+gCa6RYOE41GXKfbsR0E0RGLIg7+XrruHklgowVGSZTfzf96IgyQjiViUrnthUu7K5TkmrODg9QszUdICZlHFOdFeQk6IhOW1TftTTM14L00x4O7TiIMzifVir0fj3xjEZDBx9LgXDclzAS4TxKsj/KbK4/Dr3cW0Rx4Nx1vZjVe1yCRhTq9vYK8wJ0c1D6sq/hsipOn9WZ3kXSOn7l1T/qIsSou2A9uTkw9YxkRKfeF9RVQ+GNA5Pd6scD2VFxPtWdj76Kwi7zP+hSWlxOa7zUTvmesd9MHcJZ6iPeuyeVNPBENjskG0bI475/m6SKrcm0QkAKTY7KqV0ilPFQRFlqylOI36GYx1Dt16pMz7H3dGaP1WjTF2qegUoFubl7djXIDAOwa5s3Ij3HzTELIVQMMwllVnM3dhT3cGkAvHQwsn56c+yi16+iiivoiLwuGKP3Oc0kkzNnGgDh0N3JeDKAVuuVDVlPb6YBxzXV/9mbveiHhbIcc3ZI11Q5xKw5Sdah8mudLXkuPl/5Hn/tmv";
		String salt = "1001";
		try {
			String encryptText = encrypt("123qwe",pubKey,salt);
			System.out.println(encryptText);
			decrypt(encryptText,priKey,salt);
		} catch (Exception e) {
			System.out.println(e.toString());
		}
	}
}