    package com.fynn.tools.encryption;  
      
    import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;

import javax.crypto.Cipher;

import sun.misc.BASE64Decoder;  
      
    public class RSA {  
    	
    	public static void main(String args[]) throws Exception{
//    		String pubKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHOedxRc+ur0gy+jyJachH6OhCjbbWij2LygjH1ePb4d0xGISIaCSpQ+xVEPWLM2lC8Zdz6yuaPM069hDIiMvZs2XZU9E95G9tnVvCc1HReGiHm/5JfV9KiNz8NWzP4uSF5LE000XZsZ9EmLyfLgpe0Kcs0sb73QvT1WGA92FudQIDAQAB";
    		String priKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMKF1LDiL/ohUAdZ7ss5nJ5tEGaMO7Js2twINhF/lobPMc/FG40C5YsmcvYBf1wN3/Hs63xah6oK4wff9i0ukR2U/na45JOWLZvfhw3QB7x5yC+f7kJSzFhbUBZv/rjAMXrUBVhCxiw7d6w87vQXmlCxyt2VZ5IAlwkvV6KcH3HhAgMBAAECgYEAgILsJkP4kFaryX+HvGl+aEgDmswwsEssOEuQdPUG3F9MOEivT/TG86xeLNqGaqmb9vegB9LDZ/qzTMOQnv7xzSH7Gw9WqB98d1Oi88D8Il4Vu445/YzEp/EnZfKty6xrA9KhNxySjthhUIIBibko7wKIJSnTM005c8wo0Jo2irECQQD3GA01G59HvLELhfM3qrgykzGK6zk1UpAGQSNUVUrqYz+zItZCElN6DkculZ2ii6rumWp9eWxnTVCBS5K22VMtAkEAyYizzHcGooDvjsJ2hP6Bv8t+xu0Z2vOGlbAD+fSQnjd5htkkyoPZ67EuTxYYQgn7PqwJ0aT6IeOuRqGZrw9aBQJBAL6CY8R7nI3x1MsepsxXqxcLV9pUy9Hp6zN3S2b9L/qRNQ7HoExm1se3dHhdUKF/b/XwgSNm2Aa5nIVjoCWsX60CQE995j2N7UYHyXXr6kfHA3KdV6IrP3mHeNxuEwNyneBqTTsNR1/B5iD7QCLdui/CNCGiRjU095yKa+FcOHw+d+kCQDW7JN0f5KPQnUWlNnOlPB4jEYP46eVD4RA8i0R00ZE0y3u2/BbdhSKvjZpiE6UojoSQKKRDJA10HGBbBw7e6f8=";
//    		RSAPublicKey publicKey = getPublicKey(pubKey);
    		RSAPrivateKey privateKey = getPrivateKey(priKey);
//    		String encryptText = encryptByPublicKey("你好",publicKey);
//    		System.out.println(encryptText);
    		
    		String encryptText = "jrvCw80x5bShvwlC0r0q/cLNbjp55Tsz/tCl4gAx1yl7GjUIx43zd/rGh5M6MVKMyhzul5TSpyds772eRdRLIRtqRQxCFLc1wpICz1seGyzWyuJiM2Vtoi5vh5vgBLhS2YFZTsz/sCI/OapTnKRFdqhyp7x7pRkv/h8DWazlcpY=";
//    		byte[] keyBytes;
//    		keyBytes = (new BASE64Decoder()).decodeBuffer(test);
//    		encryptText = keyBytes.toString();
    		String text = decryptByPrivateKey(encryptText,privateKey);
    		System.out.println(text);
    	}
    	
        /** 
         * 生成公钥和私钥 
         * @throws NoSuchAlgorithmException  
         * 
         */  
        public static HashMap<String, Object> getKeys() throws NoSuchAlgorithmException{  
            HashMap<String, Object> map = new HashMap<String, Object>();  
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");  
            keyPairGen.initialize(1024);  
            KeyPair keyPair = keyPairGen.generateKeyPair();  
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();  
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();  
            map.put("public", publicKey);  
            map.put("private", privateKey);  
            return map;  
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
        
        public static RSAPublicKey getPublicKey(String key) throws Exception {
            byte[] keyBytes;
            keyBytes = (new BASE64Decoder()).decodeBuffer(key);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            return (RSAPublicKey) publicKey;
      }
        
	public static RSAPrivateKey getPrivateKey(String key) throws Exception {
		byte[] keyBytes;
		keyBytes = (new BASE64Decoder()).decodeBuffer(key);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
		return (RSAPrivateKey) privateKey;
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
      
        /** 
         * 公钥加密 
         *  
         * @param data 
         * @param publicKey 
         * @return 
         * @throws Exception 
         */  
        public static String encryptByPublicKey(String data, RSAPublicKey publicKey)  
                throws Exception {  
            Cipher cipher = Cipher.getInstance("RSA");  
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);  
            // 模长  
            int key_len = publicKey.getModulus().bitLength() / 8;  
            // 加密数据长度 <= 模长-11  
            String[] datas = splitString(data, key_len - 11);  
            String mi = "";  
            //如果明文长度大于模长-11则要分组加密  
            for (String s : datas) {  
                mi += bcd2Str(cipher.doFinal(s.getBytes()));  
            }  
            return mi;  
        }  
      
        /** 
         * 私钥解密 
         *  
         * @param data 
         * @param privateKey 
         * @return 
         * @throws Exception 
         */  
        public static String decryptByPrivateKey(String data, RSAPrivateKey privateKey)  
                throws Exception {  
            Cipher cipher = Cipher.getInstance("RSA");  
            cipher.init(Cipher.DECRYPT_MODE, privateKey);  
            //模长  
            int key_len = privateKey.getModulus().bitLength() / 8;  
            byte[] bytes = data.getBytes();  
            byte[] bcd = ASCII_To_BCD(bytes, bytes.length);  
            System.err.println(bcd.length);  
            //如果密文长度大于模长则要分组解密  
            String ming = "";  
            byte[][] arrays = splitArray(bcd, key_len);  
            for(byte[] arr : arrays){  
                ming += new String(cipher.doFinal(arr));  
            }  
            return ming;  
        }  
        /** 
         * ASCII码转BCD码 
         *  
         */  
        public static byte[] ASCII_To_BCD(byte[] ascii, int asc_len) {  
            byte[] bcd = new byte[asc_len / 2];  
            int j = 0;  
            for (int i = 0; i < (asc_len + 1) / 2; i++) {  
                bcd[i] = asc_to_bcd(ascii[j++]);  
                bcd[i] = (byte) (((j >= asc_len) ? 0x00 : asc_to_bcd(ascii[j++])) + (bcd[i] << 4));  
            }  
            return bcd;  
        }  
        public static byte asc_to_bcd(byte asc) {  
            byte bcd;  
      
            if ((asc >= '0') && (asc <= '9'))  
                bcd = (byte) (asc - '0');  
            else if ((asc >= 'A') && (asc <= 'F'))  
                bcd = (byte) (asc - 'A' + 10);  
            else if ((asc >= 'a') && (asc <= 'f'))  
                bcd = (byte) (asc - 'a' + 10);  
            else  
                bcd = (byte) (asc - 48);  
            return bcd;  
        }  
        /** 
         * BCD转字符串 
         */  
        public static String bcd2Str(byte[] bytes) {  
            char temp[] = new char[bytes.length * 2], val;  
      
            for (int i = 0; i < bytes.length; i++) {  
                val = (char) (((bytes[i] & 0xf0) >> 4) & 0x0f);  
                temp[i * 2] = (char) (val > 9 ? val + 'A' - 10 : val + '0');  
      
                val = (char) (bytes[i] & 0x0f);  
                temp[i * 2 + 1] = (char) (val > 9 ? val + 'A' - 10 : val + '0');  
            }  
            return new String(temp);  
        }  
        /** 
         * 拆分字符串 
         */  
        public static String[] splitString(String string, int len) {  
            int x = string.length() / len;  
            int y = string.length() % len;  
            int z = 0;  
            if (y != 0) {  
                z = 1;  
            }  
            String[] strings = new String[x + z];  
            String str = "";  
            for (int i=0; i<x+z; i++) {  
                if (i==x+z-1 && y!=0) {  
                    str = string.substring(i*len, i*len+y);  
                }else{  
                    str = string.substring(i*len, i*len+len);  
                }  
                strings[i] = str;  
            }  
            return strings;  
        }  
        /** 
         *拆分数组  
         */  
        public static byte[][] splitArray(byte[] data,int len){  
            int x = data.length / len;  
            int y = data.length % len;  
            int z = 0;  
            if(y!=0){  
                z = 1;  
            }  
            byte[][] arrays = new byte[x+z][];  
            byte[] arr;  
            for(int i=0; i<x+z; i++){  
                arr = new byte[len];  
                if(i==x+z-1 && y!=0){  
                    System.arraycopy(data, i*len, arr, 0, y);  
                }else{  
                    System.arraycopy(data, i*len, arr, 0, len);  
                }  
                arrays[i] = arr;  
            }  
            return arrays;  
        }  
    }  