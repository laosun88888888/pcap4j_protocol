package com.base.pcap;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.base.pacp.TLSProtocolListener;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for simple App.
 */
public class AppTest 
    extends TestCase
{
	public static final String KEY_ALGORITHM="AES";
	public static final String CIPHER_ALGORITHM="AES/ECB/PKCS7Padding";
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public AppTest( String testName )
    {
        super( testName );
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite( AppTest.class );
    }

    /**
     * Rigourous Test :-)
     * @throws NoSuchAlgorithmException 
     */
    public void testApp() throws NoSuchAlgorithmException
    {
    	  
    	
    	//String hexkey= "f75fcabc2fac7f8adb913ffd4898fd3ff61dd4f865ce601d1bbd92cb31ba8e850f6e8835a24d3eb2f883d3a4852d262a";
//    	byte[] b_key = TLSProtocolListener.hexToByteArray(hexkey);
    	byte[] key = TLSProtocolListener.hexToByteArray("2b698068f864db9a1146ed7e3caa826f");
        byte[] iv =TLSProtocolListener.hexToByteArray("560f6071");
        
//    	String stringContent = "Hello world!";
//    	byte[] byte_string = stringContent.getBytes();
        byte[] byte_string = TLSProtocolListener.hexToByteArray("1400000cf5951ef0f6737d1dd5b17ca70f7b01948dfbc25d517ed602480b27c9");
//    	byte[]c_byte_content = Base64.getEncoder().encode(byte_string);    	
    	byte[] byte_content = AESEncode(key,byte_string,iv);
//    	byte[] byte_base64_content = Base64.getEncoder().encode(byte_content);
//    	String base64Content = new String(byte_base64_content);
    	String base64Content="Xl8H8KmsJaRFiDqEC/AmR1N2q3Mdkmw/k7b+S/haSvUBFD+bOt4zdsCQ7Sd14smwBQSzIWYnLw+oleqMTW0ctA==";
    	byte[] c_byte_content = Base64.getDecoder().decode(base64Content);
    	c_byte_content = TLSProtocolListener.hexToByteArray("409eb7fb450ca6308487051a0f398de4ef00f0e3faa7f3caa4df39ad9fc7caf565ab1474306e69e51b37ed9de59d8223879cf40ade912e350b1c468a85e79aa3");
    	byte_content = AESDncode(key,c_byte_content,iv);
    	String content = new String(byte_content);
    	System.out.println(content);
        assertTrue( true );
    }
    private static byte[] tohash256Deal(String datastr) {  
        try {  
            MessageDigest digester=MessageDigest.getInstance("SHA-256");  
            digester.update(datastr.getBytes());  
            byte[] hex=digester.digest();  
            return hex;   
        } catch (NoSuchAlgorithmException e) {  
            throw new RuntimeException(e.getMessage());    
        }  
    }
    public static byte[] AESDncode(byte[] raw_key,byte[] byte_content,byte[] iv){
        try {
            //5.根据字节数组生成AES密钥
            SecretKey key=new SecretKeySpec(raw_key, "AES");
            GCMParameterSpec gcm = new GCMParameterSpec(16 * Byte.SIZE, iv);
              //6.根据指定算法AES自成密码器
            Cipher cipher=Cipher.getInstance("AES/GCM/PKCS5Padding ");
              //7.初始化密码器，第一个参数为加密(Encrypt_mode)或者解密(Decrypt_mode)操作，第二个参数为使用的KEY
            cipher.init(Cipher.DECRYPT_MODE, key,gcm);
            //8.将加密并编码后的内容解码成字节数组
            /*
             * 解密
             */
            byte [] byte_data=cipher.doFinal(byte_content);
            return byte_data;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
        //如果有错就返加nulll
        return null;         
    }
    public static byte[] AESEncode(byte[] raw_key,byte[] byte_content,byte[] iv){
        try {
            //5.根据字节数组生成AES密钥
            SecretKey key=new SecretKeySpec(raw_key, "AES");
            GCMParameterSpec gcm = new GCMParameterSpec(16 * Byte.SIZE, iv);
              //6.根据指定算法AES自成密码器
            Cipher cipher=Cipher.getInstance("AES/GCM/PKCS5Padding ");
              //7.初始化密码器，第一个参数为加密(Encrypt_mode)或者解密(Decrypt_mode)操作，第二个参数为使用的KEY
            cipher.init(Cipher.ENCRYPT_MODE, key,gcm);
            //8.将加密并编码后的内容解码成字节数组
            /*
             * 解密
             */
            byte [] byte_data=cipher.doFinal(byte_content);
            return byte_data;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
        //如果有错就返加nulll
        return null;         
    }
}
