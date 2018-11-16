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
    	  
    	
    	String hexkey= "5ca8218654afa3fe6f3db6170049444ab03eb96b556db97dc32c5ca9e13958629f575ed44af268bf8a04c98ba2aefa16";
    	byte[] b_key = TLSProtocolListener.hexToByteArray(hexkey);
    	byte[] key = new byte[32];
    	System.arraycopy(b_key,0,key,0,32);
        byte[] iv = new byte[16];
        System.arraycopy(b_key,32,iv,0,16);
        
    	String stringContent = "Hello world!";
    	byte[] byte_string = stringContent.getBytes();
    	byte[]c_byte_content = Base64.getEncoder().encode(byte_string);    	
    	byte[] byte_content = AESEncode(key,byte_string,iv);
    	byte[] byte_base64_content = Base64.getEncoder().encode(byte_content);
    	String base64Content = new String(byte_base64_content);
    	c_byte_content = Base64.getDecoder().decode(base64Content);
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
            Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");
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
            Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");
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
