package com.ecolon.crypto;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import org.bouncycastle.crypto.DataLengthException;

public class AESXcrypt {
	public static void main(String[] args) throws FileNotFoundException, IOException {
		try {
			/*
			 * FileInputStream fis = new FileInputStream( new File(
			 * "C:\\Users\\Sumit\\workspace\\AES-xcrypt\\src\\com\\wipro\\encrypt\\clear.txt"
			 * )); FileOutputStream fos = new FileOutputStream( new File(
			 * "C:\\Users\\Sumit\\workspace\\AES-xcrypt\\src\\com\\wipro\\encrypt\\encrypt.txt"
			 * ));
			 */
			// solution 1
			// BouncyCastleAPI_AES_CBC bc = new BouncyCastleAPI_AES_CBC();
			// solution 2
			/*
			 * BouncyCastleAPI_AES_CBC bc = new BouncyCastleAPI_AES_CBC(); bc.InitCiphers();
			 * 
			 * // encryption bc.CBCEncrypt(fis, fos);
			 * 
			 * fis = new FileInputStream( new File(
			 * "C:\\Users\\Sumit\\workspace\\AES-xcrypt\\src\\com\\wipro\\encrypt\\encrypt.txt"
			 * )); fos = new FileOutputStream( new File(
			 * "C:\\Users\\Sumit\\workspace\\AES-xcrypt\\src\\com\\wipro\\encrypt\\clear_test.txt"
			 * ));
			 * 
			 * // decryption bc.CBCDecrypt(fis, fos);
			 * System.out.println("Done AES CBC 192");
			 * 
			 * fis = new FileInputStream( new File(
			 * "C:\\Users\\Sumit\\workspace\\AES-xcrypt\\src\\com\\wipro\\encrypt\\clear-ofb.txt"
			 * )); fos = new FileOutputStream( new File(
			 * "C:\\Users\\Sumit\\workspace\\AES-xcrypt\\src\\com\\wipro\\encrypt\\encrypt-ofb.txt"
			 * )); BouncyCastleAPI_AES_OFB bcOFB = new BouncyCastleAPI_AES_OFB();
			 * bcOFB.InitCiphers();
			 * 
			 * // encryption bcOFB.CBCOFB256Encrypt(fis, fos);
			 * 
			 * fis = new FileInputStream( new File(
			 * "C:\\Users\\Sumit\\workspace\\AES-xcrypt\\src\\com\\wipro\\encrypt\\encrypt-ofb.txt"
			 * )); fos = new FileOutputStream( new File(
			 * "C:\\Users\\Sumit\\workspace\\AES-xcrypt\\src\\com\\wipro\\encrypt\\clear_test-ofb.txt"
			 * ));
			 * 
			 * // decryption bcOFB.CBCOFB256Decrypt(fis, fos);
			 * System.out.println("Done AES OFB 256");
			 */
			/* ENcryption with input as string */
			String input = "ecolon.com";
			byte[] inBytes = input.getBytes();
			System.out.println("Encrypting AES OFB 256 - string mode.");
			System.out.println("input string :" + input);
			
			BouncyCastleAPI_AES_OFB bcOFBWithString = new BouncyCastleAPI_AES_OFB();
			bcOFBWithString.InitCiphers();
			byte [] outBytes = bcOFBWithString.CBCOFB256Encrypt(inBytes);

			String base64encodedString = Base64.getEncoder().withoutPadding().encodeToString(outBytes);
			System.out.println("Base64 Encoded String (Basic) [with Input String] :" + base64encodedString);
			
			/* Decryption with input as string */
			byte[] decrypteBytes = bcOFBWithString.CBCOFB256Decrypt(outBytes);
			String decryptedString = new String(decrypteBytes);
			System.out.println("Decrypted text : " + decryptedString);
			System.out.println("Done AES OFB 256 - String mode");

		} catch (ShortBufferException ex) {
			Logger.getLogger(AESXcrypt.class.getName()).log(Level.SEVERE, null, ex);
		} catch (IllegalBlockSizeException ex) {
			Logger.getLogger(AESXcrypt.class.getName()).log(Level.SEVERE, null, ex);
		} catch (BadPaddingException ex) {
			Logger.getLogger(AESXcrypt.class.getName()).log(Level.SEVERE, null, ex);
		} catch (DataLengthException ex) {
			Logger.getLogger(AESXcrypt.class.getName()).log(Level.SEVERE, null, ex);
		} catch (IllegalStateException ex) {
			Logger.getLogger(AESXcrypt.class.getName()).log(Level.SEVERE, null, ex);
		} catch (Exception ex) {
			Logger.getLogger(AESXcrypt.class.getName()).log(Level.SEVERE, null, ex);
		}

		System.out.println("Test done !");
	}
}
