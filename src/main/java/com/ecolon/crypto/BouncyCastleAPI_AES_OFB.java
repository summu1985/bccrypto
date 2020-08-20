package com.ecolon.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class BouncyCastleAPI_AES_OFB {
	OFBBlockCipher aes256ofbEncryptCipher = null;
	OFBBlockCipher aes256ofbDecryptCipher = null;

	public static int ofbBlockSize = 32;
	// Buffer used to transport the bytes from one stream to another
	byte[] buf = new byte[32]; // input buffer
	byte[] obuf = new byte[512]; // output buffer
	byte[] key = null;
	// The initialization vector needed by the CBC mode
	byte[] IV = null;

	public BouncyCastleAPI_AES_OFB() {
		// default 256 bit key
		key = "SECRET_1SECRET_2SECRET_3SECRET_4".getBytes();
		// default IV vector with all bytes to 0
		IV = new byte[ofbBlockSize];
	}

	public BouncyCastleAPI_AES_OFB(byte[] keyBytes) {
		// get the key
		key = new byte[keyBytes.length];
		System.arraycopy(keyBytes, 0, key, 0, keyBytes.length);

		// default IV vector with all bytes to 0
		IV = new byte[ofbBlockSize];
	}

	public BouncyCastleAPI_AES_OFB(byte[] keyBytes, byte[] iv) {
		// get the key
		key = new byte[keyBytes.length];
		System.arraycopy(keyBytes, 0, key, 0, keyBytes.length);

		// get the IV
		IV = new byte[ofbBlockSize];
		System.arraycopy(iv, 0, IV, 0, iv.length);
	}

	public void InitCiphers() {
		// create the ciphers
		// AES block cipher in CBC mode with padding
		aes256ofbEncryptCipher = new OFBBlockCipher(new AESEngine(), 256);

		aes256ofbDecryptCipher = new OFBBlockCipher(new AESEngine(), 256);

		// create the IV parameter
		ParametersWithIV parameterIV = new ParametersWithIV(new KeyParameter(key), IV);

		aes256ofbEncryptCipher.init(true, parameterIV);
		aes256ofbDecryptCipher.init(false, parameterIV);
	}

	public void ResetCiphers() {
		if (aes256ofbEncryptCipher != null)
			aes256ofbEncryptCipher.reset();
		if (aes256ofbDecryptCipher != null)
			aes256ofbDecryptCipher.reset();
	}

	public void CBCOFB256Encrypt(InputStream in, OutputStream out)
			throws ShortBufferException, IllegalBlockSizeException, BadPaddingException, DataLengthException,
			IllegalStateException, InvalidCipherTextException, IOException {
		// Bytes written to out will be encrypted
		// Read in the cleartext bytes from in InputStream and
		// write them encrypted to out OutputStream

		// optionaly put the IV at the beggining of the cipher file
		// out.write(IV, 0, IV.length);

		int noBytesRead = 0; // number of bytes read from input
		int noBytesProcessed = 0; // number of bytes processed

		while ((noBytesRead = in.read(buf)) >= 0) {
			//System.out.println(noBytesRead + " bytes read");
			for (byte b : buf) {
				String st = String.format("%02X", b);
				//System.out.print(st);
			}
			noBytesProcessed = aes256ofbEncryptCipher.processBytes(buf, 0, noBytesRead, obuf, 0);
			//System.out.println(noBytesProcessed + " bytes processed");
			out.write(obuf, 0, noBytesProcessed);
		}

		// System.out.println(noBytesRead +" bytes read");
		// noBytesProcessed = aes256ofbEncryptCipher.doFinal(obuf, 0);

		//System.out.println(noBytesProcessed + " bytes processed");
		// out.write(obuf, 0, noBytesProcessed);
		byte[] encodedBytes = new byte[noBytesProcessed];
		System.arraycopy(obuf, 0, encodedBytes, 0, noBytesProcessed);
		String base64encodedString = Base64.getEncoder().withoutPadding().encodeToString(encodedBytes);
		//System.out.println("Base64 Encoded String (Basic) :" + base64encodedString);

		out.flush();

		in.close();
		out.close();
	}

	public byte[] CBCOFB256Encrypt(byte[] inBytes) throws ShortBufferException, IllegalBlockSizeException,
			BadPaddingException, DataLengthException, IllegalStateException, InvalidCipherTextException, IOException {
		// Bytes written to out will be encrypted
		// Read in the cleartext bytes from in InputStream and
		// write them encrypted to out OutputStream

		// optionaly put the IV at the beggining of the cipher file
		// out.write(IV, 0, IV.length);

		int noBytesRead = 0; // number of bytes read from input
		int noBytesProcessed = 0; // number of bytes processed
		int totalInBytes = inBytes.length;
		int bytesRemaining = totalInBytes - noBytesRead;

		do {

			noBytesRead = (bytesRemaining > ofbBlockSize) ? ofbBlockSize : (totalInBytes % ofbBlockSize);
			System.arraycopy(inBytes, 0, buf, 0, noBytesRead);
			//System.out.println(noBytesRead + " bytes read");
			//System.out.println("Array copied...");
			for (byte b : buf) {
				String st = String.format("%02X", b);
				//System.out.print(st);
			}
			noBytesProcessed = aes256ofbEncryptCipher.processBytes(buf, 0, noBytesRead, obuf, 0);
			bytesRemaining -= noBytesRead;
			//System.out.println(noBytesProcessed + " bytes processed");
			//out.write(obuf, 0, noBytesProcessed);
			//System.arraycopy(obuf, 0,outBytes, 0, noBytesProcessed);

		} while (noBytesRead < totalInBytes);

		// System.out.println(noBytesRead +" bytes read");
		// noBytesProcessed = aes256ofbEncryptCipher.doFinal(obuf, 0);

		//System.out.println(noBytesProcessed + " bytes processed");
		// out.write(obuf, 0, noBytesProcessed);

		byte[] encodedBytes = new byte[noBytesProcessed];
		System.arraycopy(obuf, 0, encodedBytes, 0, noBytesProcessed);
		String base64encodedString = Base64.getEncoder().withoutPadding().encodeToString(encodedBytes);
		//System.out.println("Base64 Encoded String (Basic) :" + base64encodedString);

		// out.flush();

		// in.close();
		// out.close();
		return encodedBytes;
	}

	public void CBCOFB256Decrypt(InputStream in, OutputStream out)
			throws ShortBufferException, IllegalBlockSizeException, BadPaddingException, DataLengthException,
			IllegalStateException, InvalidCipherTextException, IOException {
		// Bytes read from in will be decrypted
		// Read in the decrypted bytes from in InputStream and and
		// write them in cleartext to out OutputStream

		// get the IV from the file
		// DO NOT FORGET TO reinit the cipher with the IV
		// in.read(IV,0,IV.length);
		// this.InitCiphers();

		int noBytesRead = 0; // number of bytes read from input
		int noBytesProcessed = 0; // number of bytes processed

		while ((noBytesRead = in.read(buf)) >= 0) {
			// System.out.println(noBytesRead +" bytes read");
			for (byte b : buf) {
				String st = String.format("%02X", b);
				//System.out.print(st);
			}
			noBytesProcessed = aes256ofbDecryptCipher.processBytes(buf, 0, noBytesRead, obuf, 0);
			// System.out.println(noBytesProcessed +" bytes processed");
			out.write(obuf, 0, noBytesProcessed);
		}
		// System.out.println(noBytesRead +" bytes read");
		// noBytesProcessed = aes256ofbDecryptCipher.doFinal(obuf, 0);
		//System.out.println(noBytesProcessed + " bytes processed");
		// out.write(obuf, 0, noBytesProcessed);
		byte[] decrypted = new byte[noBytesProcessed];
		System.arraycopy(obuf, 0, decrypted, 0, noBytesProcessed);
		String decryptedString = new String(decrypted);
		//System.out.println("Decrypted text : " + decryptedString);

		out.flush();

		in.close();
		out.close();
	}

	public byte[] CBCOFB256Decrypt(byte[] inBytes) throws ShortBufferException, IllegalBlockSizeException,
			BadPaddingException, DataLengthException, IllegalStateException, InvalidCipherTextException, IOException {
		// Bytes written to out will be encrypted
		// Read in the cleartext bytes from in InputStream and
		// write them encrypted to out OutputStream

		// optionaly put the IV at the beggining of the cipher file
		// out.write(IV, 0, IV.length);

		int noBytesRead = 0; // number of bytes read from input
		int noBytesProcessed = 0; // number of bytes processed
		int totalInBytes = inBytes.length;
		int bytesRemaining = totalInBytes - noBytesRead;

		do {

			noBytesRead = (bytesRemaining > ofbBlockSize) ? ofbBlockSize : (totalInBytes % ofbBlockSize);
			System.arraycopy(inBytes, 0, buf, 0, noBytesRead);
			//System.out.println(noBytesRead + " bytes read");
			//System.out.println("Array copied...");
			for (byte b : buf) {
				String st = String.format("%02X", b);
				//System.out.print(st);
			}
			noBytesProcessed = aes256ofbDecryptCipher.processBytes(buf, 0, noBytesRead, obuf, 0);
			bytesRemaining -= noBytesRead;
			//System.out.println(noBytesProcessed + " bytes processed");
			// out.write(obuf, 0, noBytesProcessed);
			//System.arraycopy(obuf, 0,outBytes, 0, noBytesProcessed);

		} while (noBytesRead < totalInBytes);

		// System.out.println(noBytesRead +" bytes read");
		// noBytesProcessed = aes256ofbEncryptCipher.doFinal(obuf, 0);

		//System.out.println(noBytesProcessed + " bytes processed");
		// out.write(obuf, 0, noBytesProcessed);

		byte[] decrypted = new byte[noBytesProcessed+1];
		System.arraycopy(obuf, 0, decrypted, 0, noBytesProcessed+1);
		String decryptedString = new String(decrypted);
		//System.out.println("Decrypted text : " + decryptedString);

		// out.flush();

		// in.close();
		// out.close();
		return decrypted;
	}
}
