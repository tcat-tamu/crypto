/*******************************************************************************
 * Copyright © 2007-14, All Rights Reserved.
 * Texas Center for Applied Technology
 * Texas A&M Engineering Experiment Station
 * The Texas A&M University System
 * College Station, Texas, USA 77843
 *
 * Use is granted only to authorized licensee.
 * Proprietary information, not for redistribution.
 ******************************************************************************/

package edu.tamu.tcat.crypto;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import edu.tamu.tcat.crypto.internal.Activator;

public class SecureToken
{
   private static final int ivSize = 128;  //Size in bits
   
   private final SecretKeySpec key;

   /**
    * Create a new token generator/parser using an encryption key.  This attempts to fail early by creating a cipher in the constructor.
    * @param hexKey The encryption key, hex encoded.  ATM, this uses AES, so 128, 194, or 256 bit
    * @throws TokenException Thrown if the key or IV are not properly base64 encoded or the cipher cannot otherwise be created.
    */
   public SecureToken(String hexKey) throws TokenException
   {
      try
      {
         byte[] keyBytes = Hex.decodeHex(hexKey.toCharArray());
         key = new SecretKeySpec(keyBytes, "AES");
         createCipher(Cipher.ENCRYPT_MODE, createIV());
      }
      catch (DecoderException e)
      {
         throw new TokenException("Invalid Key or IV", e);
      }
   }
   
   /**
    * Create a new token generator/parser using an encryption key.  This attempts to fail early by creating a cipher in the constructor.
    * @param keyBytes The encryption key.  ATM, this uses AES, so 128, 194, or 256 bit
    * @throws TokenException Thrown if the key or IV are not properly base64 encoded or the cipher cannot otherwise be created.
    */
   public SecureToken(byte[] keyBytes) throws TokenException
   {
      key = new SecretKeySpec(keyBytes, "AES");
      createCipher(Cipher.ENCRYPT_MODE, createIV());
   }
   
   /**
    * Create a token for a given content.  The resulting token is base64 encoded. <p>
    * <b>NOTE: The tokens should likely expire.</b>  A simple way to avoid this is to make the buffer 8 bytes longer and insert System.currentTimeMillis()
    * as a long into the buffer.  Then when reading the token, read the time and use it to determine if the token has expired.
    * @param content The content to store in the token.  This {@link ByteBuffer} will not be modified and it's position, limit, and mark will also be unmodified.
    *    It should be "flipped," in that it's position should mark the start of the content and the limit is the end of the content.
    * @return The token as a base64 encoded string.
    * @throws TokenException Thrown if the token cannot be created.  This could happen due to missing cryptography algorithms, but is very unlikely if the constructor does not throw.
    */
   public String getToken(ByteBuffer content) throws TokenException
   {
      try
      {
         byte[] token = createToken(content.slice());
         byte[] iv = createIV();
         Cipher cipher = createCipher(Cipher.ENCRYPT_MODE, iv);
         int outputSize = cipher.getOutputSize(token.length);
         byte[] encrypted = new byte[outputSize + (ivSize / 8)];
         System.arraycopy(iv, 0, encrypted, 0, iv.length);
         cipher.doFinal(token, 0, token.length, encrypted, iv.length);
         String encoded = Base64.encodeBase64URLSafeString(encrypted);
         return encoded;
      }
      catch (NoSuchAlgorithmException e)
      {
         throw new TokenException("Missing algorithm", e);
      }
      catch (IllegalBlockSizeException e)
      {
         throw new TokenException("Should never happen but is thrown because Sun/Oracle doesn't understand that encryption/decryption modes are different and should really have different APIs.  This is a decrypt only problem", e);
      }
      catch (BadPaddingException e)
      {
         throw new TokenException("Should never happen but is thrown because Sun/Oracle doesn't understand that encryption/decryption modes are different and should really have different APIs.  This is a decrypt only problem", e);
      }
      catch (ShortBufferException e)
      {
         throw new TokenException("Should never happen", e);
      }
   }
   
   /**
    * Get the token's content back from the original token.
    * @param encoded The base64 encoded token as produced from {@link #getToken(ByteBuffer)}.
    * @return A {@link ByteBuffer} containing the token's content. <p>
    * 
    * If the token has no content, a 0 length {@link ByteBuffer} will be returned.  <b>This is not a good idea</b>; see {@link #getToken(ByteBuffer)}.
    * @throws TokenException Thrown if the token cannot be verified.  This could happen due to missing cryptography algorithms or if the token is corrupted.
    *    If {@link TokenException#isTokenInvalid()} is true, the token has been corrupted or maliciously modified.
    */
   public ByteBuffer getContentFromToken(String encoded) throws TokenException
   {
      try
      {
         byte[] encrypted = Base64.decodeBase64(encoded.getBytes());
         byte[] iv = new byte[ivSize / 8];
         int ivLength = iv.length;
         if (encrypted.length < ivLength)
            throw new TokenException("Invalid Token", true);
         System.arraycopy(encrypted, 0, iv, 0, ivLength);
         Cipher cipher = createCipher(Cipher.DECRYPT_MODE, iv);
         byte[] encryptedBlock = new byte[encrypted.length - ivLength];
         System.arraycopy(encrypted, ivLength, encryptedBlock, 0, encryptedBlock.length);
         byte[] token = cipher.doFinal(encryptedBlock);
         ByteBuffer content = ByteBuffer.wrap(token);
         return content;
      }
      catch (IllegalBlockSizeException e)
      {
         throw new TokenException("Incorrect input size", e, true);
      }
      catch (BadPaddingException e)
      {
         throw new TokenException("Bad Padding", e, true);
      }
   }
   
   private byte[] createIV()
   {
      SecureRandom random = new SecureRandom();
      byte[] iv = new byte[ivSize / 8];
      random.nextBytes(iv);
      return iv;
   }

   private Cipher createCipher(int mode, byte[] iv) throws TokenException
   {
      try
      {
         Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", Activator.getDefault().getBouncyCastleProvider());
         cipher.init(mode, key, new IvParameterSpec(iv));
         return cipher;
      }
      catch (NoSuchPaddingException e)
      {
         throw new TokenException("Missing algorithm", e);
      }
      catch (InvalidKeyException e)
      {
         throw new TokenException("Invalid Key (maybe you need to install the Java Cryptography Extension?)", e);
      }
      catch (InvalidAlgorithmParameterException e)
      {
         throw new TokenException("Invalid parameter (bad IV?)", e);
      }
      catch (NoSuchAlgorithmException e)
      {
         throw new TokenException("Missing algorithm", e);
      }
   }
   
   private byte[] createToken(ByteBuffer content) throws NoSuchAlgorithmException
   {
      byte[] bytes = new byte[content.remaining()];
      ByteBuffer tokenBytes = ByteBuffer.wrap(bytes);
      content.position(0);
      tokenBytes.put(content);
      return bytes;
   }
}
