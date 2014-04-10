package org.tcat.citd.sim.util.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.nio.ByteBuffer;
import java.util.Arrays;

import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.tcat.citd.sim.util.crypto.SymmetricCipherBuilder.Cipher;
import org.tcat.citd.sim.util.crypto.SymmetricCipherBuilder.Mode;

public class SymmetricCipherTest
{
   @Rule
   public ExpectedException exception = ExpectedException.none();

   @Before
   public void setUp() throws Exception
   {
   }

   @After
   public void tearDown() throws Exception
   {
   }
   
   @Test
   public void testAESEncryption() throws CipherException
   {
      byte[] key = Hex.decode("2b7e151628aed2a6abf7158809cf4f3c");
      byte[] iv = Hex.decode("000102030405060708090A0B0C0D0E0F");
      byte[] pt = Hex.decode("6bc1bee22e409f96e93d7e117393172a");
      byte[] ct = Hex.decode("7649abac8119b246cee98e9b12e9197d");
      
      SymmetricCipher encryption = SymmetricCipherBuilder.buildCipher(Cipher.AES128, Mode.CBC, true, key, iv);
      int outputLength = encryption.getFinalSize(pt.length);
      ByteBuffer output = ByteBuffer.allocate(outputLength);
      encryption.processData(ByteBuffer.wrap(pt), output);
      encryption.processFinal(output);
      
      //We are cutting off to the expected length due to padding since the test vector does not use padding
      byte[] newOutput = new byte[ct.length];
      System.arraycopy(output.array(), 0, newOutput, 0, ct.length);
      assertArrayEquals(ct, newOutput);
      
      ByteBuffer encrypted = output;
      encrypted.flip();
      SymmetricCipher decryption = SymmetricCipherBuilder.buildCipher(Cipher.AES128, Mode.CBC, false, key, iv);
      outputLength = decryption.getFinalSize(encrypted.remaining());
      output = ByteBuffer.allocate(outputLength);
      decryption.processData(encrypted, output);
      decryption.processFinal(output);
      assertEquals(ByteBuffer.wrap(pt), output.flip());
   }

   @Test
   public void testAES256Encryption() throws CipherException
   {
      byte[] key = Hex.decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
      byte[] iv = Hex.decode("000102030405060708090A0B0C0D0E0F");
      byte[] pt = Hex.decode("6bc1bee22e409f96e93d7e117393172a");
      byte[] ct = Hex.decode("f58c4c04d6e5f1ba779eabfb5f7bfbd6");
      
      SymmetricCipher encryption = SymmetricCipherBuilder.buildCipher(Cipher.AES128, Mode.CBC, true, key, iv);
      int outputLength = encryption.getFinalSize(pt.length);
      ByteBuffer output = ByteBuffer.allocate(outputLength);
      encryption.processData(ByteBuffer.wrap(pt), output);
      encryption.processFinal(output);
      
      //We are cutting off to the expected length due to padding since the test vector does not use padding
      byte[] newOutput = new byte[ct.length];
      System.arraycopy(output.array(), 0, newOutput, 0, ct.length);
      assertArrayEquals(ct, newOutput);
      
      ByteBuffer encrypted = output;
      encrypted.flip();
      SymmetricCipher decryption = SymmetricCipherBuilder.buildCipher(Cipher.AES128, Mode.CBC, false, key, iv);
      outputLength = decryption.getFinalSize(encrypted.remaining());
      output = ByteBuffer.allocate(outputLength);
      decryption.processData(encrypted, output);
      decryption.processFinal(output);
      assertEquals(ByteBuffer.wrap(pt), output.flip());
   }
   
   @Test
   public void testAES256GCM() throws CipherException
   {
      byte[] key = Hex.decode("eebc1f57487f51921c0465665f8ae6d1658bb26de6f8a069a3520293a572078f");
      byte[] iv = Hex.decode("99aa3e68ed8173a0eed06684");
      byte[] aad = Hex.decode("4d23c3cec334b49bdb370c437fec78de");
      byte[] pt = Hex.decode("f56e87055bc32d0eeb31b2eacc2bf2a5");
      byte[] tag = Hex.decode("67ba0510262ae487d737ee6298f77e0c");
      byte[] ct = Hex.decode("f7264413a84c0e7cd536867eb9f21736");
      
      AEADSymmetricCipher encryption = SymmetricCipherBuilder.buildAEADCipher(Cipher.AES256, Mode.GCM, true, key, iv);
      encryption.processAADData(aad, 0, aad.length);
      int outputLength = encryption.getFinalSize(pt.length);
      byte[] output = new byte[outputLength];
      int offset = encryption.processData(pt, 0, pt.length, output, 0);
      encryption.processFinal(output, offset);
      byte[] mac = encryption.getMac();
      assertArrayEquals(tag, mac);
      assertArrayEquals(ct, output);
      
      AEADSymmetricCipher decryption = SymmetricCipherBuilder.buildAEADCipher(Cipher.AES256, Mode.GCM, false, key, iv);
      decryption.setMac(tag);
      decryption.processAADData(aad, 0, aad.length);
      outputLength = decryption.getFinalSize(ct.length);
      output = new byte[outputLength];
      offset = decryption.processData(ct, 0, ct.length, output, 0);
      decryption.processFinal(output, offset);
      mac = decryption.getMac();
      assertArrayEquals(tag, mac);
      assertArrayEquals(pt, output);
      
      byte[] badTag = new byte[tag.length];
      System.arraycopy(tag, 0, badTag, 0, tag.length);
      badTag[3] = 0x11; //Original is 0x10
      AEADSymmetricCipher failDecryption = SymmetricCipherBuilder.buildAEADCipher(Cipher.AES256, Mode.GCM, false, key, iv);
      failDecryption.setMac(badTag);
      failDecryption.processAADData(aad, 0, aad.length);
      outputLength = failDecryption.getFinalSize(ct.length);
      output = new byte[outputLength];
      offset = failDecryption.processData(ct, 0, ct.length, output, 0);
      
      exception.expect(CipherException.class);
      failDecryption.processFinal(output, offset);
      mac = failDecryption.getMac();
      assertFalse(Arrays.equals(tag, mac));
      assertArrayEquals(pt, output);
   }

}
