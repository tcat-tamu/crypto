package edu.tamu.tcat.crypto.bouncycastle;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import edu.tamu.tcat.crypto.AEADSymmetricCipher;
import edu.tamu.tcat.crypto.CipherException;
import edu.tamu.tcat.crypto.CryptoProvider;
import edu.tamu.tcat.crypto.DigestType;
import edu.tamu.tcat.crypto.PBKDF2;
import edu.tamu.tcat.crypto.SignatureSigner;
import edu.tamu.tcat.crypto.SymmetricCipher;
import edu.tamu.tcat.crypto.SymmetricCipherBuilder.Cipher;
import edu.tamu.tcat.crypto.SymmetricCipherBuilder.Mode;

public class SymmetricCipherTest
{
   @Rule
   public ExpectedException exception = ExpectedException.none();
   private CryptoProvider provider;

   @Before
   public void getProvider()
   {
      BouncyCastleCryptoProvider bccp = new BouncyCastleCryptoProvider();
      bccp.setProvider(new BouncyCastleProvider());
      provider = bccp;
   }

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

      SymmetricCipher encryption = provider.getSymmetricCipherBuilder().buildCipher(Cipher.AES128, Mode.CBC, true, key, iv);
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
      SymmetricCipher decryption = provider.getSymmetricCipherBuilder().buildCipher(Cipher.AES128, Mode.CBC, false, key, iv);
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

      SymmetricCipher encryption = provider.getSymmetricCipherBuilder().buildCipher(Cipher.AES128, Mode.CBC, true, key, iv);
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
      SymmetricCipher decryption = provider.getSymmetricCipherBuilder().buildCipher(Cipher.AES128, Mode.CBC, false, key, iv);
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

      AEADSymmetricCipher encryption = provider.getSymmetricCipherBuilder().buildAEADCipher(Cipher.AES256, Mode.GCM, true, key, iv);
      encryption.processAADData(aad, 0, aad.length);
      int outputLength = encryption.getFinalSize(pt.length);
      byte[] output = new byte[outputLength];
      int offset = encryption.processData(pt, 0, pt.length, output, 0);
      encryption.processFinal(output, offset);
      byte[] mac = encryption.getMac();
      assertArrayEquals(tag, mac);
      assertArrayEquals(ct, output);

      AEADSymmetricCipher decryption = provider.getSymmetricCipherBuilder().buildAEADCipher(Cipher.AES256, Mode.GCM, false, key, iv);
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
      AEADSymmetricCipher failDecryption = provider.getSymmetricCipherBuilder().buildAEADCipher(Cipher.AES256, Mode.GCM, false, key, iv);
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

   @Ignore
   @Test
   //Used to perform a decryption operation and use result elsewhere.
   public void decrypt() throws Exception
   {
      int rounds = 113636;
      byte[] salt = Base64.getDecoder().decode("hpCnpDhUQS32uB/ddwjfhbJMC74Fqw38xtnUPGye6TM=");
      byte[] IV = Base64.getDecoder().decode("5HDI9/rf0JKWcIls");
      byte[] data = Base64.getDecoder().decode(
            "4lKMqSDqxhF5pJWrUQ6qFu767FrNR9wFTvfAYaTjnEK/BSTSx3Mbxmf1VWmOzb60" +
                  "XqRgptKcif6YBUiVDEppoNOngj/uXBLezubCpQKcvjpvZV6Mzbna+o55g91Vx+AK" +
                  "bTZS1x4zzJMfaLlnds94J7Bh/A41YNpfykcPFqEv7hayuy2FOCn4Aq3qKTibhwAc" +
                  "bApDSY68soPhW9z2jgKpdeYyajcXVMgeYBaFWi/Sq/357bxcA3NSIQpGLPYmlP7S" +
                  "bRpNF7WTSRG6pK6tN9XtFOr3FW9s8IhL7K/19+qzdeo7xe0iMWTHvwqEKiLqT2H5" +
                  "wDagbABlxyfYvk9cCStNuH8yUyiFU7jhjBCwYNKBP/mUAi/SWz6ScjpyCASJgGK6" +
                  "ksyj5P7SMBlqiQLCclSwH/IxQq7Cjg7J00g4A1OGnL1Pdm2wS/kuOwiTAqW8R5In" +
                  "wtQIWPUUAspJ9hAmiireawwF5ZXAZTD9+bmkluu9ABCMwXBOrc7fCqRBqZQQHoOL" +
                  "xKpiAbEYHV+V80Hb7CN/BgS8yQPL6V0ZPGSA6xj66o1DDuKsQ0cWivxrCa6zRJuu" +
                  "6dmd5c99aOwu9qfLrLKBfuafG74pwlfBmyERbauNBX9PuO1aMwcpI3/4SA+GCU7j" +
                  "U+g12d1/ws5r1Ud+95sn7wwJrGU3Lkv+c1TY7ajqsRJPqxAcGpf05GJ0MZcIxRlR" +
                  "bpK0BKI35KleyFqyaU3QLRCD6y51mrYH0y2fau20tr+t4VutRO8tGyB15RGnY4so" +
                  "7eBaeFS9H7l3kePWUuRH1ruTUYR0OAHBy7AWx7VUPjD9flsjz5GYQLf4nQlJZeDA" +
                  "nm4J1oMyfqiyu5Joxg5ND/6COqqEslS4LCIsZFXabN5ksQ8j1syJ98reJy48wZC2");
      byte[] tag = Base64.getDecoder().decode("jlIGOgUsrjCiA3Kxl+gnMw==");
      PBKDF2 pbkdf2 = provider.getPbkdf2(DigestType.SHA512);
      byte[] key = pbkdf2.deriveKey("b", salt, rounds, 256 / 8);
      AEADSymmetricCipher decryption = provider.getSymmetricCipherBuilder().buildAEADCipher(Cipher.AES256, Mode.GCM, false, key, IV);
      decryption.setMac(tag);
      byte[] output = new byte[decryption.getFinalSize(data.length)];
      int offset = decryption.processData(data, 0, data.length, output, 0);
      decryption.processFinal(output, offset);

      System.out.println("The key is [" + Base64.getEncoder().encodeToString(output) + ']');
   }

   @Ignore
   @Test
   //Used to perform a signature operation and use result elsewhere.
   public void doASignature() throws Exception
   {
      byte[] privateKeyBytes = Base64.getDecoder().decode(
            "MIICnAIBAQRBSOca0r30N55DifjFZd7PK6W1G4ZDyRVhoyo9gkiZjGUWdPb3i4NF" +
            "UxWITFoc9CcqXWZySDKxs9ayWdOEIytWGKGgggHGMIIBwgIBATBNBgcqhkjOPQEB" +
            "AkIB////////////////////////////////////////////////////////////" +
            "//////////////////////////8wgZ4EQgH/////////////////////////////" +
            "/////////////////////////////////////////////////////////ARBUZU+" +
            "uWGOHJofkpohoLaFQO6i2nJbmbMV87i0iZGO8QnhVhk5Uex+k3sWUsC9O7G/BzVz" +
            "34g9LDTx70Uf1GtQPwADFQDQnogAKRy4U5bMZxc5MoSqoNpkugSBhQQAxoWOBrcE" +
            "BOnNnj7LZiOVtEKcZIE5BT+1Ifgor2BrTT26oUted+/nWSj+HcEnov+o3jNIs8GF" +
            "akKb+X5+McLlvWYBGDkpaniaO8AEXIpftCx9G9mY9URJV5tEaBevvRcnPmYsl+5y" +
            "mV70JkDFULkBP60HYTU8cIaicsJAiL6Udp/RZlACQgH/////////////////////" +
            "//////////////////////pRhoeDvy+Wa3/MAUj3CaXQO7XJuImcR667b7cekThk" +
            "CQIBAaGBiQOBhgAEASSQlcKLto1b853Odk0GNllhsKK8yP8stMUVJA3VDziZwvfB" +
            "WdfrYtX4ohd3+QfN9O4hG4g3CE/UbfNXC3rI1hvyAGRiLWLURZiqAoNDJfbqxHQT" +
            "dZluToalEsSQJHD155tWwrGUms4FsHJdUDH2VlkjRcPPxX21IFfNhM/6MxpaXZIT");
      PrivateKey privateKey = provider.getAsn1SeqKey().decodePrivateKey("EC", privateKeyBytes);
      byte[] signedMessage = "Here is my message".getBytes(Charset.forName("UTF8"));
      SignatureSigner signer = provider.getSignatureBuilder().buildSigner(privateKey, DigestType.SHA512);
      signer.processData(signedMessage);
      byte[] signature = signer.processFinal();
      System.out.println("The signature is [" + Base64.getEncoder().encodeToString(signature) + "]");
   }

}
