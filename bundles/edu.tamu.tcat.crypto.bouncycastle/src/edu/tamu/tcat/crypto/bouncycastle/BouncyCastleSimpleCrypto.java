package edu.tamu.tcat.crypto.bouncycastle;

import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.Arrays;

import edu.tamu.tcat.crypto.AEADSymmetricCipher;
import edu.tamu.tcat.crypto.ASN1SeqKey;
import edu.tamu.tcat.crypto.AsymmetricKeyBuilder.Curve;
import edu.tamu.tcat.crypto.CipherException;
import edu.tamu.tcat.crypto.DigestType;
import edu.tamu.tcat.crypto.EncodingException;
import edu.tamu.tcat.crypto.PBKDF2;
import edu.tamu.tcat.crypto.SimpleCrypto;
import edu.tamu.tcat.crypto.SymmetricCipherBuilder.Cipher;
import edu.tamu.tcat.crypto.SymmetricCipherBuilder.Mode;

/**
 * @since 1.3
 */
public class BouncyCastleSimpleCrypto implements SimpleCrypto
{
   private BouncyCastleCryptoProvider provider;

   public BouncyCastleSimpleCrypto(BouncyCastleCryptoProvider provider)
   {
      this.provider = provider;
   }

   public void setProvider(BouncyCastleCryptoProvider provider)
   {
      this.provider = provider;
   }

   @Override
   public byte[] deriveKey(String input, byte[] salt, int rounds, int keyLengthInBytes)
   {
      PBKDF2 pbkdf2 = provider.getPbkdf2(DigestType.SHA512);
      byte[] key = pbkdf2.deriveKey(pbkdf2.passwordToBytes(input), salt, rounds, 32);
      return key;
   }

   @Override
   public boolean verifyPassword(String password, byte[] salt, int rounds, int keyLengthInBytes, byte[] iv, byte[] tag, byte[] encryptedData)
   {
      PBKDF2 pbkdf2 = provider.getPbkdf2(DigestType.SHA512);
      byte[] key = pbkdf2.deriveKey(password.getBytes(Charset.forName("UTF-8")), salt, rounds, 32);

      try
      {
         AEADSymmetricCipher decryption = provider.getSymmetricCipherBuilder().buildAEADCipher(Cipher.AES256, Mode.GCM, false, key, iv);
         decryption.setMac(tag);
         int outputLength = decryption.getFinalSize(encryptedData.length);
         byte[] output = new byte[outputLength];
         int offset = decryption.processData(encryptedData, 0, encryptedData.length, output, 0);
         decryption.processFinal(output, offset);
         byte[] mac = decryption.getMac();
         return Arrays.equals(mac, tag);
      }
      catch (CipherException e)
      {
         return false;
      }
   }

   @Override
   public KeyData makeKeyPair(String password, int keyLengthInBytes, int rounds)
   {
      KeyData newKey = new KeyData();
      SecureRandom secureRandom = new SecureRandom();
      newKey.salt = new byte[keyLengthInBytes];
      newKey.IV = new byte[12];
      secureRandom.nextBytes(newKey.salt);
      secureRandom.nextBytes(newKey.IV);

      PBKDF2 pbkdf2 = provider.getPbkdf2(DigestType.SHA512);
      byte[] key = pbkdf2.deriveKey(password.getBytes(Charset.forName("UTF-8")), newKey.salt, rounds, keyLengthInBytes);

      try
      {
         newKey.keys = provider.getAsymmetricKeyBuilder().generateECKeyPair(Curve.Secp521r1);
         ASN1SeqKey asn1SeqKey = provider.getAsn1SeqKey();
         byte[] privateKeyBytes = asn1SeqKey.encodeKey(newKey.keys.getPrivate());
         AEADSymmetricCipher encryption = provider.getSymmetricCipherBuilder().buildAEADCipher(Cipher.AES256, Mode.GCM, true, key, newKey.IV);
         int outputLength = encryption.getFinalSize(privateKeyBytes.length);
         newKey.encryptedData = new byte[outputLength];
         int offset = encryption.processData(privateKeyBytes, 0, privateKeyBytes.length, newKey.encryptedData, 0);
         encryption.processFinal(newKey.encryptedData, offset);
         newKey.tag = encryption.getMac();

         return newKey;
      }
      catch (CipherException | EncodingException e)
      {
         throw new IllegalStateException("Failed creating keypair", e);
      }
   }
}
