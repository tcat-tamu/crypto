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

/**
 * @since 1.1
 */
public interface SymmetricCipherBuilder
{
   public enum Mode {
//      ECB,
      CBC,
//      CFB,
//      OFB,
      GCM,
//      CCM,
//      //XTS(),
      ;
   }
   
   public enum Cipher {
//      None,
//      DES,
//      DES_EDE,
//      //RC4,
//      IDEA,
//      RC2,
//      //Blowfish,
      AES128,
      AES192,
      AES256,
//      Camellia128,
//      Camellia192,
//      Camellia256,
//      Seed,
      ;
   }
   
   /**
    * Build a {@link SymmetricCipher}.
    * @param cipher The {@link Cipher} type to use.
    * @param mode The {@link Mode} to use in the encryption/decryption.
    * @param encryption <code>true</code> if encrypting, <code>false</code> otherwise.
    * @param key The encyption key to use in bytes.
    * @param iv The initialization vector to use in bytes.
    * @return A {@link SymmetricCipher} to perform encryption/decryption operations.
    * @throws CipherException Thrown if the cipher cannot be built.
    */
   public SymmetricCipher buildCipher(Cipher cipher, Mode mode, boolean encryption, byte[] key, byte[] iv) throws CipherException;
   
   /**
    * Build a {@link AEADSymmetricCipher}.
    * @param cipher The {@link Cipher} type to use.
    * @param mode The {@link Mode} to use in the encryption/decryption.
    * @param encryption <code>true</code> if encrypting, <code>false</code> otherwise.
    * @param key The encyption key to use in bytes.
    * @param iv The initialization vector to use in bytes.
    * @return A {@link AEADSymmetricCipher} to perform encryption/decryption operations.
    * @throws CipherException Thrown if the cipher cannot be built.
    */
   public AEADSymmetricCipher buildAEADCipher(Cipher cipher, Mode mode, boolean encryption, byte[] key, byte[] iv) throws CipherException;
}
