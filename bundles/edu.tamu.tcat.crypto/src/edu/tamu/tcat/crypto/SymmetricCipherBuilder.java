/*
 * Copyright 2014 Texas A&M Engineering Experiment Station
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
