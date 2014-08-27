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

import java.security.KeyPair;

/**
 * @since 1.1
 */
public interface AsymmetricKeyBuilder
{
   /**
    * Generate an EC Asymmetric Key.
    * @param curve The curve to use.
    * @return The {@link KeyPair} for the key.
    * @throws CipherException Thrown if the key cannot be generated.
    */
   public KeyPair generateECKeyPair(Curve curve) throws CipherException;
   
   public enum Curve
   {
      //Recommended by RFC 5480 To promote interoperability:
                                     //Bit Strength      ECDSA Key Size      MD Algorithm (recommended for interoperability)
      Secp192r1("secp192r1"),       //80                192                 SHA-1, SHA-224, (SHA-256), SHA-384, SHA-512
      Secp224r1("secp224r1"),       //112               224                 SHA-224, (SHA-256), SHA-384, SHA-512
      Secp256r1("secp256r1"),       //128               256                 (SHA-256), SHA-384, SHA-512
      Secp384r1("secp384r1"),       //192               384                 (SHA-384), SHA-512
      Secp521r1("secp521r1"),       //256               512                 (SHA-512)
      
      //Others listed in RFS 5480
      //Bit Strength      ECDSA Key Size      MD Algorithm
      //80                160-223             SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
      sect163k1("sect163k1"),
      sect163r2("sect163r2"),
      //112               224-255             SHA-224, SHA-256, SHA-384, SHA-512
      sect233k1("sect233k1"),
      sect233r1("sect233r1"),
      //128               256-383             SHA-256, SHA-384, SHA-512
      sect283k1("sect283k1"),
      sect283r1("sect283r1"),
      //192               384-511             SHA-384, SHA-512
      sect409k1("sect409k1"),
      sect409r1("sect409r1"),
      //256               512+                SHA-512
      sect571k1("sect571k1"),
      sect571r1("sect571r1"),
      
      //Others in BouncyCastle (in a semi preferred order)
      Secp256k1("secp256k1"),
      Sect239k1("sect239k1"),
      Secp224k1("secp224k1"),
      Sect193r1("sect193r1"),
      Sect193r2("sect193r2"),
      Secp192k1("secp192k1"),
      Sect163r1("sect163r1"),
      Secp160k1("secp160k1"),
      Secp160r1("secp160r1"),
      Secp160r2("secp160r2"),
      ;
      private final String curveName;
      Curve(String curveName)
      {
         this.curveName = curveName;
      }
      
      public String getCurveName()
      {
         return curveName;
      }
   }
}
