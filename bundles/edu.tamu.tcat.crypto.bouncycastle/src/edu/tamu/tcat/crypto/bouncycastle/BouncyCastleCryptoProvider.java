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
package edu.tamu.tcat.crypto.bouncycastle;

import edu.tamu.tcat.crypto.ASN1SeqKey;
import edu.tamu.tcat.crypto.AsymmetricKeyBuilder;
import edu.tamu.tcat.crypto.CryptoProvider;
import edu.tamu.tcat.crypto.DigestType;
import edu.tamu.tcat.crypto.HashBuilder;
import edu.tamu.tcat.crypto.PBKDF2;
import edu.tamu.tcat.crypto.SecureToken;
import edu.tamu.tcat.crypto.SignatureBuilder;
import edu.tamu.tcat.crypto.SymmetricCipherBuilder;
import edu.tamu.tcat.crypto.TokenException;
import edu.tamu.tcat.crypto.X509KeyDecoder;

public class BouncyCastleCryptoProvider implements CryptoProvider
{
   @Override
   public SecureToken getSecureToken(String hexKey) throws TokenException
   {
      return new SecureTokenImpl(hexKey);
   }
   
   @Override
   public SecureToken getSecureToken(byte[] key) throws TokenException
   {
      return new SecureTokenImpl(key);
   }

   @Override
   public PBKDF2 getPbkdf2(DigestType digestType)
   {
      return new PBKDF2Impl(digestType);
   }

   @Override
   public HashBuilder getHashBuilder()
   {
      return new HashBuilderImpl();
   }

   @Override
   public AsymmetricKeyBuilder getAsymmetricKeyBuilder()
   {
      return new AsymmetricKeyBuilderImpl();
   }

   @Override
   public SignatureBuilder getSignatureBuilder()
   {
      return new SignatureBuilderImpl();
   }

   @Override
   public SymmetricCipherBuilder getSymmetricCipherBuilder()
   {
      return new SymmetricCipherBuilderImpl();
   }

   @Override
   public ASN1SeqKey getAsn1SeqKey()
   {
      return new ASN1SeqKeyImpl();
   }

   @Override
   public X509KeyDecoder getX509KeyDecoder()
   {
      return new X509KeyDecoderImpl();
   }

}
