/*
 * Copyright 2014-2019 Texas A&M Engineering Experiment Station
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

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import edu.tamu.tcat.crypto.EncodingException;
import edu.tamu.tcat.crypto.X509KeyDecoder;
import edu.tamu.tcat.crypto.bouncycastle.internal.Activator;

public class X509KeyDecoderImpl implements X509KeyDecoder
{
   private final Provider provider;

   @Deprecated
   public X509KeyDecoderImpl()
   {
      provider = Activator.getDefault().getBouncyCastleProvider();
   }

   /**
    * @since 1.3
    */
   public X509KeyDecoderImpl(Provider provider)
   {
      this.provider = provider;
   }

   @Override
   public PublicKey decodePublicKey(String type, byte[] encodedKey) throws EncodingException
   {
      try
      {
         X509EncodedKeySpec spec = new X509EncodedKeySpec(encodedKey);
         KeyFactory factory = KeyFactory.getInstance(type, this.provider);
         PublicKey key = factory.generatePublic(spec);
         return key;
      }
      catch (NoSuchAlgorithmException | InvalidKeySpecException e)
      {
         throw new EncodingException("Failed decoding type ["+type+"]", e);
      }
   }
}
