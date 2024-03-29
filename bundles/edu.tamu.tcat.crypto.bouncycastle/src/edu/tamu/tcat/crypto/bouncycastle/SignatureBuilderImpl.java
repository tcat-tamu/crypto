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

import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;

import edu.tamu.tcat.crypto.CipherException;
import edu.tamu.tcat.crypto.DigestType;
import edu.tamu.tcat.crypto.SignatureBuilder;
import edu.tamu.tcat.crypto.SignatureSigner;
import edu.tamu.tcat.crypto.SignatureVerifier;
import edu.tamu.tcat.crypto.bouncycastle.internal.Activator;
import edu.tamu.tcat.crypto.impl.JavaSigner;
import edu.tamu.tcat.crypto.impl.JavaVerifier;

public class SignatureBuilderImpl implements SignatureBuilder
{
   private final Provider provider;

   @Deprecated
   public SignatureBuilderImpl()
   {
      this.provider = Activator.getDefault().getBouncyCastleProvider();
   }

   /**
    * @since 1.3
    */
   public SignatureBuilderImpl(Provider provider)
   {
      this.provider = provider;
   }

   @Override
   public SignatureSigner buildSigner(PrivateKey privateKey, DigestType digest) throws CipherException
   {
      try
      {
         String algorithm = privateKey.getAlgorithm();
         switch (algorithm)
         {
            case "EC":
               String signatureType = digest.name() + "withECDSA";
               Signature signature = Signature.getInstance(signatureType, this.provider);
               signature.initSign(privateKey);
               return new JavaSigner(signature);
            default:
               throw new CipherException("Do not know how to construct a signature for key algorithm [" + algorithm + "]");
         }
      }
      catch (CipherException e)
      {
         throw e;
      }
      catch (Exception e)
      {
         throw new CipherException(e);
      }
   }

   @Override
   public SignatureVerifier buildVerifier(PublicKey publicKey, DigestType digest, byte[] signatureBytes) throws CipherException
   {
      try
      {
         String algorithm = publicKey.getAlgorithm();
         switch (algorithm)
         {
            case "EC":
               String signatureType = digest.name() + "withECDSA";
               Signature signature = Signature.getInstance(signatureType, this.provider);
               signature.initVerify(publicKey);
               return new JavaVerifier(signature, signatureBytes);
            default:
               throw new CipherException("Do not know how to construct a signature verification for key algorithm [" + algorithm + "]");
         }
      }
      catch (Exception e)
      {
         throw new CipherException(e);
      }
   }
}
