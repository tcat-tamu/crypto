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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

import edu.tamu.tcat.crypto.AsymmetricKeyBuilder;
import edu.tamu.tcat.crypto.CipherException;

/**
 * @since 1.1
 */
public class AsymmetricKeyBuilderImpl implements AsymmetricKeyBuilder
{
   @Override
   public KeyPair generateECKeyPair(Curve curve) throws CipherException
   {
      ECParameterSpec spec = ECNamedCurveTable.getParameterSpec(curve.getCurveName());
      try
      {
         KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
         generator.initialize(spec, new SecureRandom());
         return generator.generateKeyPair();
      }
      catch (Exception e)
      {
         throw new CipherException(e);
      }
   }
}
