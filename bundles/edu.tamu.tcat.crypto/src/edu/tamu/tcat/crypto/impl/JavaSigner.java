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
package edu.tamu.tcat.crypto.impl;

import java.nio.ByteBuffer;
import java.security.Signature;

import edu.tamu.tcat.crypto.CipherException;
import edu.tamu.tcat.crypto.SignatureSigner;

public class JavaSigner implements SignatureSigner
{
   private Signature signature;

   public JavaSigner(Signature signature)
   {
      this.signature = signature;
   }

   @Override
   public void processData(byte[] input) throws CipherException
   {
      processData(input, 0, input.length);
   }

   @Override
   public void processData(byte[] input, int inputOffset, int inputLength) throws CipherException
   {
      try
      {
         signature.update(input, inputOffset, inputLength);
      }
      catch (Exception e)
      {
         throw new CipherException(e);
      }
   }

   @Override
   public void processData(ByteBuffer input) throws CipherException
   {
      try
      {
         signature.update(input);
      }
      catch (Exception e)
      {
         throw new CipherException(e);
      }
   }
   
   @Override
   public byte[] processFinal() throws CipherException
   {
      try
      {
         return signature.sign();
      }
      catch (Exception e)
      {
         throw new CipherException(e);
      }
   }
}
