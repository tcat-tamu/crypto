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
package edu.tamu.tcat.crypto.bouncycastle.internal;

import java.nio.ByteBuffer;

import org.bouncycastle.crypto.Digest;

import edu.tamu.tcat.crypto.Hash;

public class BouncyCastleHash implements Hash
{
   private Digest digest;

   public BouncyCastleHash(Digest digest)
   {
      this.digest = digest;
   }

   @Override
   public int getOutputSize()
   {
      return digest.getDigestSize();
   }

   @Override
   public void processData(byte[] input, int inputOffset, int inputLength)
   {
      digest.update(input, inputOffset, inputLength);
   }

   @Override
   public void processData(ByteBuffer input)
   {
      processData(input.array(), input.position(), input.remaining());
   }

   @Override
   public void processFinal(byte[] output, int outputOffset)
   {
      digest.doFinal(output, outputOffset);
   }

   @Override
   public void processFinal(ByteBuffer output)
   {
      processFinal(output.array(), output.position());
   }
}
