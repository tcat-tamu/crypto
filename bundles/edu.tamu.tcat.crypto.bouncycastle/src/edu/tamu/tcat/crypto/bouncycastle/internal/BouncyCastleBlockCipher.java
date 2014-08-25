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

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;

import edu.tamu.tcat.crypto.CipherException;
import edu.tamu.tcat.crypto.SymmetricCipher;

public class BouncyCastleBlockCipher implements SymmetricCipher
{
   private final BufferedBlockCipher cipher;
   
   public BouncyCastleBlockCipher(BufferedBlockCipher cipher)
   {
      this.cipher = cipher;
   }
   
   @Override
   public int getUpdateSize(int inputSize)
   {
      return cipher.getUpdateOutputSize(inputSize);
   }
   
   @Override
   public int getFinalSize(int inputSize)
   {
      return cipher.getOutputSize(inputSize);
   }
   
   @Override
   public void processData(ByteBuffer input, ByteBuffer output)
   {
      int outputLength = processData(input.array(), input.position(), input.remaining(), output.array(), output.position());
      input.position(input.limit());
      output.position(output.position() + outputLength);
   }
   
   @Override
   public int processData(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
   {
      return cipher.processBytes(input, inputOffset, inputLength, output, outputOffset);
   }
   
   @Override
   public void processFinal(ByteBuffer output) throws CipherException
   {
      int outputLength = processFinal(output.array(), output.position());
      output.position(output.position() + outputLength);
   }
   
   @Override
   public int processFinal(byte[] output, int outputOffset) throws CipherException
   {
      try
      {
         return cipher.doFinal(output, outputOffset);
      }
      catch (IllegalStateException e)
      {
         throw new CipherException(e);
      }
      catch (InvalidCipherTextException e)
      {
         throw new CipherException(e);
      }
   }
}
