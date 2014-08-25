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

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADBlockCipher;

import edu.tamu.tcat.crypto.AEADSymmetricCipher;
import edu.tamu.tcat.crypto.CipherException;

public class BouncyCastleAEADCipher implements AEADSymmetricCipher
{
   private final AEADBlockCipher cipher;
   private final int macSize;
   private final boolean encryption;
   private byte[] mac;
   
   public BouncyCastleAEADCipher(AEADBlockCipher cipher, int macSize, boolean encryption)
   {
      this.cipher = cipher;
      this.macSize = macSize;
      this.encryption = encryption;
   }
   
   @Override
   public void setMac(byte[] mac)
   {
      this.mac = mac;
   }
   
   @Override
   public int getUpdateSize(int inputSize)
   {
      return cipher.getUpdateOutputSize(inputSize);
   }
   
   @Override
   public int getFinalSize(int inputSize)
   {
      if (encryption)
         return cipher.getOutputSize(inputSize) - macSize;
      return cipher.getOutputSize(inputSize + macSize);
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
         if (encryption) {
            byte[] tmpOutput = new byte[cipher.getOutputSize(0)];
            int count = cipher.doFinal(tmpOutput, 0);
            int finalCount = count - macSize;
            System.arraycopy(tmpOutput, 0, output, outputOffset, finalCount);
            return finalCount;
         }
         int outputLength = processData(mac, 0, mac.length, output, outputOffset);
         outputLength += cipher.doFinal(output, outputOffset + outputLength);
         return outputLength;
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
   
   @Override
   public void processAADData(ByteBuffer input)
   {
      processAADData(input.array(), input.position(), input.remaining());
      input.position(input.limit());
   }
   
   @Override
   public void processAADData(byte[] input, int inputOffset, int inputLength)
   {
      cipher.processAADBytes(input, inputOffset, inputLength);
   }
   
   @Override
   public byte[] getMac()
   {
      return cipher.getMac();
   }
}
