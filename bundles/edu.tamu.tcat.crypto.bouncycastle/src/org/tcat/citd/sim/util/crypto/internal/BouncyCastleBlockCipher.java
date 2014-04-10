/*******************************************************************************
 * Copyright © 2007-14, All Rights Reserved.
 * Texas Center for Applied Technology
 * Texas A&M Engineering Experiment Station
 * The Texas A&M University System
 * College Station, Texas, USA 77843
 *
 * Use is granted only to authorized licensee.
 * Proprietary information, not for redistribution.
 ******************************************************************************/

package org.tcat.citd.sim.util.crypto.internal;

import java.nio.ByteBuffer;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.tcat.citd.sim.util.crypto.CipherException;
import org.tcat.citd.sim.util.crypto.SymmetricCipher;

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
