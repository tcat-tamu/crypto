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
