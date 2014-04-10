package org.tcat.citd.sim.util.crypto;

import java.nio.ByteBuffer;

public interface Hash
{
   int getOutputSize();

   void processData(byte[] input, int inputOffset, int inputLength);
   
   void processData(ByteBuffer input);
   
   void processFinal(byte[] output, int outputOffset);
   
   void processFinal(ByteBuffer output);
}
