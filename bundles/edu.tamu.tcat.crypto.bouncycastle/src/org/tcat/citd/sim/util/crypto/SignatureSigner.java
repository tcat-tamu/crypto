package org.tcat.citd.sim.util.crypto;

import java.nio.ByteBuffer;

public interface SignatureSigner
{
   void processData(byte[] input) throws CipherException;

   void processData(byte[] input, int inputOffset, int inputLength) throws CipherException;
   
   void processData(ByteBuffer input) throws CipherException;
   
   byte[] processFinal() throws CipherException;
}
