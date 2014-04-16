package edu.tamu.tcat.crypto;

import java.nio.ByteBuffer;

public interface Hash
{
   /**
    * @return The output size of the hash in bytes.
    */
   int getOutputSize();

   /**
    * Add data to the content that is hashed.
    * @param input The input in bytes.
    * @param inputOffset The offset within the input.
    * @param inputLength The length of the input to add.
    */
   void processData(byte[] input, int inputOffset, int inputLength);
   
   /**
    * Add data to the content that is hashed.
    * @param input The input.
    */
   void processData(ByteBuffer input);
   
   /**
    * Finalize the hash and retrieve the output.
    * @param output The output in bytes.
    * @param outputOffset The offset within the output to store the hash.
    */
   void processFinal(byte[] output, int outputOffset);
   
   /**
    * Finalize the hash and retrieve the output.
    * @param output The output in which ot store the hash.
    */
   void processFinal(ByteBuffer output);
}
