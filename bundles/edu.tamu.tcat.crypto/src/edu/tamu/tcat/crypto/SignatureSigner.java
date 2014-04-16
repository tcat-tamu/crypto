package edu.tamu.tcat.crypto;

import java.nio.ByteBuffer;

public interface SignatureSigner
{
   /**
    * Add data to the data that is signed.
    * @param input The data to add in bytes.
    * @throws CipherException Thrown if the data cannot be processed.
    */
   void processData(byte[] input) throws CipherException;

   /**
    * Add data to the data that is signed.
    * @param input The data to add in bytes.
    * @param inputOffset The offset within the data to add
    * @param inputLength The length of the data to add.
    * @throws CipherException Thrown if the data cannot be processed.
    */
   void processData(byte[] input, int inputOffset, int inputLength) throws CipherException;
   
   /**
    * Add data to the data that is signed.
    * @param input The data to add.
    * @throws CipherException Thrown if the data cannot be processed.
    */
   void processData(ByteBuffer input) throws CipherException;
   
   /**
    * Finalize the signature and retrieve the result.
    * @return The signature in bytes.
    * @throws CipherException Thrown if the data cannot be processed.
    */
   byte[] processFinal() throws CipherException;
}
