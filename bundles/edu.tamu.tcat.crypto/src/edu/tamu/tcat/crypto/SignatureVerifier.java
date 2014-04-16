package edu.tamu.tcat.crypto;

import java.nio.ByteBuffer;

public interface SignatureVerifier
{
   /**
    * Add data to the data that to be verified.
    * @param input The data to add in bytes.
    * @throws CipherException Thrown if the data cannot be processed.
    */
   void processData(byte[] input) throws CipherException;
   
   /**
    * Add data to the data that to be verified.
    * @param input The data to add in bytes.
    * @param inputOffset The offset within the data.
    * @param inputLength The length of the data to process.
    * @throws CipherException Thrown if the data cannot be processed.
    */
   void processData(byte[] input, int inputOffset, int inputLength) throws CipherException;
   
   /**
    * Add data to the data that to be verified.
    * @param input The data to add.
    * @throws CipherException Thrown if the data cannot be processed.
    */
   void processData(ByteBuffer input) throws CipherException;
   
   /**
    * Finalize the signature and verify.
    * @return <code>true</code> if the signature is valid, <code>false</code> otherwise.
    * @throws CipherException Thrown if the data cannot be processed.
    */
   boolean verify() throws CipherException;
}
