package edu.tamu.tcat.crypto.impl;

import java.nio.ByteBuffer;
import java.security.Signature;

import edu.tamu.tcat.crypto.CipherException;
import edu.tamu.tcat.crypto.SignatureVerifier;

public class JavaVerifier implements SignatureVerifier
{
   private Signature signature;
   private byte[] signatureBytes;

   public JavaVerifier(Signature signature, byte[] signatureBytes)
   {
      this.signature = signature;
      this.signatureBytes = signatureBytes;
   }
   
   @Override
   public void processData(byte[] input) throws CipherException
   {
      processData(input, 0, input.length);
   }

   @Override
   public void processData(byte[] input, int inputOffset, int inputLength) throws CipherException
   {
      try
      {
         signature.update(input, inputOffset, inputLength);
      }
      catch (Exception e)
      {
         throw new CipherException(e);
      }
   }

   @Override
   public void processData(ByteBuffer input) throws CipherException
   {
      try
      {
         signature.update(input);
      }
      catch (Exception e)
      {
         throw new CipherException(e);
      }
   }
   
   @Override
   public boolean verify() throws CipherException
   {
      try
      {
         return signature.verify(signatureBytes);
      }
      catch (Exception e)
      {
         throw new CipherException(e);
      }
   }
}
