package edu.tamu.tcat.crypto.impl;

import java.nio.ByteBuffer;
import java.security.Signature;

import edu.tamu.tcat.crypto.CipherException;
import edu.tamu.tcat.crypto.SignatureSigner;

public class JavaSigner implements SignatureSigner
{
   private Signature signature;

   public JavaSigner(Signature signature)
   {
      this.signature = signature;
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
   public byte[] processFinal() throws CipherException
   {
      try
      {
         return signature.sign();
      }
      catch (Exception e)
      {
         throw new CipherException(e);
      }
   }
}
