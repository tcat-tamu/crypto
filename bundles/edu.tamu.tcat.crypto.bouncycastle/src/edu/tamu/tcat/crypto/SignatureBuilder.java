package edu.tamu.tcat.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import edu.tamu.tcat.crypto.internal.Activator;
import edu.tamu.tcat.crypto.internal.JavaSigner;
import edu.tamu.tcat.crypto.internal.JavaVerifier;

public class SignatureBuilder
{
   public static SignatureSigner buildSigner(PrivateKey privateKey, DigestType digest) throws CipherException
   {
      try
      {
         String algorithm = privateKey.getAlgorithm();
         switch (algorithm)
         {
            case "EC":
               String signatureType = digest.name() + "withECDSA";
               Signature signature = Signature.getInstance(signatureType, Activator.getDefault().getBouncyCastleProvider());
               signature.initSign(privateKey);
               return new JavaSigner(signature);
            default:
               throw new CipherException("Do not know how to construct a signature for key algorithm [" + algorithm + "]");
         }
      }
      catch (CipherException e)
      {
         throw e;
      }
      catch (Exception e)
      {
         throw new CipherException(e);
      }
   }
   
   public static SignatureVerifier buildVerifier(PublicKey publicKey, DigestType digest, byte[] signatureBytes) throws CipherException
   {
      try
      {
         String algorithm = publicKey.getAlgorithm();
         switch (algorithm)
         {
            case "EC":
               String signatureType = digest.name() + "withECDSA";
               Signature signature = Signature.getInstance(signatureType, Activator.getDefault().getBouncyCastleProvider());
               signature.initVerify(publicKey);
               return new JavaVerifier(signature, signatureBytes);
            default:
               throw new CipherException("Do not know how to construct a signature verification for key algorithm [" + algorithm + "]");
         }
      }
      catch (Exception e)
      {
         throw new CipherException(e);
      }
   }
}
