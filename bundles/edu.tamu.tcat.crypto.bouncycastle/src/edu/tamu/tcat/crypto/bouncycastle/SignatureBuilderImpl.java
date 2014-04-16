package edu.tamu.tcat.crypto.bouncycastle;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import edu.tamu.tcat.crypto.CipherException;
import edu.tamu.tcat.crypto.DigestType;
import edu.tamu.tcat.crypto.SignatureBuilder;
import edu.tamu.tcat.crypto.SignatureSigner;
import edu.tamu.tcat.crypto.SignatureVerifier;
import edu.tamu.tcat.crypto.bouncycastle.internal.Activator;
import edu.tamu.tcat.crypto.impl.JavaSigner;
import edu.tamu.tcat.crypto.impl.JavaVerifier;

public class SignatureBuilderImpl implements SignatureBuilder
{
   @Override
   public SignatureSigner buildSigner(PrivateKey privateKey, DigestType digest) throws CipherException
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
   
   @Override
   public SignatureVerifier buildVerifier(PublicKey publicKey, DigestType digest, byte[] signatureBytes) throws CipherException
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
