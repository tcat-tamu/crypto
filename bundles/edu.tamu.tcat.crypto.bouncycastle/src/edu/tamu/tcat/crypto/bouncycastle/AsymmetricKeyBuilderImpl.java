package edu.tamu.tcat.crypto.bouncycastle;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

import edu.tamu.tcat.crypto.AsymmetricKeyBuilder;
import edu.tamu.tcat.crypto.CipherException;

/**
 * @since 1.1
 */
public class AsymmetricKeyBuilderImpl implements AsymmetricKeyBuilder
{
   @Override
   public KeyPair generateECKeyPair(Curve curve) throws CipherException
   {
      ECParameterSpec spec = ECNamedCurveTable.getParameterSpec(curve.getCurveName());
      try
      {
         KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
         generator.initialize(spec, new SecureRandom());
         return generator.generateKeyPair();
      }
      catch (Exception e)
      {
         throw new CipherException(e);
      }
   }
}
