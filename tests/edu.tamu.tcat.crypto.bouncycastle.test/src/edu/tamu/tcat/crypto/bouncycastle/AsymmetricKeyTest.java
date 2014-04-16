package edu.tamu.tcat.crypto.bouncycastle;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.Before;

import edu.tamu.tcat.crypto.CryptoProvider;
import edu.tamu.tcat.crypto.DigestType;
import edu.tamu.tcat.crypto.SignatureSigner;
import edu.tamu.tcat.crypto.SignatureVerifier;
import edu.tamu.tcat.crypto.bouncycastle.BouncyCastleCryptoProvider;

public class AsymmetricKeyTest
{
   protected CryptoProvider provider;
   
   @Before
   public void getProvider()
   {
      provider = new BouncyCastleCryptoProvider();
   }
   
   public void testSign(PrivateKey privateKey, PublicKey publicKey) throws Exception
   {
      SignatureSigner signer = provider.getSignatureBuilder().buildSigner(privateKey, DigestType.SHA512);
      
      byte[] message = "This is my message".getBytes();
      signer.processData(message);
      byte[] signature = signer.processFinal();
      
      SignatureVerifier verifier = provider.getSignatureBuilder().buildVerifier(publicKey, DigestType.SHA512, signature);
      verifier.processData(message);
      assertTrue(verifier.verify());
      
      verifier = provider.getSignatureBuilder().buildVerifier(publicKey, DigestType.SHA512, signature);
      verifier.processData("This is my mad messages".getBytes());
      assertFalse(verifier.verify());
   }
}
