package edu.tamu.tcat.crypto;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.PrivateKey;
import java.security.PublicKey;

import edu.tamu.tcat.crypto.DigestType;
import edu.tamu.tcat.crypto.SignatureBuilder;
import edu.tamu.tcat.crypto.SignatureSigner;
import edu.tamu.tcat.crypto.SignatureVerifier;

public class AsymmetricKeyTest
{
   public void testSign(PrivateKey privateKey, PublicKey publicKey) throws Exception
   {
      SignatureSigner signer = SignatureBuilder.buildSigner(privateKey, DigestType.SHA512);
      
      byte[] message = "This is my message".getBytes();
      signer.processData(message);
      byte[] signature = signer.processFinal();
      
      SignatureVerifier verifier = SignatureBuilder.buildVerifier(publicKey, DigestType.SHA512, signature);
      verifier.processData(message);
      assertTrue(verifier.verify());
      
      verifier = SignatureBuilder.buildVerifier(publicKey, DigestType.SHA512, signature);
      verifier.processData("This is my mad messages".getBytes());
      assertFalse(verifier.verify());
   }
}
