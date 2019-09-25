package edu.tamu.tcat.crypto.bouncycastle;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.nio.charset.Charset;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;

import edu.tamu.tcat.crypto.CryptoProvider;
import edu.tamu.tcat.crypto.DigestType;
import edu.tamu.tcat.crypto.SignatureSigner;
import edu.tamu.tcat.crypto.SignatureVerifier;

public class AsymmetricKeyTest
{
   protected static final byte[] signedMessage = "Here is my message".getBytes(Charset.forName("UTF8"));
   protected CryptoProvider provider;

   @Before
   public void getProvider()
   {
      BouncyCastleCryptoProvider bccp = new BouncyCastleCryptoProvider();
      bccp.setProvider(new BouncyCastleProvider());
      provider = bccp;
   }

   public void testVerify(PublicKey publicKey, byte[] signature) throws Exception
   {
      SignatureVerifier verifier = provider.getSignatureBuilder().buildVerifier(publicKey, DigestType.SHA512, signature);
      verifier.processData(signedMessage);
      assertTrue(verifier.verify());

      verifier = provider.getSignatureBuilder().buildVerifier(publicKey, DigestType.SHA512, signature);
      verifier.processData("This is my mad messages".getBytes());
      assertFalse(verifier.verify());
   }

   public void testSign(PrivateKey privateKey, PublicKey publicKey) throws Exception
   {
      SignatureSigner signer = provider.getSignatureBuilder().buildSigner(privateKey, DigestType.SHA512);

      signer.processData(signedMessage);
      byte[] signature = signer.processFinal();

      SignatureVerifier verifier = provider.getSignatureBuilder().buildVerifier(publicKey, DigestType.SHA512, signature);
      verifier.processData(signedMessage);
      assertTrue(verifier.verify());

      verifier = provider.getSignatureBuilder().buildVerifier(publicKey, DigestType.SHA512, signature);
      verifier.processData("This is my mad messages".getBytes());
      assertFalse(verifier.verify());
   }
}
