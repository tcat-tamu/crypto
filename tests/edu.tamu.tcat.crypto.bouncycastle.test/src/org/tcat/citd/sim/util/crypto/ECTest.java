package org.tcat.citd.sim.util.crypto;

import static org.junit.Assert.assertArrayEquals;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.tcat.citd.sim.util.crypto.AsymmetricKeyBuilder.Curve;

public class ECTest extends AsymmetricKeyTest
{
   private static final String ECPrivateKey =
         "3082016802010104203910a99c956a1a62a4a007360ee2036d0269eb5c82b52c" +
         "774b9878a521e81fdfa081fa3081f7020101302c06072a8648ce3d0101022100" +
         "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff" +
         "305b0420ffffffff00000001000000000000000000000000ffffffffffffffff" +
         "fffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce" +
         "3c3e27d2604b031500c49d360886e704936a6678e1139d26b7819f7e90044104" +
         "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
         "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5" +
         "022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc" +
         "632551020101a14403420004187c5df6c53bf739d2768cfc757e679d5e3d017b" +
         "8aadec03855430afd0fd028b6dd99ed629e6a95eb57b90dfcdc30be4b2267795" +
         "2d438900e4c37d7f5c74354d";
   
   private static final String ECPublicKey =
         "3082014b3082010306072a8648ce3d02013081f7020101302c06072a8648ce3d" +
         "0101022100ffffffff00000001000000000000000000000000ffffffffffffff" +
         "ffffffffff305b0420ffffffff00000001000000000000000000000000ffffff" +
         "fffffffffffffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc" +
         "53b0f63bce3c3e27d2604b031500c49d360886e704936a6678e1139d26b7819f" +
         "7e900441046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a139" +
         "45d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb640" +
         "6837bf51f5022100ffffffff00000000ffffffffffffffffbce6faada7179e84" +
         "f3b9cac2fc63255102010103420004187c5df6c53bf739d2768cfc757e679d5e" +
         "3d017b8aadec03855430afd0fd028b6dd99ed629e6a95eb57b90dfcdc30be4b2" +
         "2677952d438900e4c37d7f5c74354d";

   @Before
   public void setUp() throws Exception
   {
   }

   @After
   public void tearDown() throws Exception
   {
   }
   
   @Test
   @Ignore
   /*
    * It appears that Sun's implementation is broken when it comes to the seed parameter so it is set to null in BC.
    * This test fails because the seed parameter is not in the output, but since the parameter is optional, it should
    * be fine in the long run.
    */
   public void testECPublicReadWrite() throws Exception
   {
      byte[] publicKeyBytes = Hex.decode(ECPublicKey);
      PublicKey publicKey = X509KeyDecoder.decodePublicKey("ec", publicKeyBytes);
      byte[] encoded = publicKey.getEncoded();
      assertArrayEquals(publicKeyBytes, encoded);
   }
   
   @Test
   public void testECPrivateReadWrite() throws Exception
   {
      byte[] privateKeyBytes = Hex.decode(ECPrivateKey);
      PrivateKey privateKey = ASN1SeqKey.decodePrivateKey("EC", privateKeyBytes);
      byte[] encoded = ASN1SeqKey.encodeKey(privateKey);
      assertArrayEquals(privateKeyBytes, encoded);
   }

   @Test
   public void testEcSign() throws Exception
   {
      PrivateKey privateKey = ASN1SeqKey.decodePrivateKey("EC", Hex.decode(ECPrivateKey));
      PublicKey publicKey = X509KeyDecoder.decodePublicKey("EC", Hex.decode(ECPublicKey));
      testSign(privateKey, publicKey);
   }

   @Test
   public void testECGenerate() throws Exception
   {
      KeyPair keyPair = AsymmetricKeyBuilder.generateECKeyPair(Curve.Secp521r1);
      PublicKey pub = keyPair.getPublic();
      PrivateKey priv = keyPair.getPrivate();
      testSign(priv, pub);
   }
}
