package edu.tamu.tcat.crypto;


import static org.junit.Assert.assertArrayEquals;

import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import edu.tamu.tcat.crypto.CipherException;
import edu.tamu.tcat.crypto.DigestType;
import edu.tamu.tcat.crypto.Hash;
import edu.tamu.tcat.crypto.HashBuilder;
import edu.tamu.tcat.crypto.PBKDF2;

public class PBKDF2Test
{

   @Before
   public void setUp() throws Exception
   {
   }

   @After
   public void tearDown() throws Exception
   {
   }
   
   @Test
   public void testHash() throws CipherException
   {
      byte[] out = Hex.decode("a9993e364706816aba3e25717850c26c9cd0d89d");
      Hash hash = HashBuilder.buildHash(DigestType.SHA1);
      byte[] input = "abc".getBytes();
      hash.processData(input, 0, input.length);
      int outputSize = hash.getOutputSize();
      byte[] output = new byte[outputSize];
      hash.processFinal(output, 0);
      assertArrayEquals(out, output);
   }
   
   private void testSha1(String password, String salt, int rounds, int keySize, String result)
   {
      PBKDF2 pbkdf2 = new PBKDF2();
      pbkdf2.setDigest(DigestType.SHA1);
      byte[] derivedKey = pbkdf2.deriveKey(password, salt, rounds, keySize);
      
      byte[] expected = Hex.decode(result);
      Assert.assertArrayEquals(expected, derivedKey);
   }

   @Test
   public void test1Round()
   {
      testSha1("password", "salt", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6");
   }
   
   @Test
   public void test2Round()
   {
      testSha1("password", "salt", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
   }
   
   @Test
   public void test4096Round()
   {
      testSha1("password", "salt", 4096, 20, "4b007901b765489abead49d926f721d065a429c1");
   }
   
   @Test
   @Ignore  //This test takes a long time, but on last check it passed.
   public void test16777216Round()
   {
      testSha1("password", "salt", 16777216, 20, "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984");
   }
   
   @Test
   public void testLongerPass()
   {
      testSha1("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038");
   }
   
   @Test
   public void testNulls()
   {
      testSha1("pass\0word", "sa\0lt", 4096, 16, "56fa6aa75548099dcc37d7f03425e0c3");
   }
   
   @Test
   public void testPassword()
   {
      Assert.assertTrue(PBKDF2.checkHash("password",
            "$pbkdf2$1212$OB.dtnSEXZK8U5cgxU/GYQ$y5LKPOplRmok7CZp/aqVDVg8zGI"));
      Assert.assertTrue(PBKDF2.checkHash("\u0399\u03c9\u03b1\u03bd\u03bd\u03b7\u03c2",
            "$pbkdf2$1212$THDqatpidANpadlLeTeOEg$HV3oi1k5C5LQCgG1BMOL.BX4YZc"));
   }
   
   @Test
   public void testSha256Password()
   {
      Assert.assertTrue(PBKDF2.checkHash("password",
            "$pbkdf2-sha256$1212$4vjV83LKPjQzk31VI4E0Vw$hsYF68OiOUPdDZ1Fg.fJPeq1h/gXXY7acBp9/6c.tmQ"));
      Assert.assertTrue(PBKDF2.checkHash("\u0399\u03c9\u03b1\u03bd\u03bd\u03b7\u03c2",
            "$pbkdf2-sha256$1212$3SABFJGDtyhrQMVt1uABPw$WyaUoqCLgvz97s523nF4iuOqZNbp5Nt8do/cuaa7AiI"));
   }
   
   @Test
   public void testSha512Password()
   {
      Assert.assertTrue(PBKDF2.checkHash("password",
            "$pbkdf2-sha512$1212$RHY0Fr3IDMSVO/RSZyb5ow$eNLfBK.eVozomMr.1gYa1"
            + "7k9B7KIK25NOEshvhrSX.esqY3s.FvWZViXz4KoLlQI.BzY/YTNJOiKc5gBYFYGww"));
      Assert.assertTrue(PBKDF2.checkHash("\u0399\u03c9\u03b1\u03bd\u03bd\u03b7\u03c2",
            "$pbkdf2-sha512$1212$KkbvoKGsAIcF8IslDR6skQ$8be/PRmd88Ps8fmPowCJt"
            + "tH9G3vgxpG.Krjt3KT.NP6cKJ0V4Prarqf.HBwz0dCkJ6xgWnSj2ynXSV7MlvMa8Q"));
   }
   
   @Test
   public void testCreatePassword()
   {
      String hash = PBKDF2.deriveHash("password");
      Assert.assertTrue(PBKDF2.checkHash("password", hash));
   }

   @Test
   public void testCreate256Password()
   {
      String hash = PBKDF2.deriveHash("password", DigestType.SHA256);
      Assert.assertTrue(hash.startsWith("$pbkdf2-sha256$"));
      Assert.assertTrue(PBKDF2.checkHash("password", hash));
   }
   
   @Test
   public void testCreate512Password()
   {
      String hash = PBKDF2.deriveHash("password", DigestType.SHA512);
      Assert.assertTrue(hash.startsWith("$pbkdf2-sha512$"));
      Assert.assertTrue(PBKDF2.checkHash("password", hash));
   }
}
