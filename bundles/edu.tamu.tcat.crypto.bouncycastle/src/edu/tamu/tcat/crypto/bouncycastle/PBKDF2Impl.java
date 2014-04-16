/*******************************************************************************
 * Copyright © 2007-14, All Rights Reserved.
 * Texas Center for Applied Technology
 * Texas A&M Engineering Experiment Station
 * The Texas A&M University System
 * College Station, Texas, USA 77843
 *
 * Use is granted only to authorized licensee.
 * Proprietary information, not for redistribution.
 ******************************************************************************/

package edu.tamu.tcat.crypto.bouncycastle;

import java.util.Arrays;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

import edu.tamu.tcat.crypto.DigestType;
import edu.tamu.tcat.crypto.bouncycastle.internal.DigestTypeMap;
import edu.tamu.tcat.crypto.impl.BasicPBKDF2;

/**
 * @since 1.1
 */
public class PBKDF2Impl extends BasicPBKDF2
{
   private final Digest bouncyDigest;

   public PBKDF2Impl(DigestType digest)
   {
      super(digest);
      bouncyDigest = DigestTypeMap.getDigest(digest);
   }

   @Override
   public byte[] passwordToBytes(String password)
   {
      return PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password.toCharArray());
   }

   @Override
   public byte[] deriveKey(byte[] password, byte[] salt, int rounds, int keySizeInBytes) {
      PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(bouncyDigest);
      generator.init(password, salt, rounds);
      KeyParameter keyParameter = (KeyParameter)generator.generateDerivedMacParameters(keySizeInBytes * 8);
      return keyParameter.getKey();
   }

   @Override
   protected String deriveHash(byte[] password, int rounds, byte[] salt) {
      int outputSize = bouncyDigest.getDigestSize();
      
      String hashType;
      if (digest == DigestType.SHA1)
         hashType = "pbkdf2";
      else
         hashType = "pbkdf2-" + digest.name().toLowerCase();
      byte[] output = deriveKey(password, salt, rounds, outputSize);
      return "$" + hashType + "$" + rounds + "$" + Base64.encodeBase64String(salt).replace('+', '.') + "$" + Base64.encodeBase64String(output).replace('+', '.');
   }
   
   @Override
   protected boolean checkHash(byte[] password, String saltStr, String outputStr, DigestType digest, int rounds)
   {
      if (!Base64.isBase64(saltStr) || !Base64.isBase64(outputStr))
         return false;
      
      byte[] salt = Base64.decodeBase64(saltStr);
      byte[] output = Base64.decodeBase64(outputStr);
      int outputSize = bouncyDigest.getDigestSize();
      if (output.length != outputSize)
         return false;
      
      PBKDF2Impl pbkdf2 = new PBKDF2Impl(digest);
      byte[] candidate = pbkdf2.deriveKey(password, salt, rounds, outputSize);
      return Arrays.equals(candidate, output);
   }
}
