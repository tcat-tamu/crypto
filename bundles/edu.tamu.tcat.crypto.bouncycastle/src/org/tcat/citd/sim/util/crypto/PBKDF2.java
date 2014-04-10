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

package org.tcat.citd.sim.util.crypto;

import java.security.SecureRandom;
import java.util.Arrays;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

public class PBKDF2
{
   private DigestType digest;

   public DigestType getDigest()
   {
      return digest;
   }

   public void setDigest(DigestType digest)
   {
      this.digest = digest;
   }
   
   public byte[] deriveKey(byte[] password, byte[] salt, int rounds, int keySizeInBytes) {
      PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(digest.getDigest());
      generator.init(password, salt, rounds);
      KeyParameter keyParameter = (KeyParameter)generator.generateDerivedMacParameters(keySizeInBytes * 8);
      return keyParameter.getKey();
   }

   public byte[] deriveKey(String password, String salt, int rounds, int keySizeInBytes) {
      return deriveKey(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password.toCharArray()), PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(salt.toCharArray()), rounds, keySizeInBytes);
   }
   
   public static String deriveHash(String password) {
      return deriveHash(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password.toCharArray()));
   }
   
   public static String deriveHash(String password, DigestType digest) {
      return deriveHash(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password.toCharArray()), digest);
   }
   
   public static String deriveHash(String password, DigestType digest, int rounds) {
      return deriveHash(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password.toCharArray()), digest, rounds);
   }
   
   public static String deriveHash(byte[] password) {
      return deriveHash(password, DigestType.SHA1);
   }
   
   public static String deriveHash(byte[] password, DigestType digest) {
      return deriveHash(password, digest, 10000);
   }

   public static String deriveHash(byte[] password, DigestType digest, int rounds) {
      byte[] salt = new byte[16];
      new SecureRandom().nextBytes(salt);
    
      return deriveHash(password, digest, rounds, salt);
   }
   
   private static String deriveHash(byte[] password, DigestType digest, int rounds, byte[] salt) {
      PBKDF2 pbkdf2 = new PBKDF2();
      pbkdf2.setDigest(digest);
      int outputSize = digest.getDigest().getDigestSize();
      
      String hashType;
      if (digest == DigestType.SHA1)
         hashType = "pbkdf2";
      else
         hashType = "pbkdf2-" + digest.name().toLowerCase();
      byte[] output = pbkdf2.deriveKey(password, salt, rounds, outputSize);
      return "$" + hashType + "$" + rounds + "$" + Base64.encodeBase64String(salt).replace('+', '.') + "$" + Base64.encodeBase64String(output).replace('+', '.');
   }
   
   public static boolean checkHash(String password, String hash)
   {
      return checkHash(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password.toCharArray()), hash);
   }
   
   public static boolean checkHash(byte[] password, String hash)
   {
      //Decoding and sanity checks
      String[] components = hash.split("\\$");
      if (components.length != 5 || components[0].length() != 0)
         return false;
      
      String hashType = components[1];
      String roundsStr = components[2];
      String saltStr = components[3].replace('.', '+');
      String outputStr = components[4].replace('.', '+');
      
      DigestType digest;
      if (!hashType.startsWith("pbkdf2"))
         return false;
      if (hashType.equals("pbkdf2"))
         digest = DigestType.SHA1;
      else if (hashType.startsWith("pbkdf2-"))
      {
         String type = hashType.substring(7).toUpperCase();
         try
         {
            digest = DigestType.valueOf(type);
         }
         catch (Exception e)
         {
            return false;
         }
      }
      else
         return false;
      
      int rounds;
      try
      {
         rounds = Integer.parseInt(roundsStr);
      }
      catch (NumberFormatException e)
      {
         return false;
      }
      if (!Base64.isBase64(saltStr) || !Base64.isBase64(outputStr))
         return false;
      
      byte[] salt = Base64.decodeBase64(saltStr);
      byte[] output = Base64.decodeBase64(outputStr);
      int outputSize = digest.getDigest().getDigestSize();
      if (output.length != outputSize)
         return false;
      
      PBKDF2 pbkdf2 = new PBKDF2();
      pbkdf2.setDigest(digest);
      byte[] candidate = pbkdf2.deriveKey(password, salt, rounds, outputSize);
      return Arrays.equals(candidate, output);
   }
}
