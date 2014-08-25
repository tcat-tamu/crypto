/*
 * Copyright 2014 Texas A&M Engineering Experiment Station
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.tamu.tcat.crypto.impl;

import java.security.SecureRandom;

import edu.tamu.tcat.crypto.DigestType;
import edu.tamu.tcat.crypto.PBKDF2;

public abstract class BasicPBKDF2 implements PBKDF2
{
   protected final DigestType digest;
   
   public BasicPBKDF2(DigestType digest)
   {
      this.digest = digest;
   }

   @Override
   public DigestType getDigest()
   {
      return digest;
   }

   @Override
   public byte[] deriveKey(String password, byte[] salt, int rounds, int keySizeInBytes) {
      return deriveKey(passwordToBytes(password), salt, rounds, keySizeInBytes);
   }
   
   @Override
   public byte[] deriveKey(String password, String salt, int rounds, int keySizeInBytes) {
      return deriveKey(password, passwordToBytes(salt), rounds, keySizeInBytes);
   }
   
   @Override
   public String deriveHash(String password) {
      return deriveHash(passwordToBytes(password));
   }
   
   @Override
   public String deriveHash(String password, int rounds) {
      return deriveHash(passwordToBytes(password), rounds);
   }
   
   @Override
   public String deriveHash(byte[] password) {
      return deriveHash(password, 10000);
   }
   
   @Override
   public String deriveHash(byte[] password, int rounds) {
      byte[] salt = new byte[16];
      new SecureRandom().nextBytes(salt);
    
      return deriveHash(password, rounds, salt);
   }
   
   protected abstract String deriveHash(byte[] password, int rounds, byte[] salt);
   
   @Override
   public boolean checkHash(String password, String hash)
   {
      return checkHash(passwordToBytes(password), hash);
   }
   
   @Override
   public boolean checkHash(byte[] password, String hash)
   {
      //Decoding and sanity checks
      String[] components = hash.split("\\$");
      if (components.length != 5 || components[0].length() != 0)
         return false;
      
      String hashType = components[1];
      String roundsStr = components[2];
      //NOTE: revert '.' to '+', which was previously converted to avoid issues with URL encoding of the derived hash (converting '+' to "%2B")
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
      return checkHash(password, saltStr, outputStr, digest, rounds);
   }

   protected abstract boolean checkHash(byte[] password, String saltStr, String outputStr, DigestType digest, int rounds);
}
