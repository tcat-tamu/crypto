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

package edu.tamu.tcat.crypto;

/**
 * @since 1.1
 */
public interface PBKDF2
{
   DigestType getDigest();

   byte[] passwordToBytes(String password);
   
   byte[] deriveKey(byte[] password, byte[] salt, int rounds, int keySizeInBytes);

   byte[] deriveKey(String password, byte[] salt, int rounds, int keySizeInBytes);

   byte[] deriveKey(String password, String salt, int rounds, int keySizeInBytes);

   
   String deriveHash(String password);
   
   String deriveHash(String password, int rounds);
   
   String deriveHash(byte[] password);
   
   String deriveHash(byte[] password, int rounds);
   
   /**
    * Check the password against the PBKDF2 hash.  Note, the digest for this PBKDF2
    * need to match the one used in the hash.
    * @param password The password to check
    * @param hash The hashed version of the password.
    * @return <code>true</code> if the password matches the hash, <code>false</code> otherwise.
    */
   boolean checkHash(String password, String hash);
   
   /**
    * Check the password against the PBKDF2 hash.  Note, the digest for this PBKDF2
    * need to match the one used in the hash.
    * @param password The password to check
    * @param hash The hashed version of the password.
    * @return <code>true</code> if the password matches the hash, <code>false</code> otherwise.
    */
   boolean checkHash(byte[] password, String hash);
}
