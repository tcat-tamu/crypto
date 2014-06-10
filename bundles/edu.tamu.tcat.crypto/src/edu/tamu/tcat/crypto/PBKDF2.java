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
