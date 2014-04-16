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
   
   boolean checkHash(String password, String hash);
   
   boolean checkHash(byte[] password, String hash);
}
