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

import java.nio.ByteBuffer;

/**
 * An Authenticating {@link SymmetricCipher}.
 */
public interface AEADSymmetricCipher extends SymmetricCipher
{
   /**
    * Add additional authenticated data.  Must be called before any encryption.
    * @param input The authenticated data.
    */
   void processAADData(ByteBuffer input);
   
   /**
    * Add additional authenticated data.  Must be called before any encryption.
    * @param input The authenticated data.
    * @param inputOffset The offset within the data to authenticate.
    * @param inputLength The length of the data to authenticate.
    */
   void processAADData(byte[] input, int inputOffset, int inputLength);
   
   /**
    * Get the MAC or tag used to authenticate the data.
    * This must not be called before the end of the encryption operation.
    * @return The authenticating data in bytes.
    */
   byte[] getMac();
   
   /**
    * Set the MAC or tag used to authenticate during decryption.  This must be called
    * before {@link #processFinal(ByteBuffer)} or {@link #processFinal(byte[], int)}.
    * @param mac The MAC or tag used to authenticate the data.
    */
   void setMac(byte[] mac);
}
