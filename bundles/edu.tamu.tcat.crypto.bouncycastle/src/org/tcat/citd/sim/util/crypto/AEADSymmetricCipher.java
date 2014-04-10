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

import java.nio.ByteBuffer;

public interface AEADSymmetricCipher extends SymmetricCipher
{
   void processAADData(ByteBuffer input);
   
   void processAADData(byte[] input, int inputOffset, int inputLength);
   
   byte[] getMac();
   
   void setMac(byte[] mac);
}
