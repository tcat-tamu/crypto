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

public interface SymmetricCipher
{
   void processData(ByteBuffer input, ByteBuffer output);
   
   int processData(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset);
   
   void processFinal(ByteBuffer output) throws CipherException;
   
   int processFinal(byte[] output, int outputOffset) throws CipherException;
   
   int getUpdateSize(int inputSize);
   
   int getFinalSize(int inputSize);
}
