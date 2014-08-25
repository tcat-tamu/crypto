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
