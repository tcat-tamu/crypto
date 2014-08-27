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

public interface SignatureSigner
{
   /**
    * Add data to the data that is signed.
    * @param input The data to add in bytes.
    * @throws CipherException Thrown if the data cannot be processed.
    */
   void processData(byte[] input) throws CipherException;

   /**
    * Add data to the data that is signed.
    * @param input The data to add in bytes.
    * @param inputOffset The offset within the data to add
    * @param inputLength The length of the data to add.
    * @throws CipherException Thrown if the data cannot be processed.
    */
   void processData(byte[] input, int inputOffset, int inputLength) throws CipherException;
   
   /**
    * Add data to the data that is signed.
    * @param input The data to add.
    * @throws CipherException Thrown if the data cannot be processed.
    */
   void processData(ByteBuffer input) throws CipherException;
   
   /**
    * Finalize the signature and retrieve the result.
    * @return The signature in bytes.
    * @throws CipherException Thrown if the data cannot be processed.
    */
   byte[] processFinal() throws CipherException;
}
