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

public interface Hash
{
   /**
    * @return The output size of the hash in bytes.
    */
   int getOutputSize();

   /**
    * Add data to the content that is hashed.
    * @param input The input in bytes.
    * @param inputOffset The offset within the input.
    * @param inputLength The length of the input to add.
    */
   void processData(byte[] input, int inputOffset, int inputLength);
   
   /**
    * Add data to the content that is hashed.
    * @param input The input.
    */
   void processData(ByteBuffer input);
   
   /**
    * Finalize the hash and retrieve the output.
    * @param output The output in bytes.
    * @param outputOffset The offset within the output to store the hash.
    */
   void processFinal(byte[] output, int outputOffset);
   
   /**
    * Finalize the hash and retrieve the output.
    * @param output The output in which ot store the hash.
    */
   void processFinal(ByteBuffer output);
}
