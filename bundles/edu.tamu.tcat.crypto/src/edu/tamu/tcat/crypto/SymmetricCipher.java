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

public interface SymmetricCipher
{
   /**
    * Encrypt or decrypt a block of data.  Note: The output size may not be the same as the input.
    * Use {@link #getUpdateSize(int)} to determine the output size.
    * @param input The input data to encrypt/decrypt.
    * @param output The encrypted/decrypted data.
    */
   void processData(ByteBuffer input, ByteBuffer output);
   
   /**
    * Encrypt or decrypt a block of data.  Note: The output size may not be the same as the input.
    * Use {@link #getUpdateSize(int)} to determine the output size.
    * @param input The input data to encrypt/decrypt in bytes.
    * @param inputOffset The offset within the data to encrypt/decrypt.
    * @param inputLength The length of the data to encrypt/decrypt.
    * @param output The encrypted/decrypted data in bytes.
    * @param outputOffset The offset within the output to store the encrypted data/decrypted.
    * @return The number of bytes stored in the output.
    */
   int processData(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset);
   
   /**
    * Finalize the encryption/decryption and get the remaining output.
    * Use {@link #getFinalSize(int)} to determine the output size.
    * @param output The encrypted/decryted data.
    * @throws CipherException Thrown if the encyption/decription fails.  Typically this is in authenticating ciphers.
    */
   void processFinal(ByteBuffer output) throws CipherException;
   
   /**
    * Finalize the encryption/decryption and get the remaining output.
    * Use {@link #getFinalSize(int)} to determine the output size.
    * @param output The encrypted/decryted data in bytes.
    * @param outputOffset The offset within the output to store the encrypted data/decrypted.
    * @return The number of bytes stored in the output.
    * @throws CipherException Thrown if the encyption/decription fails.  Typically this is in authenticating ciphers.
    */
   int processFinal(byte[] output, int outputOffset) throws CipherException;
   
   /**
    * Get the number of output bytes for a given number of input bytes.
    * @param inputSize The number of input bytes.
    * @return The number of output bytes that will be produced for this input size.
    */
   int getUpdateSize(int inputSize);
   
   /**
    * Get the number of output bytes for the final operation.
    * @param inputSize The number of input bytes provided before finalization.
    * @return The number of output bytes that will be provided by processing and final combined.
    */
   int getFinalSize(int inputSize);
}
