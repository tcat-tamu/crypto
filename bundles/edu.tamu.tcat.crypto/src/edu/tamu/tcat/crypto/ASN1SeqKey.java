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

import java.security.PrivateKey;

/**
 * @since 1.1
 */
public interface ASN1SeqKey
{
   /**
    * Decodes a private key from a byte array using ASN1Sequence encoding
    * @param type one of "RSA", "DSA", "EC", etc.
    * @param encodedKey byte[] representing the private key in the X.509 ASN1Sequence format
    * @return the private key represented by the X.509 structure
    * @throws EncodingException
    */
   public PrivateKey decodePrivateKey(String type, byte[] encodedKey) throws EncodingException;

   /**
    * Encode a private key into a byte array
    * @param key The key to encode.
    * @return The encoded key in the X.509 ASN1Sequence format.
    * @throws EncodingException
    */
   public byte[] encodeKey(PrivateKey key) throws EncodingException;
}
