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

import java.security.PublicKey;

/**
 * @since 1.1
 */
public interface X509KeyDecoder
{
   /**
    * Decodes a public key from a byte array using
    * @param type one of "RSA", "DSA", "EC", etc.
    * @param encodedKey byte[] representing the public key in the X.509 format
    * @return the public key represented by the X.509 structure
    * @throws EncodingException
    */
   public PublicKey decodePublicKey(String type, byte[] encodedKey) throws EncodingException;
}
