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
package edu.tamu.tcat.crypto.bouncycastle;

import edu.tamu.tcat.crypto.DigestType;
import edu.tamu.tcat.crypto.Hash;
import edu.tamu.tcat.crypto.HashBuilder;
import edu.tamu.tcat.crypto.bouncycastle.internal.BouncyCastleHash;
import edu.tamu.tcat.crypto.bouncycastle.internal.DigestTypeMap;

/**
 * @since 1.1
 */
public class HashBuilderImpl implements HashBuilder
{
   @Override
   public Hash buildHash(DigestType type)
   {
      return new BouncyCastleHash(DigestTypeMap.getDigest(type));
   }
}
