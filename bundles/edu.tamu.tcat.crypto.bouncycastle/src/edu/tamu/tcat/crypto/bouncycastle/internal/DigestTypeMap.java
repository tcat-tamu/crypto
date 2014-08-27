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

package edu.tamu.tcat.crypto.bouncycastle.internal;

import java.util.Objects;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

import edu.tamu.tcat.crypto.DigestType;

public class DigestTypeMap {
   
   public static Digest getDigest(DigestType type)
   {
      Objects.requireNonNull(type);
      switch (type)
      {
         case SHA1:
            return new SHA1Digest();
         case SHA224:
            return new SHA224Digest();
         case SHA256:
            return new SHA256Digest();
         case SHA384:
            return new SHA384Digest();
         case SHA512:
            return new SHA512Digest();
         default:
            throw new IllegalArgumentException();
      }
   }
}