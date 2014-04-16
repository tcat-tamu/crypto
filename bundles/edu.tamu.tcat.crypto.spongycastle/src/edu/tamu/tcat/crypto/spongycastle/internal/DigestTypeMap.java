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

package edu.tamu.tcat.crypto.spongycastle.internal;

import java.util.Objects;

import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.digests.SHA224Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.digests.SHA384Digest;
import org.spongycastle.crypto.digests.SHA512Digest;

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