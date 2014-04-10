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

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.util.Memoable;

public enum DigestType {
   SHA1(new SHA1Digest()),
   SHA224(new SHA224Digest()),
   SHA256(new SHA256Digest()),
   SHA384(new SHA384Digest()),
   SHA512(new SHA512Digest()),
   ;

   private final Digest digest;

   DigestType(Digest digest) {
      this.digest = digest;
   }

   Digest getDigest()
   {
      //We need to copy the digest before returning since the digest is stateful.
      return (Digest)((Memoable)digest).copy();
   }
}