package org.tcat.citd.sim.util.crypto;

import org.tcat.citd.sim.util.crypto.internal.BouncyCastleHash;

public class HashBuilder
{
   public static Hash buildHash(DigestType type)
   {
      return new BouncyCastleHash(type.getDigest());
   }
}
