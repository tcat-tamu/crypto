package edu.tamu.tcat.crypto;

import edu.tamu.tcat.crypto.internal.BouncyCastleHash;

public class HashBuilder
{
   public static Hash buildHash(DigestType type)
   {
      return new BouncyCastleHash(type.getDigest());
   }
}
