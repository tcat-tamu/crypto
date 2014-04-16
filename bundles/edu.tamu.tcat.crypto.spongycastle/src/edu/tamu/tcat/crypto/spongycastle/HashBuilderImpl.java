package edu.tamu.tcat.crypto.spongycastle;

import edu.tamu.tcat.crypto.DigestType;
import edu.tamu.tcat.crypto.Hash;
import edu.tamu.tcat.crypto.HashBuilder;
import edu.tamu.tcat.crypto.spongycastle.internal.BouncyCastleHash;
import edu.tamu.tcat.crypto.spongycastle.internal.DigestTypeMap;

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
