package edu.tamu.tcat.crypto;

/**
 * @since 1.1
 */
public interface HashBuilder
{
   /**
    * Build a hash for a given digest type.
    * @param type The type of hash to build.
    * @return A {@link Hash} implementation to hash data.
    */
   public Hash buildHash(DigestType type);
}
