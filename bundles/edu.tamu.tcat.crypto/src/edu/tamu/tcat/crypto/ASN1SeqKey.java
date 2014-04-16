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
