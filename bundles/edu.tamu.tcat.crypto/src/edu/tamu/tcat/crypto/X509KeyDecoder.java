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
