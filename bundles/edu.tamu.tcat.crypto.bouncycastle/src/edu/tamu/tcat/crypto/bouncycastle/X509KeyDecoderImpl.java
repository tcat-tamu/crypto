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

package edu.tamu.tcat.crypto.bouncycastle;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import edu.tamu.tcat.crypto.EncodingException;
import edu.tamu.tcat.crypto.X509KeyDecoder;
import edu.tamu.tcat.crypto.bouncycastle.internal.Activator;

public class X509KeyDecoderImpl implements X509KeyDecoder
{
   @Override
   public PublicKey decodePublicKey(String type, byte[] encodedKey) throws EncodingException
   {
      try
      {
         X509EncodedKeySpec spec = new X509EncodedKeySpec(encodedKey);
         KeyFactory factory = KeyFactory.getInstance(type, Activator.getDefault().getBouncyCastleProvider());
         PublicKey key = factory.generatePublic(spec);
         return key;
      }
      catch (NoSuchAlgorithmException | InvalidKeySpecException e)
      {
         throw new EncodingException("Failed decoding type ["+type+"]", e);
      }
   }
}
