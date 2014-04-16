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

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import edu.tamu.tcat.crypto.AEADSymmetricCipher;
import edu.tamu.tcat.crypto.CipherException;
import edu.tamu.tcat.crypto.SymmetricCipher;
import edu.tamu.tcat.crypto.SymmetricCipherBuilder;
import edu.tamu.tcat.crypto.bouncycastle.internal.BouncyCastleAEADCipher;
import edu.tamu.tcat.crypto.bouncycastle.internal.BouncyCastleBlockCipher;


/**
 * @since 1.1
 */
public class SymmetricCipherBuilderImpl implements SymmetricCipherBuilder
{
   @Override
   public SymmetricCipher buildCipher(Cipher cipher, Mode mode, boolean encryption, byte[] key, byte[] iv) throws CipherException
   {
      ParametersWithIV cipherParameters = new ParametersWithIV(new KeyParameter(key), iv);
      BlockCipher underlyingCipher = null;
      switch (cipher)
      {
         case AES128:
         case AES192:
         case AES256:
            underlyingCipher = new AESEngine();
            break;
      }
      BlockCipher blockCipher = null;
      switch (mode)
      {
         case CBC:
            blockCipher = new CBCBlockCipher(underlyingCipher);
            break;
         case GCM:
            throw new CipherException("GCM mode is authenticating encryption; use buildAEADCipher instead");
      }
      BufferedBlockCipher bufferedBlockCipher = new PaddedBufferedBlockCipher(blockCipher);
      bufferedBlockCipher.init(encryption, cipherParameters);
      
      return new BouncyCastleBlockCipher(bufferedBlockCipher);
   }
   
   @Override
   public AEADSymmetricCipher buildAEADCipher(Cipher cipher, Mode mode, boolean encryption, byte[] key, byte[] iv) throws CipherException
   {
      ParametersWithIV cipherParameters = new ParametersWithIV(new KeyParameter(key), iv);
      BlockCipher underlyingCipher = null;
      int macSize = 0;
      switch (cipher)
      {
         case AES128:
         case AES192:
         case AES256:
            underlyingCipher = new AESEngine();
            break;
      }
      AEADBlockCipher aeadCipher = null;
      switch (mode)
      {
         case CBC:
            throw new CipherException(mode + " is not an authenticating encryption mode; use buildCipher instead");
         case GCM:
            aeadCipher = new GCMBlockCipher(underlyingCipher);
            macSize = underlyingCipher.getBlockSize();
            break;
      }
      aeadCipher.init(encryption, cipherParameters);
      
      return new BouncyCastleAEADCipher(aeadCipher, macSize, encryption);
   }
}
