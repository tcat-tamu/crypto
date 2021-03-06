/*
 * Copyright 2014 Texas A&M Engineering Experiment Station
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.tamu.tcat.crypto.spongycastle;

import org.spongycastle.crypto.BlockCipher;
import org.spongycastle.crypto.BufferedBlockCipher;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.modes.AEADBlockCipher;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.modes.GCMBlockCipher;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;

import edu.tamu.tcat.crypto.AEADSymmetricCipher;
import edu.tamu.tcat.crypto.CipherException;
import edu.tamu.tcat.crypto.SymmetricCipher;
import edu.tamu.tcat.crypto.SymmetricCipherBuilder;
import edu.tamu.tcat.crypto.spongycastle.internal.BouncyCastleAEADCipher;
import edu.tamu.tcat.crypto.spongycastle.internal.BouncyCastleBlockCipher;


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
