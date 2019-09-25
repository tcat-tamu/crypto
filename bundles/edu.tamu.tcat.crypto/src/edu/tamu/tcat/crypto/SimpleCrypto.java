/*
 * Copyright 2014-2019 Texas A&M Engineering Experiment Station
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
package edu.tamu.tcat.crypto;

import java.security.KeyPair;

/**
 * A facade to simplify crypto processing according to an implementation.
 *
 * @since 1.2
 */
public interface SimpleCrypto
{

   byte[] deriveKey(String input, byte[] salt, int rounds, int keyLengthInBytes);

   boolean verifyPassword(String password, byte[] salt, int rounds, int keyLengthInBytes, byte[] iv, byte[] tag, byte[] encryptedData);

   static class KeyData
   {
      public byte[] salt;
      public byte[] IV;
      public byte[] encryptedData;
      public byte[] tag;
      public KeyPair keys;
   }

   KeyData makeKeyPair(String password, int keyLengthInBytes, int rounds);

   SecureToken getSecureToken(byte[] key) throws TokenException;
}
