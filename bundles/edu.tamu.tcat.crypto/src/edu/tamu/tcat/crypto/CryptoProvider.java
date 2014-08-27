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
package edu.tamu.tcat.crypto;

public interface CryptoProvider
{
   SecureToken getSecureToken(String hexKey) throws TokenException;
   
   SecureToken getSecureToken(byte[] key) throws TokenException;
   
   PBKDF2 getPbkdf2(DigestType digestType);
   
   HashBuilder getHashBuilder();
   
   AsymmetricKeyBuilder getAsymmetricKeyBuilder();
   
   SignatureBuilder getSignatureBuilder();
   
   SymmetricCipherBuilder getSymmetricCipherBuilder();
   
   ASN1SeqKey getAsn1SeqKey();
   
   X509KeyDecoder getX509KeyDecoder();
}
