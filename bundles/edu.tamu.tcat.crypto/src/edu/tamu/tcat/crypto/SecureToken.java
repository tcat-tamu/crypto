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

import java.nio.ByteBuffer;

/**
 * @since 1.1
 */
public interface SecureToken
{
   /**
    * Create a token for a given content.  The resulting token is base64 encoded. <p>
    * <b>NOTE: The tokens should likely expire.</b>  A simple way to avoid this is to make the buffer 8 bytes longer and insert System.currentTimeMillis()
    * as a long into the buffer.  Then when reading the token, read the time and use it to determine if the token has expired.
    * @param content The content to store in the token.  This {@link ByteBuffer} will not be modified and it's position, limit, and mark will also be unmodified.
    *    It should be "flipped," in that it's position should mark the start of the content and the limit is the end of the content.
    * @return The token as a base64 encoded string.
    * @throws TokenException Thrown if the token cannot be created.  This could happen due to missing cryptography algorithms, but is very unlikely if the constructor does not throw.
    */
   public String getToken(ByteBuffer content) throws TokenException;
   
   /**
    * Get the token's content back from the original token.
    * @param encoded The base64 encoded token as produced from {@link #getToken(ByteBuffer)}.
    * @return A {@link ByteBuffer} containing the token's content. <p>
    * 
    * If the token has no content, a 0 length {@link ByteBuffer} will be returned.  <b>This is not a good idea</b>; see {@link #getToken(ByteBuffer)}.
    * @throws TokenException Thrown if the token cannot be verified.  This could happen due to missing cryptography algorithms or if the token is corrupted.
    *    If {@link TokenException#isTokenInvalid()} is true, the token has been corrupted or maliciously modified.
    */
   public ByteBuffer getContentFromToken(String encoded) throws TokenException;
}
