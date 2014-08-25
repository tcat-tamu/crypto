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

public class TokenException extends Exception
{
   private final boolean tokenInvalid;

   public TokenException(String message, Throwable cause)
   {
      this(message, cause, false);
   }
   
   public TokenException(String message, boolean tokenValid)
   {
      super(message);
      this.tokenInvalid = tokenValid;
   }
   
   public TokenException(String message, Throwable cause, boolean tokenInvalid)
   {
      super(message, cause);
      this.tokenInvalid = tokenInvalid;
   }

   public boolean isTokenInvalid()
   {
      return tokenInvalid;
   }
}
