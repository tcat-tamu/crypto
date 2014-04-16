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
