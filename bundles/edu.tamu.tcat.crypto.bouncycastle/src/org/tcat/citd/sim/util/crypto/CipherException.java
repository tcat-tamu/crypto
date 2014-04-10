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

package org.tcat.citd.sim.util.crypto;

public class CipherException extends Exception
{

   public CipherException()
   {
      super();
   }

   public CipherException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace)
   {
      super(message, cause, enableSuppression, writableStackTrace);
   }

   public CipherException(String message, Throwable cause)
   {
      super(message, cause);
   }

   public CipherException(String message)
   {
      super(message);
   }

   public CipherException(Throwable cause)
   {
      super(cause);
   }

}
