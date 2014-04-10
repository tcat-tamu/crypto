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

package edu.tamu.tcat.crypto.internal;

import java.security.Provider;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;

public class Activator implements BundleActivator {

	private static Activator activator;
	
	/**
	 * Instantiate and use this {@link Provider} instance instead of adding it to the
	 * JVM via {@link java.security.Security#addProvider(Provider)}.
	 * <br/>There are problems in "redeployable"
	 * environments (such as OSGI and Tomcat) with using JVM-global singletons. Namely,
	 * the provider could be added once if whatever added it was "undeployed", the provider
	 * becomes invalid and throws exceptions when trying to access it.
	 * <br/>
	 * To avoid these issues, the provider is constructed explicitly where needed and
	 * given as an argument to cypher API explicitly rather than having the security
	 * framework look up a provider by identifier or choose a default.
	 */
	private final Provider bouncyCastleProvider = new BouncyCastleProvider();

	public static Activator getDefault() {
		return activator;
	}

	@Override
   public void start(BundleContext bundleContext) throws Exception {
		activator = this;
	}

	@Override
   public void stop(BundleContext bundleContext) throws Exception {
	   activator = null;
	}

   public Provider getBouncyCastleProvider()
   {
      return bouncyCastleProvider;
   }
}
