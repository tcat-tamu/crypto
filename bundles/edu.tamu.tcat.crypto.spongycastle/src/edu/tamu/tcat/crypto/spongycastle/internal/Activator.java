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

package edu.tamu.tcat.crypto.spongycastle.internal;

import java.security.Provider;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;

public class Activator implements BundleActivator {

	private static Activator activator;
   private static BundleContext bundleContext;

	
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

   public static BundleContext getContext() {
      return bundleContext;
   }

	@Override
   public void start(BundleContext bundleContext) throws Exception {
		Activator.bundleContext = bundleContext;
      activator = this;
	}

	@Override
   public void stop(BundleContext bundleContext) throws Exception {
      Activator.bundleContext = null;
	   activator = null;
	}

   public Provider getBouncyCastleProvider()
   {
      return bouncyCastleProvider;
   }
}
