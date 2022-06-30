/*
 * Copyright 2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022 Ping Identity Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Copyright (C) 2022 Ping Identity Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License (GPLv2 only)
 * or the terms of the GNU Lesser General Public License (LGPLv2.1 only)
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 */
package com.unboundid.util;



import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.List;

import com.unboundid.ldap.sdk.InternalSDKHelper;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides a helper to ensure that the non-FIPS 140-2-compliant
 * version of the Bouncy Castle cryptographic library may be available to the
 * JVM when running in a Ping Identity Directory Server (or a related server
 * product), even if it's not in the main JVM classpath.  This is primarily
 * intended for internal use within Ping Identity server products.
 */
@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class BouncyCastleNonFIPSHelper
{
  /**
   * Prevents this utility class from being instantiated.
   */
  private BouncyCastleNonFIPSHelper()
  {
    // No implementation required.
  }



  /**
   * Retrieves a {@code ClassLoader} instance that may be used to load classes
   * from the non-FIPS-compliant Bouncy Castle library.  When this is run from
   * within a Ping Identity server VM, it will retrieve a class loader that may
   * be used to access the library from its default location in a Ping Identity
   * server installation, even if it's not in the JVM's classpath.  If the JVM
   * is not running as part of the server, then it may optionally either throw
   * an exception or it may return the JVM's default class loader and will
   * depend on the Bouncy Castle library being included in the JVM's classpath.
   *
   * @param  fallBackToDefaultClassLoader  Indicates whether to fall back to
   *                                       returning the JVM's default class
   *                                       loader if the JVM isn't running as
   *                                       part of a Ping Identity server
   *                                       installation or if the Bouncy Castle
   *                                       libraries cannot be found.  If this
   *                                       is {@code true}, then the JVM-default
   *                                       class loader will be returned in that
   *                                       case; if it is {@code false} then an
   *                                       exception will be thrown.
   *
   * @return  The class loader to use to access the Bouncy Castle library.
   *
   * @throws  ReflectiveOperationException  If a problem occurs while attempting
   *                                        to create the class loader.
   */
  @NotNull()
  public static ClassLoader getNonFIPSBouncyCastleClassLoader(
              final boolean fallBackToDefaultClassLoader)
         throws ReflectiveOperationException
  {
    final File serverRoot = InternalSDKHelper.getPingIdentityServerRoot();
    if (serverRoot == null)
    {
      if (fallBackToDefaultClassLoader)
      {
        return ClassLoader.getSystemClassLoader();
      }
      else
      {
        throw new ReflectiveOperationException(
             ERR_GET_NON_BC_FIPS_CLASS_LOADER_UNKNOWN_INSTANCE_ROOT.get());
      }
    }


    // Find the non-FIPS-compliant Bouncy Castle jar file in the server's
    // resource/bc/non-fips directory.
    final List<URL> bcJarFileURLList = new ArrayList<>();
    final File resourceBCNonFIPSDir =
         StaticUtils.constructPath(serverRoot, "resource", "bc", "non-fips");
    try
    {
      if (resourceBCNonFIPSDir.exists() && resourceBCNonFIPSDir.isDirectory())
      {
        for (final File f : resourceBCNonFIPSDir.listFiles())
        {
          if (f.isFile() && f.getName().toLowerCase().endsWith(".jar"))
          {
            bcJarFileURLList.add(f.toURI().toURL());
          }
        }
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      if (fallBackToDefaultClassLoader)
      {
        return ClassLoader.getSystemClassLoader();
      }
      else
      {
        throw new ReflectiveOperationException(
             ERR_GET_NON_BC_FIPS_CLASS_LOADER_ERROR_FINDING_JARS.get(
                  resourceBCNonFIPSDir.getAbsolutePath(),
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }

    if (bcJarFileURLList.isEmpty())
    {
      if (fallBackToDefaultClassLoader)
      {
        return ClassLoader.getSystemClassLoader();
      }
      else
      {
        throw new ReflectiveOperationException(
             ERR_GET_NON_FIPS_BC_CLASS_LOADER_NO_JARS_FOUND.get(
                  resourceBCNonFIPSDir.getAbsolutePath()));
      }
    }

    final URL[] bcJarFileURLArray = new URL[bcJarFileURLList.size()];
    bcJarFileURLList.toArray(bcJarFileURLArray);
    return new URLClassLoader(bcJarFileURLArray,
         ClassLoader.getSystemClassLoader());
  }
}
