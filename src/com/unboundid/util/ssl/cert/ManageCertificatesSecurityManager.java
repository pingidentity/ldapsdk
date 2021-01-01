/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
package com.unboundid.util.ssl.cert;



import java.security.Permission;

import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.ssl.cert.CertMessages.*;



/**
 * This class provides an implementation of a Java security manager that will
 * prevent System.exit from being invoked.  This is needed when invoking the
 * keytool utility programmatically via reflection, because it has the potential
 * to call System.exit if an error is encountered, and we don't want to allow
 * that (but we do want to be able to trap it).
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
final class ManageCertificatesSecurityManager
      extends SecurityManager
{
  // Indicates whether an attempt was made to exit the VM with a nonzero status.
  private volatile boolean exitCalledWithNonZeroStatus;

  // Indicates whether an attempt was made to exit the VM with a zero status.
  private volatile boolean exitCalledWithZeroStatus;

  // The security manager to which all non-exit decisions will be delegated.
  @Nullable private final SecurityManager delegateSecurityManager;



  /**
   * Creates a new instance of this security manager.
   */
  ManageCertificatesSecurityManager()
  {
    delegateSecurityManager = System.getSecurityManager();
    exitCalledWithZeroStatus = false;
    exitCalledWithNonZeroStatus = false;
  }



  /**
   * Checks to see whether the JVM should be allowed to exit.  If this method
   * exits normally without an exception, then it should be allowed.
   *
   * @param  status  The exit status to be used.
   *
   * @throws  SecurityException  If the exit attempt should be blocked.
   */
  @Override()
  public void checkExit(final int status)
         throws SecurityException
  {
    if (status == 0)
    {
      exitCalledWithZeroStatus = true;
    }
    else
    {
      exitCalledWithNonZeroStatus = true;
    }

    throw new SecurityException(
         ERR_MANAGE_CERTS_SECURITY_MANAGER_EXIT_NOT_ALLOWED.get());
  }



  /**
   * Checks to see whether the specified permission should be granted.  If this
   * method exits normally without an exception, then it should be allowed.
   *
   * @param  permission  The permission for which to make the determination.
   *
   * @throws  SecurityException  If the exit attempt should be blocked.
   */
  @Override()
  public void checkPermission(@Nullable final Permission permission)
         throws SecurityException
  {
    if ((permission == null) || (permission.getName() == null))
    {
      if (delegateSecurityManager != null)
      {
        delegateSecurityManager.checkPermission(permission);
      }

      return;
    }

    final String permissionName = StaticUtils.toLowerCase(permission.getName());
    if (permissionName.equals("exitvm") || permissionName.equals("exitvm.0"))
    {
      exitCalledWithZeroStatus = true;
      throw new SecurityException(
           ERR_MANAGE_CERTS_SECURITY_MANAGER_EXIT_NOT_ALLOWED.get());
    }

    if (permissionName.startsWith("exitvm."))
    {
      exitCalledWithNonZeroStatus = true;
      throw new SecurityException(
           ERR_MANAGE_CERTS_SECURITY_MANAGER_EXIT_NOT_ALLOWED.get());
    }

    if (delegateSecurityManager != null)
    {
      delegateSecurityManager.checkPermission(permission);
    }
  }



  /**
   * Indicates whether an attempt was made to exit the VM with a status of zero.
   *
   * @return  {@code true} if an attempt was made to exit the VM with a status
   *          of zero, or {@code false} if not.
   */
  boolean exitCalledWithZeroStatus()
  {
    return exitCalledWithZeroStatus;
  }



  /**
   * Indicates whether an attempt was made to exit the VM with a status of
   * something other than zero.
   *
   * @return  {@code true} if an attempt was made to exit the VM with a status
   *          of something other than zero, or {@code false} if not.
   */
  boolean exitCalledWithNonZeroStatus()
  {
    return exitCalledWithNonZeroStatus;
  }
}
