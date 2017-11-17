/*
 * Copyright 2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2017 Ping Identity Corporation
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



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the manage certificates security
 * manager.
 */
public final class ManageCertificatesSecurityManagerTestCase
     extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the {@code checkExit} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCheckExit()
         throws Exception
  {
    ManageCertificatesSecurityManager securityManager =
         new ManageCertificatesSecurityManager();

    try
    {
      securityManager.checkExit(0);
    }
    catch (final SecurityException se)
    {
      // This was expected.
    }
    finally
    {
      assertTrue(securityManager.exitCalledWithZeroStatus());
    }


    securityManager = new ManageCertificatesSecurityManager();

    try
    {
      securityManager.checkExit(1);
    }
    catch (final SecurityException se)
    {
      // This was expected.
    }
    finally
    {
      assertTrue(securityManager.exitCalledWithNonZeroStatus());
    }
  }



  /**
   * Provides test coverage for the {@code checkPermission} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCheckPermission()
         throws Exception
  {
    ManageCertificatesSecurityManager securityManager =
         new ManageCertificatesSecurityManager();
    securityManager.checkPermission(null);
    assertFalse(securityManager.exitCalledWithZeroStatus());
    assertFalse(securityManager.exitCalledWithNonZeroStatus());


    securityManager = new ManageCertificatesSecurityManager();

    try
    {
      securityManager.checkPermission(new RuntimePermission("exitvm"));
    }
    catch (final SecurityException se)
    {
      // This was expected.
    }
    finally
    {
      assertTrue(securityManager.exitCalledWithZeroStatus());
    }


    securityManager = new ManageCertificatesSecurityManager();

    try
    {
      securityManager.checkPermission(new RuntimePermission("exitvm.0"));
    }
    catch (final SecurityException se)
    {
      // This was expected.
    }
    finally
    {
      assertTrue(securityManager.exitCalledWithZeroStatus());
    }


    securityManager = new ManageCertificatesSecurityManager();

    try
    {
      securityManager.checkPermission(new RuntimePermission("exitvm.1"));
    }
    catch (final SecurityException se)
    {
      // This was expected.
    }
    finally
    {
      assertTrue(securityManager.exitCalledWithNonZeroStatus());
    }
  }
}
