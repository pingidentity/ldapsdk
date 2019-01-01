/*
 * Copyright 2017-2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2017-2019 Ping Identity Corporation
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
 * This class provides test coverage for the CertException class.
 */
public class CertExceptionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of an exception without a cause.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExceptionWithoutCause()
         throws Exception
  {
    final CertException e = new CertException("message");

    assertNotNull(e.getMessage());
    assertEquals(e.getMessage(), "message");

    assertNull(e.getCause());
  }



  /**
   * Tests the behavior of an exception with a {@code null} cause.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExceptionWithNullCause()
         throws Exception
  {
    final CertException e = new CertException("message", null);

    assertNotNull(e.getMessage());
    assertEquals(e.getMessage(), "message");

    assertNull(e.getCause());
  }



  /**
   * Tests the behavior of an exception with a non-{@code null} cause.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExceptionWithNonNullCause()
         throws Exception
  {
    final CertException e = new CertException("message",
         new Exception("cause"));

    assertNotNull(e.getMessage());
    assertEquals(e.getMessage(), "message");

    assertNotNull(e.getCause());
    assertEquals(e.getCause().getMessage(), "cause");
  }
}
