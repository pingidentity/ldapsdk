/*
 * Copyright 2013-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2013-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.controls;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of tests for the purge password request control.
 */
public final class PurgePasswordRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the control when it is marked critical.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCriticalControl()
         throws Exception
  {
    PurgePasswordRequestControl c = new PurgePasswordRequestControl(true);
    c = new PurgePasswordRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.32");

    assertTrue(c.isCritical());

    assertNull(c.getValue());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the control when it is not marked critical.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonCriticalControl()
         throws Exception
  {
    PurgePasswordRequestControl c = new PurgePasswordRequestControl(false);
    c = new PurgePasswordRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.32");

    assertFalse(c.isCritical());

    assertNull(c.getValue());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the control when creating it from a malformed
   * control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedControl()
         throws Exception
  {
    new PurgePasswordRequestControl(new Control("1.3.6.1.4.1.30221.2.5.32",
         true, new ASN1OctetString("foo")));
  }
}
