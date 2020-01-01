/*
 * Copyright 2018-2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2018-2020 Ping Identity Corporation
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
 * This class provides a set of test cases for the permit unindexed search
 * request control.
 */
public final class PermitUnindexedSearchRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the control behavior when using the default constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultConstructor()
         throws Exception
  {
    PermitUnindexedSearchRequestControl c =
         new PermitUnindexedSearchRequestControl();

    c = new PermitUnindexedSearchRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.55");

    assertFalse(c.isCritical());

    assertNull(c.getValue());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the control behavior with an explicit criticality of {@code true}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExplicitCriticalityTrue()
         throws Exception
  {
    PermitUnindexedSearchRequestControl c =
         new PermitUnindexedSearchRequestControl(true);

    c = new PermitUnindexedSearchRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.55");

    assertTrue(c.isCritical());

    assertNull(c.getValue());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the control behavior with an explicit criticality of {@code false}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExplicitCriticalityFalse()
         throws Exception
  {
    PermitUnindexedSearchRequestControl c =
         new PermitUnindexedSearchRequestControl(false);

    c = new PermitUnindexedSearchRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.55");

    assertFalse(c.isCritical());

    assertNull(c.getValue());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when trying to decode a control that has a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlWithValue()
         throws Exception
  {
    final Control genericControl = new Control("1.3.6.1.4.1.30221.2.5.55",
         false, new ASN1OctetString("unexpected value"));

    new PermitUnindexedSearchRequestControl(genericControl);
  }
}
