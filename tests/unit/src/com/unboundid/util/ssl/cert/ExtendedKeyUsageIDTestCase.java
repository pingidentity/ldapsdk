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
import com.unboundid.util.OID;



/**
 * This class provides test coverage for the ExtendedKeyUsageID class.
 */
public class ExtendedKeyUsageIDTestCase
       extends LDAPSDKTestCase
{
  /**
   * Performs a number of tests for the defined set of values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValues()
         throws Exception
  {
    for (final ExtendedKeyUsageID id : ExtendedKeyUsageID.values())
    {
      assertNotNull(id);

      assertNotNull(id.getOID());

      assertNotNull(id.getName());

      assertNotNull(ExtendedKeyUsageID.forOID(id.getOID()));
      assertEquals(ExtendedKeyUsageID.forOID(id.getOID()), id);

      assertNotNull(ExtendedKeyUsageID.getNameOrOID(id.getOID()));
      assertEquals(ExtendedKeyUsageID.getNameOrOID(id.getOID()), id.getName());

      assertNotNull(ExtendedKeyUsageID.valueOf(id.name()));
      assertEquals(ExtendedKeyUsageID.valueOf(id.name()), id);
    }
  }



  /**
   * Tests the behavior when attempting to use a nonexistent value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonexistentValue()
         throws Exception
  {
    assertNull(ExtendedKeyUsageID.forOID(new OID("1.2.3.4")));

    assertNotNull(ExtendedKeyUsageID.getNameOrOID(new OID("1.2.3.4")));
    assertEquals(ExtendedKeyUsageID.getNameOrOID(new OID("1.2.3.4")),
         "1.2.3.4");

    try
    {
      ExtendedKeyUsageID.valueOf("nonexistent");
      fail("Expected an exception from valueOf with a nonexistent name");
    }
    catch (final IllegalArgumentException iae)
    {
      // This was expected.
    }
  }
}
