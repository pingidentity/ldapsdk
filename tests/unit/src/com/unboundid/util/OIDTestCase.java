/*
 * Copyright 2014-2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2014-2017 Ping Identity Corporation
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



import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the OID class.
 */
public final class OIDTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests an OID created from a null string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNullString()
         throws Exception
  {
    final OID oid = new OID((String) null);
    assertNotNull(oid);

    assertFalse(oid.isValidNumericOID());

    assertFalse(oid.isStrictlyValidNumericOID());

    assertNull(oid.getComponents());

    assertNotNull(oid.toString());
    assertEquals(oid.toString(), "");
  }



  /**
   * Tests a range of OID functionality.
   *
   * @param  s  The string representation for the OID.  It must not be
   *            {@code null}.
   * @param  c  The integer components that comprise the OID.  It may be
   *            {@code null}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "oidTestData")
  public void testOID(final String s, final int[] c)
         throws Exception
  {
    final OID oid;
    if ((c == null) || (c.length == 0))
    {
      oid = new OID(s);

      assertEquals(new OID(c).toString(), "");

      assertFalse(oid.isValidNumericOID());
      assertFalse(OID.isValidNumericOID(s));
      assertFalse(oid.isStrictlyValidNumericOID());
      assertFalse(OID.isStrictlyValidNumericOID(s));
      assertNull(oid.getComponents());
    }
    else
    {
      oid = new OID(c);

      assertTrue(oid.isValidNumericOID());
      assertTrue(OID.isValidNumericOID(s));
      assertNotNull(oid.getComponents());
      assertEquals(oid.getComponents().size(), c.length);
      for (int i=0; i < c.length; i++)
      {
        assertEquals(oid.getComponents().get(i).intValue(), c[i]);
      }
    }

    oid.hashCode();

    assertFalse(oid.equals(null));
    assertTrue(oid.equals(oid));
    assertFalse(oid.equals(s));
    assertTrue(oid.equals(new OID(s)));

    assertEquals(oid.compareTo(oid), 0);
    assertEquals(oid.compareTo(new OID(s)), 0);

    final OID smaller = new OID(1, 0);
    final OID bigger  = new OID(9999, 9999, 9999, 9999);
    final OID empty   = new OID("");
    if (oid.isValidNumericOID())
    {
      assertFalse(oid.equals(smaller));
      assertFalse(smaller.equals(oid));
      assertTrue(oid.compareTo(smaller) > 0);
      assertTrue(smaller.compareTo(oid) < 0);

      assertFalse(oid.equals(bigger));
      assertFalse(bigger.equals(oid));
      assertTrue(oid.compareTo(bigger) < 0);
      assertTrue(bigger.compareTo(oid) > 0);

      assertFalse(oid.equals(empty));
      assertTrue(oid.compareTo(empty) < 0);
      assertTrue(empty.compareTo(oid) > 0);
    }
    else
    {
      assertFalse(oid.equals(smaller));
      assertFalse(smaller.equals(oid));
      assertTrue(oid.compareTo(smaller) > 0);
      assertTrue(smaller.compareTo(oid) < 0);

      assertFalse(oid.equals(bigger));
      assertFalse(bigger.equals(oid));
      assertTrue(oid.compareTo(bigger) > 0);
      assertTrue(bigger.compareTo(oid) < 0);

      if (s.length() > 0)
      {
        assertFalse(oid.equals(empty));
        assertTrue(oid.compareTo(empty) > 0);
        assertTrue(empty.compareTo(oid) < 0);
      }
      else
      {
        assertTrue(oid.equals(empty));
        assertEquals(oid.compareTo(empty), 0);
      }
    }

    assertNotNull(oid.toString());
    assertEquals(oid.toString(), s);
  }



  /**
   * Retrieves a set of data that can be used for testing.
   *
   * @return  A set of data that can be used for testing.
   */
  @DataProvider(name = "oidTestData")
  public Object[][] getOIDTestData()
  {
    return new Object[][]
    {
      new Object[]
      {
        "",
        null
      },

      new Object[]
      {
        "",
        new int[0]
      },

      new Object[]
      {
        "not valid",
        null
      },

      new Object[]
      {
        "1.2.3.4",
        new int[] { 1, 2, 3, 4 }
      },

      new Object[]
      {
        "1.1",
        new int[] { 1, 1 }
      },

      new Object[]
      {
        "1.0.1",
        new int[] { 1, 0, 1 }
      },

      new Object[]
      {
        "2",
        new int[] { 2 }
      },

      new Object[]
      {
        "9999",
        new int[] { 9999 }
      },

      new Object[]
      {
        "9999.9999",
        new int[] { 9999, 9999 }
      },

      new Object[]
      {
        "9999.9999.9999",
        new int[] { 9999, 9999, 9999 }
      },

      new Object[]
      {
        "999.999.999.999",
        new int[] { 999, 999, 999, 999 }
      },

      new Object[]
      {
        "9999.9999.9999.9998",
        new int[] { 9999, 9999, 9999, 9998 }
      },

      new Object[]
      {
        "9999.9999.9999.9998.9999",
        new int[] { 9999, 9999, 9999, 9998, 9999 }
      },
    };
  }



  /**
   * Provides test coverage for the {@code isStrictlyValidNumericOID} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIsStrictlyValidNumericOID()
         throws Exception
  {
    // This is valid.
    assertTrue(OID.isStrictlyValidNumericOID("1.2.3.4"));

    // This is also valid.
    assertTrue(OID.isStrictlyValidNumericOID("1.2"));

    // This is not valid because it is not numeric.
    assertFalse(OID.isStrictlyValidNumericOID("not.numeric"));

    // This is not valid because it starts with a period.
    assertFalse(OID.isStrictlyValidNumericOID(".1.2.3.4"));

    // This is not valid because it ends with a period.
    assertFalse(OID.isStrictlyValidNumericOID("1.2.3.4."));

    // This is not valid because it has two consecutive periods.
    assertFalse(OID.isStrictlyValidNumericOID("1.2..3.4."));

    // This is not valid because it only has one component.
    assertFalse(OID.isStrictlyValidNumericOID("1"));

    // This is not valid because the first component has a value that is not
    // 0, 1, or 2.
    assertFalse(OID.isStrictlyValidNumericOID("9.9"));

    // This is not valid because the first component has a value of 0 and the
    // second component has a value greater than 39.
    assertFalse(OID.isStrictlyValidNumericOID("0.40"));

    // This is not valid because the first component has a value of 1 and the
    // second component has a value greater than 39.
    assertFalse(OID.isStrictlyValidNumericOID("1.40"));

    // This is valid because the first component has a value of 2 and the
    // second component can be anything.
    assertTrue(OID.isStrictlyValidNumericOID("2.40"));
  }
}
