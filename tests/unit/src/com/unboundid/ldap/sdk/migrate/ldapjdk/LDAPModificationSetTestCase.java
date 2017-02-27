/*
 * Copyright 2009-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2017 UnboundID Corp.
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
package com.unboundid.ldap.sdk.migrate.ldapjdk;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the {@code LDAPModificationSet} class.
 */
public class LDAPModificationSetTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for operations on a modification set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModificationSet()
         throws Exception
  {
    LDAPModificationSet s = new LDAPModificationSet();

    assertNotNull(s);

    assertEquals(s.size(), 0);

    assertNotNull(s.toArray());
    assertEquals(s.toArray().length, 0);

    assertNotNull(s.toString());

    try
    {
      s.elementAt(0);
      fail("Expected an exception for elementAt with an invalid index");
    }
    catch (IndexOutOfBoundsException ioobe)
    {
      // This was expected.
    }

    try
    {
      s.removeElementAt(0);
      fail("Expected an exception for removeElementAt with an invalid index");
    }
    catch (IndexOutOfBoundsException ioobe)
    {
      // This was expected
    }

    s.remove("foo");

    s.add(0, new LDAPAttribute("foo", "bar"));

    assertEquals(s.size(), 1);

    assertNotNull(s.toArray());
    assertEquals(s.toArray().length, 1);

    assertNotNull(s.toString());

    s.add(1, new LDAPAttribute("a", "b"));
    s.add(2, new LDAPAttribute("c", "d"));
    s.add(2, new LDAPAttribute("c", "e"));

    assertEquals(s.size(), 4);

    assertNotNull(s.toArray());
    assertEquals(s.toArray().length, 4);

    assertNotNull(s.toString());

    assertNotNull(s.elementAt(0));
    assertNotNull(s.elementAt(1));
    assertNotNull(s.elementAt(2));
    assertNotNull(s.elementAt(3));

    try
    {
      s.elementAt(4);
      fail("Expected an exception for elementAt with an invalid index");
    }
    catch (IndexOutOfBoundsException ioobe)
    {
      // This was expected.
    }

    s.remove("c");

    assertEquals(s.size(), 3);

    s.remove("c");

    assertEquals(s.size(), 2);

    s.remove("c");

    assertEquals(s.size(), 2);

    s.removeElementAt(1);

    assertEquals(s.size(), 1);

    try
    {
      s.removeElementAt(1);
      fail("Expected an exception for removeElementAt with an invalid index");
    }
    catch (IndexOutOfBoundsException ioobe)
    {
      // This was expected.
    }

    s.removeElementAt(0);

    try
    {
      s.removeElementAt(0);
      fail("Expected an exception for removeElementAt with an invalid index");
    }
    catch (IndexOutOfBoundsException ioobe)
    {
      // This was expected.
    }
  }
}
