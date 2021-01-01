/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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



import java.util.Enumeration;
import java.util.NoSuchElementException;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the {@code LDAPAttributeSet}
 * class.
 */
public class LDAPAttributeSetTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests an attribute set without any attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptySet()
         throws Exception
  {
    LDAPAttributeSet s = new LDAPAttributeSet();
    s = s.duplicate();

    assertNotNull(s);

    Enumeration<LDAPAttribute> e = s.getAttributes();
    assertNotNull(e);
    assertFalse(e.hasMoreElements());
    try
    {
      e.nextElement();
      fail("Expected an exception when trying to get the next element");
    }
    catch (NoSuchElementException nsee)
    {
      // This was expected.
    }

    LDAPAttributeSet subset = s.getSubset("binary");
    assertNotNull(subset);
    assertFalse(subset.getAttributes().hasMoreElements());

    assertNull(s.getAttribute("bar", "lang-en-US"));
    assertNull(s.getAttribute("bar", "lang-en"));
    assertNull(s.getAttribute("bar", null));

    assertNull(s.getAttribute("foo", "lang-en-US"));
    assertNull(s.getAttribute("foo", "lang-en"));
    assertNull(s.getAttribute("foo", null));

    assertNull(s.getAttribute("foo", null));

    try
    {
      s.elementAt(0);
      fail("Expected an exception when trying to get the element at 0");
    }
    catch (IndexOutOfBoundsException ioobe)
    {
      // This was expected.
    }

    s.remove("foo");

    try
    {
      s.removeElementAt(0);
      fail("Expected an exception when trying to remove the element at 0");
    }
    catch (IndexOutOfBoundsException ioobe)
    {
      // This was expected.
    }

    assertEquals(s.size(), 0);

    assertNotNull(s.toString());
  }



  /**
   * Tests an attribute set without a set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonEmptySet()
         throws Exception
  {
    LDAPAttribute[] attrs =
    {
      new LDAPAttribute("foo", "a"),
      new LDAPAttribute("bar;lang-en-US", "b"),
      new LDAPAttribute("baz;binary", "c"),
      new LDAPAttribute("bat;binary;lang-en-US", "d"),
    };

    LDAPAttributeSet s = new LDAPAttributeSet(attrs);
    s = s.duplicate();

    assertNotNull(s);

    Enumeration<LDAPAttribute> e = s.getAttributes();
    assertNotNull(e);
    assertTrue(e.hasMoreElements());
    assertNotNull(e.nextElement());

    LDAPAttributeSet subset = s.getSubset("binary");
    assertNotNull(subset);
    assertTrue(subset.getAttributes().hasMoreElements());
    assertEquals(subset.getAttributes().nextElement().getBaseName(), "baz");

    assertNotNull(s.getAttribute("foo"));
    assertNotNull(s.getAttribute("bar;lang-en-US"));
    assertNull(s.getAttribute("bar"));
    assertNotNull(s.getAttribute("baz;binary"));
    assertNull(s.getAttribute("baz"));

    assertNotNull(s.getAttribute("bar", "lang-en-US"));
    assertNotNull(s.getAttribute("bar", "lang-en"));
    assertNull(s.getAttribute("bar", null));

    assertNotNull(s.getAttribute("bat", "lang-en-US"));
    assertNotNull(s.getAttribute("bat", "lang-en"));
    assertNull(s.getAttribute("bat", null));

    assertNull(s.getAttribute("foo", "lang-en-US"));
    assertNull(s.getAttribute("foo", "lang-en"));
    assertNotNull(s.getAttribute("foo", null));

    assertNotNull(s.elementAt(0));
    assertNotNull(s.elementAt(1));
    assertNotNull(s.elementAt(2));
    assertNotNull(s.elementAt(3));
    try
    {
      assertNotNull(s.elementAt(4));
      fail("Expected an exception when trying to get the element at 4");
    }
    catch (IndexOutOfBoundsException ioobe)
    {
      // This was expected.
    }

    s.remove("foo");
    s.remove("foo");

    try
    {
      s.removeElementAt(3);
      fail("Expected an exception when trying to remove the element at 3");
    }
    catch (IndexOutOfBoundsException ioobe)
    {
      // This was expected.
    }

    assertEquals(s.size(), 3);

    assertNotNull(s.toString());
  }



  /**
   * Tests the behavior when adding and removing attributes from the set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddAndRemove()
         throws Exception
  {
    LDAPAttributeSet s = new LDAPAttributeSet();

    assertEquals(s.size(), 0);
    assertNull(s.getAttribute("a"));
    assertNull(s.getAttribute("b"));
    assertNull(s.getAttribute("c"));

    s.add(new LDAPAttribute("a", "1"));
    assertEquals(s.size(), 1);
    assertNotNull(s.getAttribute("a"));
    assertNull(s.getAttribute("b"));
    assertNull(s.getAttribute("c"));

    s.add(new LDAPAttribute("b", "2"));
    assertEquals(s.size(), 2);
    assertNotNull(s.getAttribute("a"));
    assertNotNull(s.getAttribute("b"));
    assertNull(s.getAttribute("c"));

    s.add(new LDAPAttribute("b", "3"));
    assertEquals(s.size(), 2);
    assertNotNull(s.getAttribute("a"));
    assertNotNull(s.getAttribute("b"));
    assertNull(s.getAttribute("c"));

    s.add(new LDAPAttribute("c", "4"));
    assertEquals(s.size(), 3);
    assertNotNull(s.getAttribute("a"));
    assertNotNull(s.getAttribute("b"));
    assertNotNull(s.getAttribute("c"));

    s.remove("b");
    assertEquals(s.size(), 2);
    assertNotNull(s.getAttribute("a"));
    assertNull(s.getAttribute("b"));
    assertNotNull(s.getAttribute("c"));

    s.remove("b");
    assertEquals(s.size(), 2);
    assertNotNull(s.getAttribute("a"));
    assertNull(s.getAttribute("b"));
    assertNotNull(s.getAttribute("c"));

    s.removeElementAt(1);
    assertEquals(s.size(), 1);
    assertNotNull(s.getAttribute("a"));
    assertNull(s.getAttribute("b"));
    assertNull(s.getAttribute("c"));

    s.removeElementAt(0);
    assertEquals(s.size(), 0);
    assertNull(s.getAttribute("a"));
    assertNull(s.getAttribute("b"));
    assertNull(s.getAttribute("c"));
  }
}
