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



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the {@code LDAPEntry} class.
 */
public class LDAPEntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the default constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultConstructor()
         throws Exception
  {
    LDAPEntry e = new LDAPEntry();

    assertNotNull(e.getDN());
    assertEquals(e.getDN(), "");

    assertNotNull(e.getAttributeSet());
    assertEquals(e.getAttributeSet().size(), 0);

    assertNotNull(e.getAttributeSet("binary"));
    assertEquals(e.getAttributeSet("binary").size(), 0);

    assertNull(e.getAttribute("foo"));

    assertNull(e.getAttribute("bar"), "lang-en-US");

    assertNotNull(e.toEntry());
    assertEquals(e.toEntry().getDN(), "");
    assertEquals(e.toEntry().getAttributes().size(), 0);

    assertNotNull(e.toString());
  }



  /**
   * Provides test coverage for the constructor which takes a DN and no
   * attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithDNAndNoAttributes()
         throws Exception
  {
    LDAPEntry e = new LDAPEntry("dc=example,dc=com");

    assertNotNull(e.getDN());
    assertEquals(e.getDN(), "dc=example,dc=com");

    assertNotNull(e.getAttributeSet());
    assertEquals(e.getAttributeSet().size(), 0);

    assertNotNull(e.getAttributeSet("binary"));
    assertEquals(e.getAttributeSet("binary").size(), 0);

    assertNull(e.getAttribute("foo"));

    assertNull(e.getAttribute("bar"), "lang-en-US");

    assertNotNull(e.toEntry());
    assertEquals(e.toEntry().getDN(), "dc=example,dc=com");
    assertEquals(e.toEntry().getAttributes().size(), 0);

    assertNotNull(e.toString());
  }



  /**
   * Provides test coverage for the constructor which takes a DN and set of
   * attributes with a null attribute set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithDNAndNullAttributes()
         throws Exception
  {
    LDAPEntry e = new LDAPEntry("dc=example,dc=com", null);

    assertNotNull(e.getDN());
    assertEquals(e.getDN(), "dc=example,dc=com");

    assertNotNull(e.getAttributeSet());
    assertEquals(e.getAttributeSet().size(), 0);

    assertNotNull(e.getAttributeSet("binary"));
    assertEquals(e.getAttributeSet("binary").size(), 0);

    assertNull(e.getAttribute("foo"));

    assertNull(e.getAttribute("bar"), "lang-en-US");

    assertNotNull(e.toEntry());
    assertEquals(e.toEntry().getDN(), "dc=example,dc=com");
    assertEquals(e.toEntry().getAttributes().size(), 0);

    assertNotNull(e.toString());
  }



  /**
   * Provides test coverage for the constructor which takes a DN and set of
   * attributes with an empty attribute set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithDNAndEmptyAttributes()
         throws Exception
  {
    LDAPEntry e = new LDAPEntry("dc=example,dc=com", new LDAPAttributeSet());

    assertNotNull(e.getDN());
    assertEquals(e.getDN(), "dc=example,dc=com");

    assertNotNull(e.getAttributeSet());
    assertEquals(e.getAttributeSet().size(), 0);

    assertNotNull(e.getAttributeSet("binary"));
    assertEquals(e.getAttributeSet("binary").size(), 0);

    assertNull(e.getAttribute("foo"));

    assertNull(e.getAttribute("bar"), "lang-en-US");

    assertNotNull(e.toEntry());
    assertEquals(e.toEntry().getDN(), "dc=example,dc=com");
    assertEquals(e.toEntry().getAttributes().size(), 0);

    assertNotNull(e.toString());
  }



  /**
   * Provides test coverage for the constructor which takes a DN and set of
   * attributes with a non-empty attribute set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithDNAndNonEmptyAttributes()
         throws Exception
  {
    LDAPAttributeSet attrSet = new LDAPAttributeSet();
    attrSet.add(new LDAPAttribute("objectClass", "top"));
    attrSet.add(new LDAPAttribute("objectClass", "domain"));
    attrSet.add(new LDAPAttribute("objectClass", "extensibleObject"));
    attrSet.add(new LDAPAttribute("dc", "example"));
    attrSet.add(new LDAPAttribute("foo", "a"));
    attrSet.add(new LDAPAttribute("bar;lang-en-US", "b"));
    attrSet.add(new LDAPAttribute("baz;binary", "c"));

    LDAPEntry e = new LDAPEntry("dc=example,dc=com", attrSet);

    assertNotNull(e.getDN());
    assertEquals(e.getDN(), "dc=example,dc=com");

    assertNotNull(e.getAttributeSet());
    assertEquals(e.getAttributeSet().size(), 5);

    assertNotNull(e.getAttributeSet("binary"));
    assertEquals(e.getAttributeSet("binary").size(), 1);

    assertNotNull(e.getAttribute("foo"));

    assertNotNull(e.getAttribute("bar", "lang-en-US"));

    assertNotNull(e.toEntry());
    assertEquals(e.toEntry().getDN(), "dc=example,dc=com");
    assertEquals(e.toEntry().getAttributes().size(), 5);

    assertNotNull(e.toString());
  }



  /**
   * Provides test coverage for the constructor which takes an SDK entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithSDKEntry()
         throws Exception
  {
    LDAPEntry e = new LDAPEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "objectClass: extensibleObject",
         "dc: example",
         "foo: a",
         "bar;lang-en-US: b",
         "baz;binary: c"));

    assertNotNull(e.getDN());
    assertEquals(e.getDN(), "dc=example,dc=com");

    assertNotNull(e.getAttributeSet());
    assertEquals(e.getAttributeSet().size(), 5);

    assertNotNull(e.getAttributeSet("binary"));
    assertEquals(e.getAttributeSet("binary").size(), 1);

    assertNotNull(e.getAttribute("foo"));

    assertNotNull(e.getAttribute("bar", "lang-en-US"));

    assertNotNull(e.toEntry());
    assertEquals(e.toEntry().getDN(), "dc=example,dc=com");
    assertEquals(e.toEntry().getAttributes().size(), 5);

    assertNotNull(e.toString());
  }
}
