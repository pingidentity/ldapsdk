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



import java.net.MalformedURLException;
import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.LDAPURL;



/**
 * This class provides test coverage for the {@code LDAPUrl} class.
 */
public class LDAPUrlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for an LDAP URL created from a valid string with
   * all components present.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateFromValidCompleteString()
         throws Exception
  {
    LDAPUrl url = new LDAPUrl("ldap://server.example.com:1234/" +
         "dc=example,dc=com?givenName,sn?one?(uid=test.user)");

    assertNotNull(url);

    assertNotNull(url.getHost());
    assertEquals(url.getHost(), "server.example.com");

    assertEquals(url.getPort(), 1234);

    assertNotNull(url.getDN());
    assertEquals(url.getDN(), "dc=example,dc=com");

    assertNotNull(url.getAttributes());
    assertTrue(url.getAttributes().hasMoreElements());

    assertNotNull(url.getAttributeArray());
    assertEquals(url.getAttributeArray().length, 2);

    assertEquals(url.getScope(), 1);

    assertNotNull(url.getFilter());
    assertEquals(url.getFilter(), "(uid=test.user)");

    url.hashCode();

    assertFalse(url.equals(null));
    assertTrue(url.equals(url));
    assertFalse(url.equals("foo"));

    assertNotNull(url.getUrl());

    assertNotNull(url.toLDAPURL());

    assertNotNull(url.toString());
  }



  /**
   * Provides test coverage for an LDAP URL created from a valid string with
   * a minimal set of elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateFromValidMinimalString()
         throws Exception
  {
    LDAPUrl url = new LDAPUrl("ldap://");

    assertNotNull(url);

    assertNull(url.getHost());

    assertEquals(url.getPort(), 389);

    assertNull(url.getDN());

    assertNull(url.getAttributes());

    assertNull(url.getAttributeArray());

    assertEquals(url.getScope(), 0);

    assertNotNull(url.getFilter());
    assertEquals(url.getFilter().toLowerCase(), "(objectclass=*)");

    url.hashCode();

    assertFalse(url.equals(null));
    assertTrue(url.equals(url));
    assertFalse(url.equals("foo"));

    assertNotNull(url.getUrl());

    assertNotNull(url.toLDAPURL());

    assertNotNull(url.toString());
  }



  /**
   * Provides test coverage for an LDAP URL created from an invalid string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { MalformedURLException.class })
  public void testCreateFromInvalidString()
         throws Exception
  {
    new LDAPUrl("invalid");
  }



  /**
   * Provides test coverage for an LDAP URL created using the constructor that
   * takes a host, port, and DN with all elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithHostPortDNAllNonNull()
         throws Exception
  {
    LDAPUrl url = new LDAPUrl("server.example.com", 389, "dc=example,dc=com");

    assertNotNull(url);

    assertNotNull(url.getHost());
    assertEquals(url.getHost(), "server.example.com");

    assertEquals(url.getPort(), 389);

    assertNotNull(url.getDN());
    assertEquals(url.getDN(), "dc=example,dc=com");

    assertNull(url.getAttributes());

    assertNull(url.getAttributeArray());

    assertEquals(url.getScope(), 0);

    assertNotNull(url.getFilter());
    assertEquals(url.getFilter().toLowerCase(), "(objectclass=*)");

    url.hashCode();

    assertFalse(url.equals(null));
    assertTrue(url.equals(url));
    assertFalse(url.equals("foo"));

    assertNotNull(url.getUrl());

    assertNotNull(url.toLDAPURL());

    assertNotNull(url.toString());
  }



  /**
   * Provides test coverage for an LDAP URL created using the constructor that
   * takes a host, port, and DN with a null host and DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithNullHostPortNullDN()
         throws Exception
  {
    LDAPUrl url = new LDAPUrl(null, 389, null);

    assertNotNull(url);

    assertNull(url.getHost());

    assertEquals(url.getPort(), 389);

    assertNull(url.getDN());

    assertNull(url.getAttributes());

    assertNull(url.getAttributeArray());

    assertEquals(url.getScope(), 0);

    assertNotNull(url.getFilter());
    assertEquals(url.getFilter().toLowerCase(), "(objectclass=*)");

    url.hashCode();

    assertFalse(url.equals(null));
    assertTrue(url.equals(url));
    assertFalse(url.equals("foo"));

    assertNotNull(url.getUrl());

    assertNotNull(url.toLDAPURL());

    assertNotNull(url.toString());
  }



  /**
   * Provides test coverage for an LDAP URL created using the constructor that
   * takes a host, port, and DN with an invalid DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { RuntimeException.class })
  public void testCreateWithHostPortInvalidDN()
         throws Exception
  {
    new LDAPUrl(null, 389, "invalid");
  }



  /**
   * Provides test coverage for an LDAP URL created with all elements including
   * an attribute array with all elements non-null.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateAllWithAttrArrayAllNonNull()
         throws Exception
  {
    String[] attrs = { "givenName", "sn" };
    LDAPUrl url = new LDAPUrl("server.example.com", 1234, "dc=example,dc=com",
         attrs, 1, "(uid=test.user)");

    assertNotNull(url);

    assertNotNull(url.getHost());
    assertEquals(url.getHost(), "server.example.com");

    assertEquals(url.getPort(), 1234);

    assertNotNull(url.getDN());
    assertEquals(url.getDN(), "dc=example,dc=com");

    assertNotNull(url.getAttributes());
    assertTrue(url.getAttributes().hasMoreElements());

    assertNotNull(url.getAttributeArray());
    assertEquals(url.getAttributeArray().length, 2);

    assertEquals(url.getScope(), 1);

    assertNotNull(url.getFilter());
    assertEquals(url.getFilter(), "(uid=test.user)");

    url.hashCode();

    assertFalse(url.equals(null));
    assertTrue(url.equals(url));
    assertFalse(url.equals("foo"));

    assertNotNull(url.getUrl());

    assertNotNull(url.toLDAPURL());

    assertNotNull(url.toString());
  }



  /**
   * Provides test coverage for an LDAP URL created with all elements including
   * an attribute array with all elements null.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateAllWithAttrArrayAllNull()
         throws Exception
  {
    String[] attrs = null;
    LDAPUrl url = new LDAPUrl(null, 1234, null, attrs, 0, "(objectClass=*)");

    assertNotNull(url);

    assertNull(url.getHost());

    assertEquals(url.getPort(), 1234);

    assertNull(url.getDN());

    assertNull(url.getAttributes());

    assertNull(url.getAttributeArray());

    assertEquals(url.getScope(), 0);

    assertNotNull(url.getFilter());
    assertEquals(url.getFilter().toLowerCase(), "(objectclass=*)");

    url.hashCode();

    assertFalse(url.equals(null));
    assertTrue(url.equals(url));
    assertFalse(url.equals("foo"));

    assertNotNull(url.getUrl());

    assertNotNull(url.toLDAPURL());

    assertNotNull(url.toString());
  }



  /**
   * Provides test coverage for an LDAP URL created with all elements including
   * an attribute array with an invalid filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { RuntimeException.class })
  public void testCreateAllWithAttrArrayInvalidFilter()
         throws Exception
  {
    String[] attrs = null;
    new LDAPUrl(null, 1234, null, attrs, 0, "(invalid)");
  }



  /**
   * Provides test coverage for an LDAP URL created with all elements including
   * an attribute enumeration with all elements non-null.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateAllWithAttrEnumerationAllNonNull()
         throws Exception
  {
    IterableEnumeration<String> attrs =
         new IterableEnumeration<String>(Arrays.asList("givenName", "sn"));
    LDAPUrl url = new LDAPUrl("server.example.com", 1234, "dc=example,dc=com",
         attrs, 1, "(uid=test.user)");

    assertNotNull(url);

    assertNotNull(url.getHost());
    assertEquals(url.getHost(), "server.example.com");

    assertEquals(url.getPort(), 1234);

    assertNotNull(url.getDN());
    assertEquals(url.getDN(), "dc=example,dc=com");

    assertNotNull(url.getAttributes());
    assertTrue(url.getAttributes().hasMoreElements());

    assertNotNull(url.getAttributeArray());
    assertEquals(url.getAttributeArray().length, 2);

    assertEquals(url.getScope(), 1);

    assertNotNull(url.getFilter());
    assertEquals(url.getFilter(), "(uid=test.user)");

    url.hashCode();

    assertFalse(url.equals(null));
    assertTrue(url.equals(url));
    assertFalse(url.equals("foo"));

    assertNotNull(url.getUrl());

    assertNotNull(url.toLDAPURL());

    assertNotNull(url.toString());
  }



  /**
   * Provides test coverage for an LDAP URL created with all elements including
   * an attribute enumeration with all elements null.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateAllWithAttrEnumerationAllNull()
         throws Exception
  {
    IterableEnumeration<String> attrs = null;
    LDAPUrl url = new LDAPUrl(null, 1234, null, attrs, 0, "(objectClass=*)");

    assertNotNull(url);

    assertNull(url.getHost());

    assertEquals(url.getPort(), 1234);

    assertNull(url.getDN());

    assertNull(url.getAttributes());

    assertNull(url.getAttributeArray());

    assertEquals(url.getScope(), 0);

    assertNotNull(url.getFilter());
    assertEquals(url.getFilter().toLowerCase(), "(objectclass=*)");

    url.hashCode();

    assertFalse(url.equals(null));
    assertTrue(url.equals(url));
    assertFalse(url.equals("foo"));

    assertNotNull(url.getUrl());

    assertNotNull(url.toLDAPURL());

    assertNotNull(url.toString());
  }



  /**
   * Provides test coverage for an LDAP URL created with all elements including
   * an attribute enumeration with an invalid filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { RuntimeException.class })
  public void testCreateAllWithAttrEnumerationInvalidFilter()
         throws Exception
  {
    IterableEnumeration<String> attrs = null;
    new LDAPUrl(null, 1234, null, attrs, 0, "(invalid)");
  }



  /**
   * Provides test coverage for an LDAP URL created from an SDK LDAP URL.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateFromSDKURL()
         throws Exception
  {
    LDAPUrl url = new LDAPUrl(new LDAPURL("ldap://server.example.com:1234/" +
         "dc=example,dc=com?givenName,sn?one?(uid=test.user)"));

    assertNotNull(url);

    assertNotNull(url.getHost());
    assertEquals(url.getHost(), "server.example.com");

    assertEquals(url.getPort(), 1234);

    assertNotNull(url.getDN());
    assertEquals(url.getDN(), "dc=example,dc=com");

    assertNotNull(url.getAttributes());
    assertTrue(url.getAttributes().hasMoreElements());

    assertNotNull(url.getAttributeArray());
    assertEquals(url.getAttributeArray().length, 2);

    assertEquals(url.getScope(), 1);

    assertNotNull(url.getFilter());
    assertEquals(url.getFilter(), "(uid=test.user)");

    url.hashCode();

    assertFalse(url.equals(null));
    assertTrue(url.equals(url));
    assertFalse(url.equals("foo"));

    assertNotNull(url.getUrl());

    assertNotNull(url.toLDAPURL());

    assertNotNull(url.toString());
  }
}
