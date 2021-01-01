/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.util.Arrays;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the LDAPURL class.
 */
public class LDAPURLTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with a valid URL string.
   *
   * @param  urlString         The string to parse as an LDAP URL.
   * @param  scheme            The expected scheme for the URL.
   * @param  host              The expected host for the URL.
   * @param  hostProvided      Indicates whether the host was provided in the
   *                           URL string.
   * @param  port              The expected port for the URL.
   * @param  portProvided      Indicates whether the port was provided in the
   *                           URL string.
   * @param  baseDN            The expected base DN for the URL.
   * @param  baseDNProvided    Indicates whether the base DN was provided in the
   *                           URL string.
   * @param  attributes        The expected attributes for the URL.
   * @param  attrsProvided     Indicates whether the attribute list was provided
   *                           in the URL string.
   * @param  scope             The expected scope for the URL.
   * @param  scopeProvided     Indicates whether the scope was provided in the
   *                           URL string.
   * @param  filter            The expected filter for the URL.
   * @param  filterProvided    Indicates whether the filter was provided in the
   *                           URL string.
   * @param  normalizedString  The expected normalized string representation for
   *                           the URL.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidURLs")
  public void testConstructor1Valid(String urlString, String scheme,
                                    String host, boolean hostProvided, int port,
                                    boolean portProvided, DN baseDN,
                                    boolean baseDNProvided, String[] attributes,
                                    boolean attrsProvided, SearchScope scope,
                                    boolean scopeProvided, Filter filter,
                                    boolean filterProvided,
                                    String normalizedString)
         throws Exception
  {
    LDAPURL url = new LDAPURL(urlString);

    assertEquals(url.toString(), urlString);
    assertEquals(url.getScheme(), scheme);
    assertEquals(url.getHost(), host);
    assertEquals(url.hostProvided(), hostProvided);
    assertEquals(url.getPort(), port);
    assertEquals(url.portProvided(), portProvided);
    assertEquals(url.getBaseDN(), baseDN);
    assertEquals(url.baseDNProvided(), baseDNProvided);
    assertEquals(url.getScope(), scope);
    assertEquals(url.scopeProvided(), scopeProvided);
    assertEquals(url.getFilter(), filter);
    assertEquals(url.filterProvided(), filterProvided);
    assertEquals(url.toNormalizedString(), normalizedString);
    assertTrue(Arrays.equals(url.getAttributes(), attributes));
    assertEquals(url.attributesProvided(), attrsProvided);

    assertNotNull(url.toSearchRequest());
    assertEquals(new DN(url.toSearchRequest().getBaseDN()), baseDN);
    assertEquals(url.toSearchRequest().getScope(), scope);
    assertEquals(url.toSearchRequest().getFilter(), filter);
    assertTrue(Arrays.equals(url.toSearchRequest().getAttributes(),
                             attributes));

    LDAPURL url2 = new LDAPURL(normalizedString);
    assertEquals(url2.toNormalizedString(), normalizedString);

    assertEquals(url.hashCode(), url2.hashCode());
    assertEquals(url, url2);
  }



  /**
   * Tests to ensure that invalid LDAP URLs are properly rejected.
   *
   * @param  urlString  An invalid LDAP URL string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testInvalidURLs",
        expectedExceptions = { LDAPSDKUsageException.class,
                               LDAPException.class })
  public void testConstructor1Invalid(String urlString)
         throws Exception
  {
    new LDAPURL(urlString);
  }



  /**
   * Tests the second constructor with a valid URL string.
   *
   * @param  urlString         The string to parse as an LDAP URL.
   * @param  scheme            The expected scheme for the URL.
   * @param  host              The expected host for the URL.
   * @param  hostProvided      Indicates whether the host was provided in the
   *                           URL string.
   * @param  port              The expected port for the URL.
   * @param  portProvided      Indicates whether the port was provided in the
   *                           URL string.
   * @param  baseDN            The expected base DN for the URL.
   * @param  baseDNProvided    Indicates whether the base DN was provided in the
   *                           URL string.
   * @param  attributes        The expected attributes for the URL.
   * @param  attrsProvided     Indicates whether the attribute list was provided
   *                           in the URL string.
   * @param  scope             The expected scope for the URL.
   * @param  scopeProvided     Indicates whether the scope was provided in the
   *                           URL string.
   * @param  filter            The expected filter for the URL.
   * @param  filterProvided    Indicates whether the filter was provided in the
   *                           URL string.
   * @param  normalizedString  The expected normalized string representation for
   *                           the URL.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidURLs")
  public void testConstructor2Valid(String urlString, String scheme,
                                    String host, boolean hostProvided, int port,
                                    boolean portProvided, DN baseDN,
                                    boolean baseDNProvided, String[] attributes,
                                    boolean attrsProvided, SearchScope scope,
                                    boolean scopeProvided, Filter filter,
                                    boolean filterProvided,
                                    String normalizedString)
         throws Exception
  {
    LDAPURL url = new LDAPURL(scheme, host, (portProvided ? port : null),
                              (baseDNProvided ? baseDN : null),
                              (attrsProvided ? attributes : null),
                              (scopeProvided ? scope : null),
                              (filterProvided ? filter : null));

    assertEquals(url.getScheme(), scheme);
    assertEquals(url.getHost(), host);
    assertEquals(url.hostProvided(), hostProvided);
    assertEquals(url.getPort(), port);
    assertEquals(url.portProvided(), portProvided);
    assertEquals(url.getBaseDN(), baseDN);
    assertEquals(url.baseDNProvided(), baseDNProvided);
    assertEquals(url.getScope(), scope);
    assertEquals(url.scopeProvided(), scopeProvided);
    assertEquals(url.getFilter(), filter);
    assertEquals(url.filterProvided(), filterProvided);
    assertEquals(url.toNormalizedString(), normalizedString);
    assertTrue(Arrays.equals(url.getAttributes(), attributes));
    assertEquals(url.attributesProvided(), attrsProvided);

    assertNotNull(url.toSearchRequest());
    assertEquals(new DN(url.toSearchRequest().getBaseDN()), baseDN);
    assertEquals(url.toSearchRequest().getScope(), scope);
    assertEquals(url.toSearchRequest().getFilter(), filter);
    assertTrue(Arrays.equals(url.toSearchRequest().getAttributes(),
                             attributes));

    assertNotNull(url.toString());

    assertEquals(new LDAPURL(urlString), url);

    LDAPURL url2 = new LDAPURL(normalizedString);
    assertEquals(url2.toNormalizedString(), normalizedString);

    assertEquals(url.hashCode(), url2.hashCode());
    assertEquals(url, url2);
  }



  /**
   * Tests the second constructor with an invalid scheme.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor2InvalidScheme()
         throws Exception
  {
    new LDAPURL("invalid", null, null, null, null, null, null);
  }



  /**
   * Tests the second constructor with a port value that is too low.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor2PortTooLow()
         throws Exception
  {
    new LDAPURL("ldap", null, 0, null, null, null, null);
  }



  /**
   * Tests the second constructor with a port value that is too high.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor2PortTooHigh()
         throws Exception
  {
    new LDAPURL("ldap", null, 100000, null, null, null, null);
  }



  /**
   * Tests the second constructor with an invalid scope value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor2InvalidScope()
         throws Exception
  {
    new LDAPURL("ldap", null, null, null, null, SearchScope.valueOf(5), null);
  }



  /**
   * Tests the {@code equals} method with various cases.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEquals()
         throws Exception
  {
    LDAPURL url1 = new LDAPURL("ldap:///");
    LDAPURL url2 = new LDAPURL("ldap://:389/??base?(objectClass=*)");
    LDAPURL url3 = new LDAPURL("ldap://server.example.com:1389/" +
                            "dc=example,dc=com?cn,sn?sub?(uid=john.doe)");

    // Test null.
    assertFalse(url1.equals(null));
    assertFalse(url2.equals(null));
    assertFalse(url3.equals(null));

    // Test identity.
    assertTrue(url1.equals(url1));
    assertTrue(url2.equals(url2));
    assertTrue(url3.equals(url3));

    // Test not URL.
    assertFalse(url1.equals(5));
    assertFalse(url2.equals(url2.toString()));
    assertFalse(url3.equals(url3.toNormalizedString()));

    // Test equivalent URL.
    assertTrue(url1.equals(url2));
    assertTrue(url2.equals(url1));

    // Test non-equivalent URLs.
    assertFalse(url1.equals(url3));
    assertFalse(url2.equals(url3));
    assertFalse(url3.equals(url1));
    assertFalse(url3.equals(url2));
  }



  /**
   * Retrieves a set of data that may be used to test valid LDAP URLs.
   *
   * @return  A set of data that may be used to test valid LDAP URLs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name = "testValidURLs")
  public Object[][] getTestValidURLs()
         throws Exception
  {
    return new Object[][]
    {
      new Object[]
      {
        "ldap://",
        "ldap",
        null,
        false,
        389,
        false,
        new DN(),
        false,
        new String[0],
        false,
        SearchScope.BASE,
        false,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://:389/??base?(objectclass=*)"
      },

      new Object[]
      {
        "ldaps://",
        "ldaps",
        null,
        false,
        636,
        false,
        new DN(),
        false,
        new String[0],
        false,
        SearchScope.BASE,
        false,
        Filter.create("(objectClass=*)"),
        false,
        "ldaps://:636/??base?(objectclass=*)"
      },

      new Object[]
      {
        "ldapi://",
        "ldapi",
        null,
        false,
        0,
        false,
        new DN(),
        false,
        new String[0],
        false,
        SearchScope.BASE,
        false,
        Filter.create("(objectClass=*)"),
        false,
        "ldapi:///??base?(objectclass=*)"
      },

      new Object[]
      {
        "ldap:///",
        "ldap",
        null,
        false,
        389,
        false,
        new DN(),
        false,
        new String[0],
        false,
        SearchScope.BASE,
        false,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://:389/??base?(objectclass=*)"
      },

      new Object[]
      {
        "ldap://server.example.com",
        "ldap",
        "server.example.com",
        true,
        389,
        false,
        new DN(),
        false,
        new String[0],
        false,
        SearchScope.BASE,
        false,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://server.example.com:389/??base?(objectclass=*)"
      },

      new Object[]
      {
        "ldap://server.example.com:12345",
        "ldap",
        "server.example.com",
        true,
        12345,
        true,
        new DN(),
        false,
        new String[0],
        false,
        SearchScope.BASE,
        false,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://server.example.com:12345/??base?(objectclass=*)"
      },

      new Object[]
      {
        "ldap://:12345",
        "ldap",
        null,
        false,
        12345,
        true,
        new DN(),
        false,
        new String[0],
        false,
        SearchScope.BASE,
        false,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://:12345/??base?(objectclass=*)"
      },

      new Object[]
      {
        "ldap://[::1]",
        "ldap",
        "::1",
        true,
        389,
        false,
        new DN(),
        false,
        new String[0],
        false,
        SearchScope.BASE,
        false,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://[::1]:389/??base?(objectclass=*)"
      },

      new Object[]
      {
        "ldap://[::1]:12345",
        "ldap",
        "::1",
        true,
        12345,
        true,
        new DN(),
        false,
        new String[0],
        false,
        SearchScope.BASE,
        false,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://[::1]:12345/??base?(objectclass=*)"
      },

      new Object[]
      {
        "ldap://server.example.com/",
        "ldap",
        "server.example.com",
        true,
        389,
        false,
        new DN(),
        false,
        new String[0],
        false,
        SearchScope.BASE,
        false,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://server.example.com:389/??base?(objectclass=*)"
      },

      new Object[]
      {
        "ldap://server.example.com:12345/",
        "ldap",
        "server.example.com",
        true,
        12345,
        true,
        new DN(),
        false,
        new String[0],
        false,
        SearchScope.BASE,
        false,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://server.example.com:12345/??base?(objectclass=*)"
      },

      new Object[]
      {
        "ldap://:12345/",
        "ldap",
        null,
        false,
        12345,
        true,
        new DN(),
        false,
        new String[0],
        false,
        SearchScope.BASE,
        false,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://:12345/??base?(objectclass=*)"
      },

      new Object[]
      {
        "ldap://[::1]/",
        "ldap",
        "::1",
        true,
        389,
        false,
        new DN(),
        false,
        new String[0],
        false,
        SearchScope.BASE,
        false,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://[::1]:389/??base?(objectclass=*)"
      },

      new Object[]
      {
        "ldap://[::1]:12345/",
        "ldap",
        "::1",
        true,
        12345,
        true,
        new DN(),
        false,
        new String[0],
        false,
        SearchScope.BASE,
        false,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://[::1]:12345/??base?(objectclass=*)"
      },

      new Object[]
      {
        "ldap://server.example.com/dc=example,dc=com",
        "ldap",
        "server.example.com",
        true,
        389,
        false,
        new DN("dc=example,dc=com"),
        true,
        new String[0],
        false,
        SearchScope.BASE,
        false,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://server.example.com:389/dc=example,dc=com??base?(objectclass=*)"
      },

      new Object[]
      {
        "ldap://server.example.com/dc=example,dc=com?",
        "ldap",
        "server.example.com",
        true,
        389,
        false,
        new DN("dc=example,dc=com"),
        true,
        new String[0],
        false,
        SearchScope.BASE,
        false,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://server.example.com:389/dc=example,dc=com??base?(objectclass=*)"
      },

      new Object[]
      {
        "ldap://server.example.com/dc=example,dc=com??",
        "ldap",
        "server.example.com",
        true,
        389,
        false,
        new DN("dc=example,dc=com"),
        true,
        new String[0],
        false,
        SearchScope.BASE,
        false,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://server.example.com:389/dc=example,dc=com??base?(objectclass=*)"
      },

      new Object[]
      {
        "ldap://server.example.com/dc=example,dc=com? ?",
        "ldap",
        "server.example.com",
        true,
        389,
        false,
        new DN("dc=example,dc=com"),
        true,
        new String[0],
        false,
        SearchScope.BASE,
        false,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://server.example.com:389/dc=example,dc=com??base?(objectclass=*)"
      },

      new Object[]
      {
        "ldap://server.example.com/dc=example,dc=com?givenName",
        "ldap",
        "server.example.com",
        true,
        389,
        false,
        new DN("dc=example,dc=com"),
        true,
        new String[] { "givenName" },
        true,
        SearchScope.BASE,
        false,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://server.example.com:389/dc=example,dc=com?givenname?base?" +
             "(objectclass=*)"
      },

      new Object[]
      {
        "ldap://server.example.com/dc=example,dc=com?givenName?",
        "ldap",
        "server.example.com",
        true,
        389,
        false,
        new DN("dc=example,dc=com"),
        true,
        new String[] { "givenName" },
        true,
        SearchScope.BASE,
        false,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://server.example.com:389/dc=example,dc=com?givenname?base?" +
             "(objectclass=*)"
      },

      new Object[]
      {
        "ldap://server.example.com/dc=example,dc=com?givenName,sn,cn?",
        "ldap",
        "server.example.com",
        true,
        389,
        false,
        new DN("dc=example,dc=com"),
        true,
        new String[] { "givenName", "sn", "cn" },
        true,
        SearchScope.BASE,
        false,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://server.example.com:389/dc=example,dc=com?givenname,sn,cn?" +
             "base?(objectclass=*)"
      },

      new Object[]
      {
        "ldap://server.example.com/dc=example,dc=com??base",
        "ldap",
        "server.example.com",
        true,
        389,
        false,
        new DN("dc=example,dc=com"),
        true,
        new String[0],
        false,
        SearchScope.BASE,
        true,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://server.example.com:389/dc=example,dc=com??base?(objectclass=*)"
      },

      new Object[]
      {
        "ldap://server.example.com/dc=example,dc=com??one",
        "ldap",
        "server.example.com",
        true,
        389,
        false,
        new DN("dc=example,dc=com"),
        true,
        new String[0],
        false,
        SearchScope.ONE,
        true,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://server.example.com:389/dc=example,dc=com??one?(objectclass=*)"
      },

      new Object[]
      {
        "ldap://server.example.com/dc=example,dc=com??sub",
        "ldap",
        "server.example.com",
        true,
        389,
        false,
        new DN("dc=example,dc=com"),
        true,
        new String[0],
        false,
        SearchScope.SUB,
        true,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://server.example.com:389/dc=example,dc=com??sub?(objectclass=*)"
      },

      new Object[]
      {
        "ldap://server.example.com/dc=example,dc=com??subordinates",
        "ldap",
        "server.example.com",
        true,
        389,
        false,
        new DN("dc=example,dc=com"),
        true,
        new String[0],
        false,
        SearchScope.SUBORDINATE_SUBTREE,
        true,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://server.example.com:389/dc=example,dc=com??subordinates?" +
             "(objectclass=*)"
      },

      new Object[]
      {
        "ldap://server.example.com/dc=example,dc=com??base?",
        "ldap",
        "server.example.com",
        true,
        389,
        false,
        new DN("dc=example,dc=com"),
        true,
        new String[0],
        false,
        SearchScope.BASE,
        true,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://server.example.com:389/dc=example,dc=com??base?(objectclass=*)"
      },

      new Object[]
      {
        "ldap://server.example.com/dc=example,dc=com??one?",
        "ldap",
        "server.example.com",
        true,
        389,
        false,
        new DN("dc=example,dc=com"),
        true,
        new String[0],
        false,
        SearchScope.ONE,
        true,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://server.example.com:389/dc=example,dc=com??one?(objectclass=*)"
      },

      new Object[]
      {
        "ldap://server.example.com/dc=example,dc=com??sub?",
        "ldap",
        "server.example.com",
        true,
        389,
        false,
        new DN("dc=example,dc=com"),
        true,
        new String[0],
        false,
        SearchScope.SUB,
        true,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://server.example.com:389/dc=example,dc=com??sub?(objectclass=*)"
      },

      new Object[]
      {
        "ldap://server.example.com/dc=example,dc=com??subordinates?",
        "ldap",
        "server.example.com",
        true,
        389,
        false,
        new DN("dc=example,dc=com"),
        true,
        new String[0],
        false,
        SearchScope.SUBORDINATE_SUBTREE,
        true,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://server.example.com:389/dc=example,dc=com??subordinates?" +
             "(objectclass=*)"
      },

      new Object[]
      {
        "ldap://server.example.com/dc=example,dc=com???(objectClass=*)",
        "ldap",
        "server.example.com",
        true,
        389,
        false,
        new DN("dc=example,dc=com"),
        true,
        new String[0],
        false,
        SearchScope.BASE,
        false,
        Filter.create("(objectClass=*)"),
        true,
        "ldap://server.example.com:389/dc=example,dc=com??base?(objectclass=*)"
      },

      new Object[]
      {
        "ldaps://server.example.com:12345/dc=example,dc=com?givenName,sn?" +
           "sub?(uid=John.Doe)",
        "ldaps",
        "server.example.com",
        true,
        12345,
        true,
        new DN("dc=example,dc=com"),
        true,
        new String[] { "givenName", "sn" },
        true,
        SearchScope.SUB,
        true,
        Filter.create("(uid=John.Doe)"),
        true,
        "ldaps://server.example.com:12345/dc=example,dc=com?givenname,sn?sub" +
             "?(uid=john.doe)"
      },

      new Object[]
      {
        "ldapi:///dc=example,dc=com?givenName,sn?sub?(uid=John.Doe)",
        "ldapi",
        null,
        false,
        0,
        false,
        new DN("dc=example,dc=com"),
        true,
        new String[] { "givenName", "sn" },
        true,
        SearchScope.SUB,
        true,
        Filter.create("(uid=John.Doe)"),
        true,
        "ldapi:///dc=example,dc=com?givenname,sn?sub?(uid=john.doe)"
      },

      new Object[]
      {
        "ldap://server.example.com/o=Example Corp??sub?(cn=foo bar)",
        "ldap",
        "server.example.com",
        true,
        389,
        false,
        new DN("o=Example Corp"),
        true,
        new String[0],
        false,
        SearchScope.SUB,
        true,
        Filter.create("(cn=foo bar)"),
        true,
        "ldap://server.example.com:389/o=example%20corp??sub?(cn=foo%20bar)"
      },

      new Object[]
      {
        "ldap://server.example.com/o=Example%20Corp??sub?(cn=foo%20bar)",
        "ldap",
        "server.example.com",
        true,
        389,
        false,
        new DN("o=Example Corp"),
        true,
        new String[0],
        false,
        SearchScope.SUB,
        true,
        Filter.create("(cn=foo bar)"),
        true,
        "ldap://server.example.com:389/o=example%20corp??sub?(cn=foo%20bar)"
      },

      new Object[]
      {
        "ldap://server.example.com/dc%3Dexample%2Cdc%3Dcom??sub?" +
             "(cn=foo%20bar)",
        "ldap",
        "server.example.com",
        true,
        389,
        false,
        new DN("dc=example,dc=com"),
        true,
        new String[0],
        false,
        SearchScope.SUB,
        true,
        Filter.create("(cn=foo bar)"),
        true,
        "ldap://server.example.com:389/dc=example,dc=com??sub?(cn=foo%20bar)"
      },

      new Object[]
      {
        "ldap://server.example.com/a=b+c=d,dc=example,dc=com??sub?" +
             "(cn=foo%20bar)",
        "ldap",
        "server.example.com",
        true,
        389,
        false,
        new DN("a=b+c=d,dc=example,dc=com"),
        true,
        new String[0],
        false,
        SearchScope.SUB,
        true,
        Filter.create("(cn=foo bar)"),
        true,
        "ldap://server.example.com:389/a=b+c=d,dc=example,dc=com??sub?" +
             "(cn=foo%20bar)"
      },

      new Object[]
      {
        "ldap://child.root.example.com/OU=%25%5E%25%5E%25%5E*,DC=child," +
             "DC=root,DC=example,DC=com",
        "ldap",
        "child.root.example.com",
        true,
        389,
        false,
        new DN(new RDN("OU", "%^%^%^*"), new RDN("DC", "child"),
             new RDN("DC", "root"), new RDN("DC", "example"),
             new RDN("dc", "com")),
        true,
        new String[0],
        false,
        SearchScope.BASE,
        false,
        Filter.create("(objectClass=*)"),
        false,
        "ldap://child.root.example.com:389/ou=%25%5e%25%5e%25%5e*,dc=child," +
             "dc=root,dc=example,dc=com??base?(objectclass=*)"
      }
    };
  }



  /**
   * Retrieves a set of data that may be used to test invalid LDAP URLs.
   *
   * @return  A set of data that may be used to test invalid LDAP URLs.
   */
  @DataProvider(name = "testInvalidURLs")
  public Object[][] getTestInvalidURLs()
  {
    return new Object[][]
    {
      new Object[] { null },
      new Object[] { "" },
      new Object[] { "foo" },
      new Object[] { "foo://" },
      new Object[] { "ldap://:notnumeric" },
      new Object[] { "ldap://:0" },
      new Object[] { "ldap://:65536" },
      new Object[] { "ldap://host:notnumeric" },
      new Object[] { "ldap://host:0" },
      new Object[] { "ldap://host:65536" },
      new Object[] { "ldap://[]" },
      new Object[] { "ldap://[]:389" },
      new Object[] { "ldap://[]:notnumeric" },
      new Object[] { "ldap://[::1]:0" },
      new Object[] { "ldap://[::1]:65536" },
      new Object[] { "ldap://[::1]:notnumeric" },
      new Object[] { "ldap://[::1:389" },
      new Object[] { "ldap://[::1]foo" },
      new Object[] { "ldap:///invalid" },
      new Object[] { "ldap:///invalid?" },
      new Object[] { "ldap:///?," },
      new Object[] { "ldap:///? ," },
      new Object[] { "ldap:///?,givenName,sn" },
      new Object[] { "ldap:///?givenName,,sn" },
      new Object[] { "ldap:///?givenName,sn," },
      new Object[] { "ldap:///?givenName,sn, " },
      new Object[] { "ldap:///?,?" },
      new Object[] { "ldap:///?givenName,,sn?" },
      new Object[] { "ldap:///??invalid" },
      new Object[] { "ldap:///??invalid?" },
      new Object[] { "ldap:///???invalid" },
      new Object[] { "ldap:///dc=%" },
      new Object[] { "ldap:///dc=%0" },
      new Object[] { "ldap:///dc=%w" },
      new Object[] { "ldap:///dc=%0w" },
      new Object[] { "ldap:///dc=%00%" },
      new Object[] { "ldap:///dc=%11%" },
      new Object[] { "ldap:///dc=%22%" },
      new Object[] { "ldap:///dc=%33%" },
      new Object[] { "ldap:///dc=%44%" },
      new Object[] { "ldap:///dc=%55%" },
      new Object[] { "ldap:///dc=%66%" },
      new Object[] { "ldap:///dc=%77%" },
      new Object[] { "ldap:///dc=%88%" },
      new Object[] { "ldap:///dc=%99%" },
      new Object[] { "ldap:///dc=%aa%" },
      new Object[] { "ldap:///dc=%bb%" },
      new Object[] { "ldap:///dc=%cc%" },
      new Object[] { "ldap:///dc=%dd%" },
      new Object[] { "ldap:///dc=%ee%" },
      new Object[] { "ldap:///dc=%ff%" },
      new Object[] { "ldap:///dc=%AA%" },
      new Object[] { "ldap:///dc=%BB%" },
      new Object[] { "ldap:///dc=%CC%" },
      new Object[] { "ldap:///dc=%DD%" },
      new Object[] { "ldap:///dc=%EE%" },
      new Object[] { "ldap:///dc=%FF%" },
    };
  }
}
