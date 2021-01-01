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



import java.util.ArrayList;
import java.util.Arrays;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the DN class.
 */
public class DNTestCase
       extends LDAPSDKTestCase
{
  // The default standard schema for the LDAP SDK.
  private Schema schema = null;



  /**
   * Obtains the default standard schema for the LDAP SDK.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void getSchema()
         throws Exception
  {
    schema = Schema.getDefaultStandardSchema();
  }



  /**
   * Tests the first constructor, which takes an array of RDNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    RDN[] rdns =
    {
      new RDN("givenName=Test+sn=User"),
      new RDN("ou=People"),
      new RDN("dc=example"),
      new RDN("dc=com")
    };

    DN dn = new DN(rdns);
    assertNotNull(dn.getRDN());
    assertEquals(dn.getRDN(), new RDN("givenname=Test+sn=User"));
    assertNotNull(dn.getRDNs());
    assertEquals(dn.getRDNs().length, 4);

    assertEquals(dn.toString(),
                 "givenName=Test+sn=User,ou=People,dc=example,dc=com");

    StringBuilder buffer = new StringBuilder();
    dn.toString(buffer);
    assertEquals(new DN(buffer.toString()), dn);

    DN decodedDN = new DN(dn.toString());
    assertEquals(decodedDN.toNormalizedString(), dn.toNormalizedString());
    assertEquals(decodedDN.hashCode(), dn.hashCode());

    decodedDN = new DN(dn.toMinimallyEncodedString());
    assertEquals(decodedDN.toNormalizedString(), dn.toNormalizedString());
    assertEquals(decodedDN.hashCode(), dn.hashCode());

    assertEquals(dn.toNormalizedString(),
                 "givenname=test+sn=user,ou=people,dc=example,dc=com");
    decodedDN = new DN(dn.toNormalizedString());
    assertEquals(decodedDN, dn);
    assertEquals(decodedDN.hashCode(), dn.hashCode());

    DN parentDN = dn.getParent();
    assertNotNull(parentDN);
    assertEquals(parentDN.toString(), "ou=People,dc=example,dc=com");
    assertEquals(parentDN.toNormalizedString(), "ou=people,dc=example,dc=com");

    assertFalse(dn.isAncestorOf(parentDN, true));
    assertTrue(parentDN.isAncestorOf(dn, true));
    assertTrue(dn.isAncestorOf(dn, true));
    assertTrue(parentDN.isAncestorOf(parentDN, true));

    assertFalse(dn.isAncestorOf(parentDN, false));
    assertTrue(parentDN.isAncestorOf(dn, false));
    assertFalse(dn.isAncestorOf(dn, false));
    assertFalse(parentDN.isAncestorOf(parentDN, false));

    assertTrue(dn.isDescendantOf(parentDN, true));
    assertFalse(parentDN.isDescendantOf(dn, true));
    assertTrue(dn.isDescendantOf(dn, true));
    assertTrue(parentDN.isDescendantOf(parentDN, true));

    assertTrue(dn.isDescendantOf(parentDN, false));
    assertFalse(parentDN.isDescendantOf(dn, false));
    assertFalse(dn.isDescendantOf(dn, false));
    assertFalse(parentDN.isDescendantOf(parentDN, false));
  }



  /**
   * Tests the first constructor, which takes an array of RDNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1WithSchema()
         throws Exception
  {
    RDN[] rdns =
    {
      new RDN("cn=Test User+emailAddress=test.user@example.com", schema),
      new RDN("ou=People", schema),
      new RDN("dc=example", schema),
      new RDN("dc=com", schema)
    };

    DN dn = new DN(rdns);
    assertNotNull(dn.getRDN());
    assertEquals(dn.getRDN(),
         new RDN("cn=test user+e=Test.User@EXAMPLE.COM", schema));
    assertNotNull(dn.getRDNs());
    assertEquals(dn.getRDNs().length, 4);

    assertEquals(dn.toString(),
         "cn=Test User+emailAddress=test.user@example.com,ou=People," +
              "dc=example,dc=com");

    StringBuilder buffer = new StringBuilder();
    dn.toString(buffer);
    assertEquals(new DN(buffer.toString(), schema), dn);

    DN decodedDN = new DN(dn.toString(), schema);
    assertEquals(decodedDN.toNormalizedString(), dn.toNormalizedString());
    assertEquals(decodedDN.hashCode(), dn.hashCode());

    decodedDN = new DN(dn.toMinimallyEncodedString(), schema);
    assertEquals(decodedDN.toNormalizedString(), dn.toNormalizedString());
    assertEquals(decodedDN.hashCode(), dn.hashCode());

    assertEquals(dn.toNormalizedString(),
         "cn=test user+e=test.user@example.com,ou=people,dc=example,dc=com");
    decodedDN = new DN(dn.toNormalizedString(), schema);
    assertEquals(decodedDN, dn);
    assertEquals(decodedDN.hashCode(), dn.hashCode());

    DN parentDN = dn.getParent();
    assertNotNull(parentDN);
    assertEquals(parentDN.toString(), "ou=People,dc=example,dc=com");
    assertEquals(parentDN.toNormalizedString(), "ou=people,dc=example,dc=com");

    assertFalse(dn.isAncestorOf(parentDN, true));
    assertTrue(parentDN.isAncestorOf(dn, true));
    assertTrue(dn.isAncestorOf(dn, true));
    assertTrue(parentDN.isAncestorOf(parentDN, true));

    assertFalse(dn.isAncestorOf(parentDN, false));
    assertTrue(parentDN.isAncestorOf(dn, false));
    assertFalse(dn.isAncestorOf(dn, false));
    assertFalse(parentDN.isAncestorOf(parentDN, false));

    assertTrue(dn.isDescendantOf(parentDN, true));
    assertFalse(parentDN.isDescendantOf(dn, true));
    assertTrue(dn.isDescendantOf(dn, true));
    assertTrue(parentDN.isDescendantOf(parentDN, true));

    assertTrue(dn.isDescendantOf(parentDN, false));
    assertFalse(parentDN.isDescendantOf(dn, false));
    assertFalse(dn.isDescendantOf(dn, false));
    assertFalse(parentDN.isDescendantOf(parentDN, false));
  }



  /**
   * Tests the first constructor with a {@code null} RDN array.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1Null()
  {
    new DN((RDN[]) null);
  }



  /**
   * Tests the first constructor with an empty RDN array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Empty()
         throws Exception
  {
    DN dn = new DN(new RDN[0]);
    assertNull(dn.getRDN());
    assertNotNull(dn.getRDNs());
    assertEquals(dn.getRDNs().length, 0);

    assertEquals(dn.toString(), "");

    StringBuilder buffer = new StringBuilder();
    dn.toString(buffer);
    assertEquals(new DN(buffer.toString()), dn);

    DN decodedDN = new DN(dn.toString());
    assertEquals(decodedDN, dn);
    assertEquals(decodedDN.hashCode(), dn.hashCode());

    decodedDN = new DN(dn.toMinimallyEncodedString());
    assertEquals(decodedDN, dn);
    assertEquals(decodedDN.hashCode(), dn.hashCode());

    assertEquals(dn.toNormalizedString(), "");
    decodedDN = new DN(dn.toNormalizedString());
    assertEquals(decodedDN, dn);
    assertEquals(decodedDN.hashCode(), dn.hashCode());

    assertNull(dn.getParent());
    assertEquals(dn, DN.NULL_DN);
    assertEquals(dn.hashCode(), DN.NULL_DN.hashCode());

    assertTrue(dn.isAncestorOf(DN.NULL_DN, true));
    assertTrue(dn.isDescendantOf(DN.NULL_DN, true));

    assertFalse(dn.isAncestorOf(DN.NULL_DN, false));
    assertFalse(dn.isDescendantOf(DN.NULL_DN, false));
  }



  /**
   * Tests the second constructor, which takes a list of RDNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    ArrayList<RDN> rdnList = new ArrayList<RDN>();
    rdnList.add(new RDN("givenName=Test+sn=User"));
    rdnList.add(new RDN("ou=People"));
    rdnList.add(new RDN("dc=example"));
    rdnList.add(new RDN("dc=com"));

    DN dn = new DN(rdnList);
    assertNotNull(dn.getRDN());
    assertEquals(dn.getRDN(), new RDN("givenname=Test+sn=User"));
    assertNotNull(dn.getRDNs());
    assertEquals(dn.getRDNs().length, 4);

    assertEquals(dn.toString(),
                 "givenName=Test+sn=User,ou=People,dc=example,dc=com");

    StringBuilder buffer = new StringBuilder();
    dn.toString(buffer);
    assertEquals(new DN(buffer.toString()), dn);

    DN decodedDN = new DN(dn.toString());
    assertEquals(decodedDN.toNormalizedString(), dn.toNormalizedString());
    assertEquals(decodedDN.hashCode(), dn.hashCode());

    decodedDN = new DN(dn.toMinimallyEncodedString());
    assertEquals(decodedDN.toNormalizedString(), dn.toNormalizedString());
    assertEquals(decodedDN.hashCode(), dn.hashCode());

    assertEquals(dn.toNormalizedString(),
                 "givenname=test+sn=user,ou=people,dc=example,dc=com");
    decodedDN = new DN(dn.toNormalizedString());
    assertEquals(decodedDN, dn);
    assertEquals(decodedDN.hashCode(), dn.hashCode());

    DN parentDN = dn.getParent();
    assertNotNull(parentDN);
    assertEquals(parentDN.toString(), "ou=People,dc=example,dc=com");
    assertEquals(parentDN.toNormalizedString(), "ou=people,dc=example,dc=com");

    assertFalse(dn.isAncestorOf(parentDN, true));
    assertTrue(parentDN.isAncestorOf(dn, true));
    assertTrue(dn.isAncestorOf(dn, true));
    assertTrue(parentDN.isAncestorOf(parentDN, true));

    assertFalse(dn.isAncestorOf(parentDN, false));
    assertTrue(parentDN.isAncestorOf(dn, false));
    assertFalse(dn.isAncestorOf(dn, false));
    assertFalse(parentDN.isAncestorOf(parentDN, false));

    assertTrue(dn.isDescendantOf(parentDN, true));
    assertFalse(parentDN.isDescendantOf(dn, true));
    assertTrue(dn.isDescendantOf(dn, true));
    assertTrue(parentDN.isDescendantOf(parentDN, true));

    assertTrue(dn.isDescendantOf(parentDN, false));
    assertFalse(parentDN.isDescendantOf(dn, false));
    assertFalse(dn.isDescendantOf(dn, false));
    assertFalse(parentDN.isDescendantOf(parentDN, false));
  }



  /**
   * Tests the second constructor, which takes a list of RDNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2WithSchema()
         throws Exception
  {
    ArrayList<RDN> rdnList = new ArrayList<RDN>();
    rdnList.add(new RDN("givenName=Test+sn=User", schema));
    rdnList.add(new RDN("ou=People", schema));
    rdnList.add(new RDN("dc=example", schema));
    rdnList.add(new RDN("dc=com", schema));

    DN dn = new DN(rdnList);
    assertNotNull(dn.getRDN());
    assertEquals(dn.getRDN(), new RDN("givenname=Test+sn=User"));
    assertNotNull(dn.getRDNs());
    assertEquals(dn.getRDNs().length, 4);

    assertEquals(dn.toString(),
                 "givenName=Test+sn=User,ou=People,dc=example,dc=com");

    StringBuilder buffer = new StringBuilder();
    dn.toString(buffer);
    assertEquals(new DN(buffer.toString(), schema), dn);

    DN decodedDN = new DN(dn.toString(), schema);
    assertEquals(decodedDN.toNormalizedString(), dn.toNormalizedString());
    assertEquals(decodedDN.hashCode(), dn.hashCode());

    decodedDN = new DN(dn.toMinimallyEncodedString(), schema);
    assertEquals(decodedDN.toNormalizedString(), dn.toNormalizedString());
    assertEquals(decodedDN.hashCode(), dn.hashCode());

    assertEquals(dn.toNormalizedString(),
                 "givenname=test+sn=user,ou=people,dc=example,dc=com");
    decodedDN = new DN(dn.toNormalizedString(), schema);
    assertEquals(decodedDN, dn);
    assertEquals(decodedDN.hashCode(), dn.hashCode());

    DN parentDN = dn.getParent();
    assertNotNull(parentDN);
    assertEquals(parentDN.toString(), "ou=People,dc=example,dc=com");
    assertEquals(parentDN.toNormalizedString(), "ou=people,dc=example,dc=com");

    assertFalse(dn.isAncestorOf(parentDN, true));
    assertTrue(parentDN.isAncestorOf(dn, true));
    assertTrue(dn.isAncestorOf(dn, true));
    assertTrue(parentDN.isAncestorOf(parentDN, true));

    assertFalse(dn.isAncestorOf(parentDN, false));
    assertTrue(parentDN.isAncestorOf(dn, false));
    assertFalse(dn.isAncestorOf(dn, false));
    assertFalse(parentDN.isAncestorOf(parentDN, false));

    assertTrue(dn.isDescendantOf(parentDN, true));
    assertFalse(parentDN.isDescendantOf(dn, true));
    assertTrue(dn.isDescendantOf(dn, true));
    assertTrue(parentDN.isDescendantOf(parentDN, true));

    assertTrue(dn.isDescendantOf(parentDN, false));
    assertFalse(parentDN.isDescendantOf(dn, false));
    assertFalse(dn.isDescendantOf(dn, false));
    assertFalse(parentDN.isDescendantOf(parentDN, false));
  }



  /**
   * Tests the second constructor with a {@code null} RDN array.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor2Null()
  {
    new DN((ArrayList<RDN>) null);
  }



  /**
   * Tests the second constructor with an empty RDN array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Empty()
         throws Exception
  {
    DN dn = new DN(new ArrayList<RDN>());
    assertNull(dn.getRDN());
    assertNotNull(dn.getRDNs());
    assertEquals(dn.getRDNs().length, 0);

    assertEquals(dn.toString(), "");

    StringBuilder buffer = new StringBuilder();
    dn.toString(buffer);
    assertEquals(new DN(buffer.toString()), dn);

    DN decodedDN = new DN(dn.toString());
    assertEquals(decodedDN, dn);
    assertEquals(decodedDN.hashCode(), dn.hashCode());

    decodedDN = new DN(dn.toMinimallyEncodedString());
    assertEquals(decodedDN, dn);
    assertEquals(decodedDN.hashCode(), dn.hashCode());

    assertEquals(dn.toNormalizedString(), "");
    decodedDN = new DN(dn.toNormalizedString());
    assertEquals(decodedDN, dn);
    assertEquals(decodedDN.hashCode(), dn.hashCode());

    assertNull(dn.getParent());
    assertEquals(dn, DN.NULL_DN);
    assertEquals(dn.hashCode(), DN.NULL_DN.hashCode());

    assertTrue(dn.isAncestorOf(DN.NULL_DN, true));
    assertTrue(dn.isDescendantOf(DN.NULL_DN, true));

    assertFalse(dn.isAncestorOf(DN.NULL_DN, false));
    assertFalse(dn.isDescendantOf(DN.NULL_DN, false));
  }



  /**
   * Tests the third constructor, which takes an RDN and a parent DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3()
         throws Exception
  {
    DN parentDN = new DN("ou=People,dc=example,dc=com");

    DN dn = new DN(new RDN("givenName=Test+sn=User"), parentDN);
    assertNotNull(dn.getRDN());
    assertEquals(dn.getRDN(), new RDN("givenname=Test+sn=User"));
    assertNotNull(dn.getRDNs());
    assertEquals(dn.getRDNs().length, 4);

    assertEquals(dn.toString(),
                 "givenName=Test+sn=User,ou=People,dc=example,dc=com");

    StringBuilder buffer = new StringBuilder();
    dn.toString(buffer);
    assertEquals(new DN(buffer.toString()), dn);

    DN decodedDN = new DN(dn.toString());
    assertEquals(decodedDN.toNormalizedString(), dn.toNormalizedString());
    assertEquals(decodedDN.hashCode(), dn.hashCode());

    decodedDN = new DN(dn.toMinimallyEncodedString());
    assertEquals(decodedDN.toNormalizedString(), dn.toNormalizedString());
    assertEquals(decodedDN.hashCode(), dn.hashCode());

    assertEquals(dn.toNormalizedString(),
                 "givenname=test+sn=user,ou=people,dc=example,dc=com");
    decodedDN = new DN(dn.toNormalizedString());
    assertEquals(decodedDN, dn);
    assertEquals(decodedDN.hashCode(), dn.hashCode());

    assertEquals(dn.getParent(), parentDN);
    parentDN = dn.getParent();
    assertNotNull(parentDN);
    assertEquals(parentDN.toString(), "ou=People,dc=example,dc=com");
    assertEquals(parentDN.toNormalizedString(), "ou=people,dc=example,dc=com");

    assertFalse(dn.isAncestorOf(parentDN, true));
    assertTrue(parentDN.isAncestorOf(dn, true));
    assertTrue(dn.isAncestorOf(dn, true));
    assertTrue(parentDN.isAncestorOf(parentDN, true));

    assertFalse(dn.isAncestorOf(parentDN, false));
    assertTrue(parentDN.isAncestorOf(dn, false));
    assertFalse(dn.isAncestorOf(dn, false));
    assertFalse(parentDN.isAncestorOf(parentDN, false));

    assertTrue(dn.isDescendantOf(parentDN, true));
    assertFalse(parentDN.isDescendantOf(dn, true));
    assertTrue(dn.isDescendantOf(dn, true));
    assertTrue(parentDN.isDescendantOf(parentDN, true));

    assertTrue(dn.isDescendantOf(parentDN, false));
    assertFalse(parentDN.isDescendantOf(dn, false));
    assertFalse(dn.isDescendantOf(dn, false));
    assertFalse(parentDN.isDescendantOf(parentDN, false));
  }



  /**
   * Tests the third constructor, which takes an RDN and a parent DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3WithSchema()
         throws Exception
  {
    DN parentDN = new DN("ou=People,dc=example,dc=com", schema);

    DN dn = new DN(new RDN("givenName=Test+sn=User", schema), parentDN);
    assertNotNull(dn.getRDN());
    assertEquals(dn.getRDN(), new RDN("givenname=Test+sn=User", schema));
    assertNotNull(dn.getRDNs());
    assertEquals(dn.getRDNs().length, 4);

    assertEquals(dn.toString(),
                 "givenName=Test+sn=User,ou=People,dc=example,dc=com");

    StringBuilder buffer = new StringBuilder();
    dn.toString(buffer);
    assertEquals(new DN(buffer.toString(), schema), dn);

    DN decodedDN = new DN(dn.toString(), schema);
    assertEquals(decodedDN.toNormalizedString(), dn.toNormalizedString());
    assertEquals(decodedDN.hashCode(), dn.hashCode());

    decodedDN = new DN(dn.toMinimallyEncodedString(), schema);
    assertEquals(decodedDN.toNormalizedString(), dn.toNormalizedString());
    assertEquals(decodedDN.hashCode(), dn.hashCode());

    assertEquals(dn.toNormalizedString(),
                 "givenname=test+sn=user,ou=people,dc=example,dc=com");
    decodedDN = new DN(dn.toNormalizedString(), schema);
    assertEquals(decodedDN, dn);
    assertEquals(decodedDN.hashCode(), dn.hashCode());

    assertEquals(dn.getParent(), parentDN);
    parentDN = dn.getParent();
    assertNotNull(parentDN);
    assertEquals(parentDN.toString(), "ou=People,dc=example,dc=com");
    assertEquals(parentDN.toNormalizedString(), "ou=people,dc=example,dc=com");

    assertFalse(dn.isAncestorOf(parentDN, true));
    assertTrue(parentDN.isAncestorOf(dn, true));
    assertTrue(dn.isAncestorOf(dn, true));
    assertTrue(parentDN.isAncestorOf(parentDN, true));

    assertFalse(dn.isAncestorOf(parentDN, false));
    assertTrue(parentDN.isAncestorOf(dn, false));
    assertFalse(dn.isAncestorOf(dn, false));
    assertFalse(parentDN.isAncestorOf(parentDN, false));

    assertTrue(dn.isDescendantOf(parentDN, true));
    assertFalse(parentDN.isDescendantOf(dn, true));
    assertTrue(dn.isDescendantOf(dn, true));
    assertTrue(parentDN.isDescendantOf(parentDN, true));

    assertTrue(dn.isDescendantOf(parentDN, false));
    assertFalse(parentDN.isDescendantOf(dn, false));
    assertFalse(dn.isDescendantOf(dn, false));
    assertFalse(parentDN.isDescendantOf(parentDN, false));
  }



  /**
   * Tests the third constructor with a null RDN and a non-null parent DN.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor3NullRDN()
         throws Exception
  {
    new DN(null, new DN("ou=People,dc=example,dc=com"));
  }



  /**
   * Tests the third constructor with a non-null RDN and a null parent DN.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor3NullParentDN()
         throws Exception
  {
    new DN(new RDN("givenName=Test+sn=User"), null);
  }



  /**
   * Tests the third constructor using the null DN as the parent DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3NoParent()
         throws Exception
  {
    DN dn = new DN(new RDN("o=example.com"), DN.NULL_DN);
    assertNotNull(dn.getRDNs());
    assertEquals(dn.getRDNs().length, 1);

    assertEquals(dn.toString(), "o=example.com");

    StringBuilder buffer = new StringBuilder();
    dn.toString(buffer);
    assertEquals(new DN(buffer.toString()), dn);

    assertEquals(dn.toNormalizedString(), "o=example.com");
  }



  /**
   * Tests the fourth constructor, which creates a DN from a string
   * representation, using a valid DN string.
   *
   * @param  dnString          The string representation for the DN.
   * @param  normalizedString  The normalized string representation for the DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidDNs")
  public void testConstructor4Valid(String dnString, String normalizedString)
         throws Exception
  {
    DN dn = new DN(dnString);

    assertEquals(dn.toString(), dnString);

    StringBuilder buffer = new StringBuilder();
    dn.toString(buffer);
    assertEquals(new DN(buffer.toString()), dn);

    assertEquals(dn.toNormalizedString(), normalizedString);
  }



  /**
   * Tests the fourth constructor, which creates a DN from a string
   * representation, using a valid DN string.
   *
   * @param  dnString          The string representation for the DN.
   * @param  normalizedString  The normalized string representation for the DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidDNs")
  public void testConstructor4ValidWithSchema(final String dnString,
                                              final String normalizedString)
         throws Exception
  {
    DN dn = new DN(dnString, schema);

    assertEquals(dn.toString(), dnString);

    StringBuilder buffer = new StringBuilder();
    dn.toString(buffer);
    assertEquals(new DN(buffer.toString(), schema), dn);

    assertEquals(dn.toNormalizedString(), normalizedString);
  }



  /**
   * Tests the fourth constructor, which creates a DN from a string
   * representation, using an invalid DN string.
   *
   * @param  dnString  The invalid string representation for the DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testInvalidDNs",
        expectedExceptions = { LDAPSDKUsageException.class,
                               LDAPException.class })
  public void testConstructor4Invalid(String dnString)
         throws Exception
  {
    new DN(dnString);
  }



  /**
   * Tests the {@code isValidDN} method with valid DNs.
   *
   * @param  s  The string to test.
   * @param  n  The normalized version of the string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidDNs")
  public void testIsValidDNTrue(String s, String n)
         throws Exception
  {
    assertTrue(DN.isValidDN(s));
    assertTrue(DN.isValidDN(s, false));
    assertTrue(DN.isValidDN(s, true));
  }



  /**
   * Tests the {@code isValidDN} method with invalid DNs.
   *
   * @param  s  The string to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testInvalidDNs")
  public void testIsValidDNFalse(String s)
         throws Exception
  {
    assertFalse(DN.isValidDN(s));
    assertFalse(DN.isValidDN(s, false));
    assertFalse(DN.isValidDN(s, true));
  }



  /**
   * Tests the {@code isValidDN} method with DNs that are invalid when it comes
   * to having malformed attribute names or OIDs.
   *
   * @param  s  The string to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testInvalidDNAttributes")
  public void testIsValidDNWithInvalidAttributeNames(String s)
         throws Exception
  {
    new DN(s);
    new DN(s, null, false);

    try
    {
      new DN(s, null, true);
      fail("Expected an exception because of an invalid attribute name.");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }

    assertTrue(DN.isValidDN(s));
    assertTrue(DN.isValidDN(s, false));
    assertFalse(DN.isValidDN(s, true));
  }



  /**
   * Tests the {@code getRDNString} methods with valid DNs.
   *
   * @param  s  The string representation of the DN to test.
   * @param  n  The normalized version of the string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidDNs")
  public void testGetRDNString(String s, String n)
         throws Exception
  {
    DN dn = new DN(s);
    if (dn.getRDN() == null)
    {
      assertNull(dn.getRDNString());
      assertNull(DN.getRDNString(s));
    }
    else
    {
      assertNotNull(dn.getRDNString());
      assertEquals(new RDN(dn.getRDNString()), dn.getRDN());

      assertNotNull(DN.getRDNString(s));
      assertEquals(new RDN(DN.getRDNString(s)), dn.getRDN());
    }
  }



  /**
   * Tests the {@code getRDNs} method that takes a string argument.
   *
   * @param  s  The string representation of the DN to test.
   * @param  n  The normalized version of the string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidDNs")
  public void testGetRDNsFromString(String s, String n)
         throws Exception
  {
    DN dn = new DN(s);

    assertNotNull(DN.getRDNs(s));
    assertTrue(Arrays.equals(DN.getRDNs(s), dn.getRDNs()));
  }



  /**
   * Tests the {@code getRDNStrings} methods.
   *
   * @param  s  The string representation of the DN to test.
   * @param  n  The normalized version of the string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidDNs")
  public void testGetRDNStrings(String s, String n)
         throws Exception
  {
    DN dn = new DN(s);

    String[] rdnStrings = dn.getRDNStrings();
    assertNotNull(rdnStrings);
    assertEquals(rdnStrings.length, dn.getRDNs().length);

    for (int i=0; i < rdnStrings.length; i++)
    {
      assertEquals(new RDN(rdnStrings[i]), dn.getRDNs()[i]);
    }

    assertNotNull(DN.getRDNStrings(s));
    assertTrue(Arrays.equals(DN.getRDNStrings(s), rdnStrings));
  }



  /**
   * Tests the {@code getParent} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetParent()
         throws Exception
  {
    assertNull(DN.NULL_DN.getParent());
    assertNull(new DN().getParent());
    assertNull(new DN("o=example.com").getParent());
    assertEquals(new DN("dc=example,dc=com").getParent(), new DN("dc=com"));
    assertEquals(new DN("ou=People,dc=example,dc=com").getParent(),
                 new DN("dc=example,dc=com"));
    assertEquals(
         new DN("uid=test.user,ou=People,dc=example,dc=com").getParent(),
         new DN("ou=People,dc=example,dc=com"));
    assertEquals(new DN("a=b,c=d,e=f,g=h,i=j").getParent(),
                 new DN("c=d,e=f,g=h,i=j"));
    assertEquals(new DN("a=b,c=d,e=f,g=h,i=j,k=l").getParent(),
                 new DN("c=d,e=f,g=h,i=j,k=l"));

    assertNull(DN.getParent(""));
    assertNull(DN.getParent("o=example.com"));
    assertEquals(DN.getParent("dc=example,dc=com"), new DN("dc=com"));
    assertEquals(DN.getParent("ou=People,dc=example,dc=com"),
                 new DN("dc=example,dc=com"));
    assertEquals(
         DN.getParent("uid=test.user,ou=People,dc=example,dc=com"),
         new DN("ou=People,dc=example,dc=com"));
    assertEquals(DN.getParent("a=b,c=d,e=f,g=h,i=j"),
                 new DN("c=d,e=f,g=h,i=j"));
    assertEquals(DN.getParent("a=b,c=d,e=f,g=h,i=j,k=l"),
                 new DN("c=d,e=f,g=h,i=j,k=l"));
  }



  /**
   * Tests the {@code getParentString} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetParentString()
         throws Exception
  {
    assertNull(DN.NULL_DN.getParentString());
    assertNull(new DN().getParentString());
    assertNull(DN.getParentString(""));
    assertNull(DN.getParentString("o=example.com"));

    assertEquals(new DN(DN.getParentString("dc=example,dc=com")),
                 new DN("dc=com"));
    assertEquals(new DN(DN.getParentString("ou=People,dc=example,dc=com")),
                 new DN("dc=example,dc=com"));
    assertEquals(new DN(
              DN.getParentString("uid=test.user,ou=People,dc=example,dc=com")),
         new DN("ou=People,dc=example,dc=com"));
    assertEquals(new DN(DN.getParentString("a=b,c=d,e=f,g=h,i=j")),
                 new DN("c=d,e=f,g=h,i=j"));
    assertEquals(new DN(DN.getParentString("a=b,c=d,e=f,g=h,i=j,k=l")),
                 new DN("c=d,e=f,g=h,i=j,k=l"));
  }



  /**
   * Tests the {@code isAncestorOf} and {@code isDescendantOf} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIsAncestorOfAndIsDescendantOf()
         throws Exception
  {
    DN dn = new DN("dc=example,dc=com");

    DN dn2 = DN.NULL_DN;
    assertFalse(dn.isAncestorOf(dn2, true));
    assertTrue(dn2.isAncestorOf(dn, true));
    assertTrue(dn.isDescendantOf(dn2, true));
    assertFalse(dn2.isDescendantOf(dn, true));
    assertFalse(dn.isAncestorOf(dn2, false));
    assertTrue(dn2.isAncestorOf(dn, false));
    assertTrue(dn.isDescendantOf(dn2, false));
    assertFalse(dn2.isDescendantOf(dn, false));

    dn2 = new DN();
    assertFalse(dn.isAncestorOf(dn2, true));
    assertTrue(dn2.isAncestorOf(dn, true));
    assertTrue(dn.isDescendantOf(dn2, true));
    assertFalse(dn2.isDescendantOf(dn, true));
    assertFalse(dn.isAncestorOf(dn2, false));
    assertTrue(dn2.isAncestorOf(dn, false));
    assertTrue(dn.isDescendantOf(dn2, false));
    assertFalse(dn2.isDescendantOf(dn, false));

    dn2 = new DN("dc=com");
    assertFalse(dn.isAncestorOf(dn2, true));
    assertTrue(dn2.isAncestorOf(dn, true));
    assertTrue(dn.isDescendantOf(dn2, true));
    assertFalse(dn2.isDescendantOf(dn, true));
    assertFalse(dn.isAncestorOf(dn2, false));
    assertTrue(dn2.isAncestorOf(dn, false));
    assertTrue(dn.isDescendantOf(dn2, false));
    assertFalse(dn2.isDescendantOf(dn, false));

    dn2 = new DN("ou=People,o=example.com");
    assertFalse(dn.isAncestorOf(dn2, true));
    assertFalse(dn2.isAncestorOf(dn, true));
    assertFalse(dn.isDescendantOf(dn2, true));
    assertFalse(dn2.isDescendantOf(dn, true));
    assertFalse(dn.isAncestorOf(dn2, false));
    assertFalse(dn2.isAncestorOf(dn, false));
    assertFalse(dn.isDescendantOf(dn2, false));
    assertFalse(dn2.isDescendantOf(dn, false));

    dn2 = new DN("dc=example,dc=coma");
    assertFalse(dn.isAncestorOf(dn2, true));
    assertFalse(dn2.isAncestorOf(dn, true));
    assertFalse(dn.isDescendantOf(dn2, true));
    assertFalse(dn2.isDescendantOf(dn, true));
    assertFalse(dn.isAncestorOf(dn2, false));
    assertFalse(dn2.isAncestorOf(dn, false));
    assertFalse(dn.isDescendantOf(dn2, false));
    assertFalse(dn2.isDescendantOf(dn, false));

    assertTrue(dn.isAncestorOf(dn, true));
    assertTrue(dn.isDescendantOf(dn, true));
    assertFalse(dn.isAncestorOf(dn, false));
    assertFalse(dn.isDescendantOf(dn, false));

    dn2 = new DN("dc=example,dc=com");
    assertTrue(dn.isAncestorOf(dn2, true));
    assertTrue(dn2.isAncestorOf(dn, true));
    assertTrue(dn.isDescendantOf(dn2, true));
    assertTrue(dn2.isDescendantOf(dn, true));
    assertFalse(dn.isAncestorOf(dn2, false));
    assertFalse(dn2.isAncestorOf(dn, false));
    assertFalse(dn.isDescendantOf(dn2, false));
    assertFalse(dn2.isDescendantOf(dn, false));

    dn2 = new DN("ou=People,dc=example,dc=com");
    assertTrue(dn.isAncestorOf(dn2, true));
    assertFalse(dn2.isAncestorOf(dn, true));
    assertFalse(dn.isDescendantOf(dn2, true));
    assertTrue(dn2.isDescendantOf(dn, true));
    assertTrue(dn.isAncestorOf(dn2, false));
    assertFalse(dn2.isAncestorOf(dn, false));
    assertFalse(dn.isDescendantOf(dn2, false));
    assertTrue(dn2.isDescendantOf(dn, false));

    dn2 = new DN("uid=test.user,ou=People,dc=example,dc=com");
    assertTrue(dn.isAncestorOf(dn2, true));
    assertFalse(dn2.isAncestorOf(dn, true));
    assertFalse(dn.isDescendantOf(dn2, true));
    assertTrue(dn2.isDescendantOf(dn, true));
    assertTrue(dn.isAncestorOf(dn2, false));
    assertFalse(dn2.isAncestorOf(dn, false));
    assertFalse(dn.isDescendantOf(dn2, false));
    assertTrue(dn2.isDescendantOf(dn, false));

    dn2 = new DN("a=b,uid=test.user,ou=People,dc=example,dc=com");
    assertTrue(dn.isAncestorOf(dn2, true));
    assertFalse(dn2.isAncestorOf(dn, true));
    assertFalse(dn.isDescendantOf(dn2, true));
    assertTrue(dn2.isDescendantOf(dn, true));
    assertTrue(dn.isAncestorOf(dn2, false));
    assertFalse(dn2.isAncestorOf(dn, false));
    assertFalse(dn.isDescendantOf(dn2, false));
    assertTrue(dn2.isDescendantOf(dn, false));
  }



  /**
   * Tests the {@code isAncestorOf} and {@code isDescendantOf} methods that take
   * one single string argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIsAncestorOfAndIsDescendantOfOneString()
         throws Exception
  {
    DN dn = new DN("dc=example,dc=com");

    String dn2 = "";
    assertFalse(dn.isAncestorOf(dn2, true));
    assertTrue(dn.isDescendantOf(dn2, true));
    assertFalse(dn.isAncestorOf(dn2, false));
    assertTrue(dn.isDescendantOf(dn2, false));

    dn2 = "dc=com";
    assertFalse(dn.isAncestorOf(dn2, true));
    assertTrue(dn.isDescendantOf(dn2, true));
    assertFalse(dn.isAncestorOf(dn2, false));
    assertTrue(dn.isDescendantOf(dn2, false));

    dn2 = "ou=People,o=example.com";
    assertFalse(dn.isAncestorOf(dn2, true));
    assertFalse(dn.isDescendantOf(dn2, true));
    assertFalse(dn.isAncestorOf(dn2, false));
    assertFalse(dn.isDescendantOf(dn2, false));

    dn2 = "dc=example,dc=coma";
    assertFalse(dn.isAncestorOf(dn2, true));
    assertFalse(dn.isDescendantOf(dn2, true));
    assertFalse(dn.isAncestorOf(dn2, false));
    assertFalse(dn.isDescendantOf(dn2, false));

    dn2 = "dc=example,dc=com";
    assertTrue(dn.isAncestorOf(dn2, true));
    assertTrue(dn.isDescendantOf(dn2, true));
    assertFalse(dn.isAncestorOf(dn2, false));
    assertFalse(dn.isDescendantOf(dn2, false));

    dn2 = "ou=People,dc=example,dc=com";
    assertTrue(dn.isAncestorOf(dn2, true));
    assertFalse(dn.isDescendantOf(dn2, true));
    assertTrue(dn.isAncestorOf(dn2, false));
    assertFalse(dn.isDescendantOf(dn2, false));

    dn2 = "uid=test.user,ou=People,dc=example,dc=com";
    assertTrue(dn.isAncestorOf(dn2, true));
    assertFalse(dn.isDescendantOf(dn2, true));
    assertTrue(dn.isAncestorOf(dn2, false));
    assertFalse(dn.isDescendantOf(dn2, false));

    dn2 = "a=b,uid=test.user,ou=People,dc=example,dc=com";
    assertTrue(dn.isAncestorOf(dn2, true));
    assertFalse(dn.isDescendantOf(dn2, true));
    assertTrue(dn.isAncestorOf(dn2, false));
    assertFalse(dn.isDescendantOf(dn2, false));
  }



  /**
   * Tests the {@code isAncestorOf} and {@code isDescendantOf} methods that take
   * two strings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIsAncestorOfAndIsDescendantOfTwoStrings()
         throws Exception
  {
    String dn1 = "dc=example,dc=com";

    String dn2 = "";
    assertFalse(DN.isAncestorOf(dn1, dn2, true));
    assertTrue(DN.isAncestorOf(dn2, dn1, true));
    assertTrue(DN.isDescendantOf(dn1, dn2, true));
    assertFalse(DN.isDescendantOf(dn2, dn1, true));
    assertFalse(DN.isAncestorOf(dn1, dn2, false));
    assertTrue(DN.isAncestorOf(dn2, dn1, false));
    assertTrue(DN.isDescendantOf(dn1, dn2, false));
    assertFalse(DN.isDescendantOf(dn2, dn1, false));

    dn2 = "dc=com";
    assertFalse(DN.isAncestorOf(dn1, dn2, true));
    assertTrue(DN.isAncestorOf(dn2, dn1, true));
    assertTrue(DN.isDescendantOf(dn1, dn2, true));
    assertFalse(DN.isDescendantOf(dn2, dn1, true));
    assertFalse(DN.isAncestorOf(dn1, dn2, false));
    assertTrue(DN.isAncestorOf(dn2, dn1, false));
    assertTrue(DN.isDescendantOf(dn1, dn2, false));
    assertFalse(DN.isDescendantOf(dn2, dn1, false));

    dn2 = "ou=People,o=example.com";
    assertFalse(DN.isAncestorOf(dn1, dn2, true));
    assertFalse(DN.isAncestorOf(dn2, dn1, true));
    assertFalse(DN.isDescendantOf(dn1, dn2, true));
    assertFalse(DN.isDescendantOf(dn2, dn1, true));
    assertFalse(DN.isAncestorOf(dn1, dn2, false));
    assertFalse(DN.isAncestorOf(dn2, dn1, false));
    assertFalse(DN.isDescendantOf(dn1, dn2, false));
    assertFalse(DN.isDescendantOf(dn2, dn1, false));

    dn2 = "dc=example,dc=coma";
    assertFalse(DN.isAncestorOf(dn1, dn2, true));
    assertFalse(DN.isAncestorOf(dn2, dn1, true));
    assertFalse(DN.isDescendantOf(dn1, dn2, true));
    assertFalse(DN.isDescendantOf(dn2, dn1, true));
    assertFalse(DN.isAncestorOf(dn1, dn2, false));
    assertFalse(DN.isAncestorOf(dn2, dn1, false));
    assertFalse(DN.isDescendantOf(dn1, dn2, false));
    assertFalse(DN.isDescendantOf(dn2, dn1, false));

    assertTrue(DN.isAncestorOf(dn1, dn1, true));
    assertTrue(DN.isDescendantOf(dn1, dn1, true));
    assertFalse(DN.isAncestorOf(dn1, dn1, false));
    assertFalse(DN.isDescendantOf(dn1, dn1, false));

    dn2 = "dc=example,dc=com";
    assertTrue(DN.isAncestorOf(dn1, dn2, true));
    assertTrue(DN.isAncestorOf(dn2, dn1, true));
    assertTrue(DN.isDescendantOf(dn1, dn2, true));
    assertTrue(DN.isDescendantOf(dn2, dn1, true));
    assertFalse(DN.isAncestorOf(dn1, dn2, false));
    assertFalse(DN.isAncestorOf(dn2, dn1, false));
    assertFalse(DN.isDescendantOf(dn1, dn2, false));
    assertFalse(DN.isDescendantOf(dn2, dn1, false));

    dn2 = "ou=People,dc=example,dc=com";
    assertTrue(DN.isAncestorOf(dn1, dn2, true));
    assertFalse(DN.isAncestorOf(dn2, dn1, true));
    assertFalse(DN.isDescendantOf(dn1, dn2, true));
    assertTrue(DN.isDescendantOf(dn2, dn1, true));
    assertTrue(DN.isAncestorOf(dn1, dn2, false));
    assertFalse(DN.isAncestorOf(dn2, dn1, false));
    assertFalse(DN.isDescendantOf(dn1, dn2, false));
    assertTrue(DN.isDescendantOf(dn2, dn1, false));

    dn2 = "uid=test.user,ou=People,dc=example,dc=com";
    assertTrue(DN.isAncestorOf(dn1, dn2, true));
    assertFalse(DN.isAncestorOf(dn2, dn1, true));
    assertFalse(DN.isDescendantOf(dn1, dn2, true));
    assertTrue(DN.isDescendantOf(dn2, dn1, true));
    assertTrue(DN.isAncestorOf(dn1, dn2, false));
    assertFalse(DN.isAncestorOf(dn2, dn1, false));
    assertFalse(DN.isDescendantOf(dn1, dn2, false));
    assertTrue(DN.isDescendantOf(dn2, dn1, false));

    dn2 = "a=b,uid=test.user,ou=People,dc=example,dc=com";
    assertTrue(DN.isAncestorOf(dn1, dn2, true));
    assertFalse(DN.isAncestorOf(dn2, dn1, true));
    assertFalse(DN.isDescendantOf(dn1, dn2, true));
    assertTrue(DN.isDescendantOf(dn2, dn1, true));
    assertTrue(DN.isAncestorOf(dn1, dn2, false));
    assertFalse(DN.isAncestorOf(dn2, dn1, false));
    assertFalse(DN.isDescendantOf(dn1, dn2, false));
    assertTrue(DN.isDescendantOf(dn2, dn1, false));
  }



  /**
   * Tests the {@code matchesBaseAndScope} method with a string representation
   * of the target DN.
   *
   * @param  targetDN         The target DN for which to make the determination.
   * @param  baseDN           The base DN for which to make the determination.
   * @param  scope            The scope for which to make the determination.
   * @param  expectMatch      Indicates whether to expect a match.
   * @param  expectException  Indicates whether to expect an exception.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testBaseAndScopeData")
  public void testMatchesBaseAndScopeString(String targetDN, String baseDN,
                   SearchScope scope, boolean expectMatch,
                   boolean expectException)
         throws Exception
  {
    DN dn = new DN(targetDN);

    try
    {
      assertEquals(dn.matchesBaseAndScope(baseDN, scope), expectMatch);
    }
    catch (LDAPException le)
    {
      if (! expectException)
      {
        throw le;
      }
    }
  }



  /**
   * Tests the {@code matchesBaseAndScope} method with a parsed representation
   * of the target DN.
   *
   * @param  targetDN         The target DN for which to make the determination.
   * @param  baseDN           The base DN for which to make the determination.
   * @param  scope            The scope for which to make the determination.
   * @param  expectMatch      Indicates whether to expect a match.
   * @param  expectException  Indicates whether to expect an exception.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testBaseAndScopeData")
  public void testMatchesBaseAndScopeDN(String targetDN, String baseDN,
                   SearchScope scope, boolean expectMatch,
                   boolean expectException)
         throws Exception
  {
    DN dn = new DN(targetDN);

    try
    {
      assertEquals(dn.matchesBaseAndScope(new DN(baseDN), scope), expectMatch);
    }
    catch (LDAPException le)
    {
      if (! expectException)
      {
        throw le;
      }
    }
  }



  /**
   * Tests the {@code equals} methods with a {@code null} argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNull()
         throws Exception
  {
    DN dn = new DN("dc=example,dc=com");
    assertFalse(dn.equals((Object) null));
    assertFalse(dn.equals((String) null));
  }



  /**
   * Tests the {@code equals} method with an identity comparison.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsIdentity()
         throws Exception
  {
    DN dn = new DN("dc=example,dc=com");
    assertTrue(dn.equals(dn));
  }



  /**
   * Tests the {@code equals} method with a non-DN argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNonDN()
         throws Exception
  {
    DN dn = new DN("dc=example,dc=com");
    assertFalse(dn.equals(new Object()));
  }



  /**
   * Tests the {@code equals} method with a string argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsString()
         throws Exception
  {
    DN dn = new DN("dc=example,dc=com");
    assertTrue(dn.equals("dc=example,dc=com"));
  }



  /**
   * Tests the {@code equals} method with a number of equivalent DNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsEquivalentDNs()
         throws Exception
  {
    DN dn = new DN("dc=example,dc=com");
    assertTrue(dn.equals(new DN("dc=example,dc=com")));
    assertTrue(dn.equals(new DN(" dc = example , dc = com ")));
    assertTrue(dn.equals(new DN("  dc  =  example  ,  dc  =  com  ")));
    assertTrue(dn.equals(new DN("DC=EXAMPLE,DC=COM")));

    dn = new DN("givenName=Test+sn=User,ou=People,dc=example,dc=com");
    assertTrue(dn.equals(
         new DN("givenName=Test+sn=User,ou=People,dc=example,dc=com")));
    assertTrue(dn.equals(
         new DN("givenname=test+sn=user,ou=people,dc=example,dc=com")));
    assertTrue(dn.equals(
         new DN(" sn = user + GIVENNAME = test , ou=people , dc=example , " +
                "dc = com ")));
  }



  /**
   * Tests the {@code equals} method with a number of equivalent DNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsEquivalentStrings()
         throws Exception
  {
    assertTrue(DN.equals("dc=example,dc=com", "dc=example,dc=com"));
    assertTrue(DN.equals("dc=example,dc=com", " dc = example , dc = com "));
    assertTrue(DN.equals("dc=example,dc=com",
                         "  dc  =  example  ,  dc  =  com  "));
    assertTrue(DN.equals("dc=example,dc=com", "DC=EXAMPLE,DC=COM"));
  }



  /**
   * Tests the {@code equals} method with a number of equivalent DNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsEquivalentStringsWithSchema()
         throws Exception
  {
    assertTrue(DN.equals("dc=example,dc=com", "dc=example,dc=com", schema));
    assertTrue(DN.equals("dc=example,dc=com", " dc = example , dc = com ",
         schema));
    assertTrue(DN.equals("dc=example,dc=com",
                         "  dc  =  example  ,  dc  =  com  ", schema));
    assertTrue(DN.equals("dc=example,dc=com", "DC=EXAMPLE,DC=COM", schema));
    assertTrue(DN.equals("dc=example,dc=com",
         "0.9.2342.19200300.100.1.25=EXAMPLE,DC=COM", schema));
  }



  /**
   * Tests the {@code normalize} method.
   *
   * @param  s  The string to process.
   * @param  n  The normalized version of the string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidDNs")
  public void testNormalize(String s, String n)
         throws Exception
  {
    assertEquals(DN.normalize(s), n);
  }



  /**
   * Tests the {@code compareTo} method.
   *
   * @param  dn1Str         The string representation of first DN to be
   *                        compared.
   * @param  dn2Str         The string representation of the second DN to be
   *                        compared.
   * @param  compareResult  An integer value that has the same sign as the
   *                        expected result.  Note that it may not be exactly
   *                        equal to the {@code compareTo} result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testCompareToDNs")
  public void testCompareTo(String dn1Str, String dn2Str, int compareResult)
         throws Exception
  {
    DN dn1 = new DN(dn1Str);
    DN dn2 = new DN(dn2Str);

    if (compareResult < 0)
    {
      assertTrue(dn1.compareTo(dn2) < 0);
    }
    else if (compareResult > 0)
    {
      assertTrue(dn1.compareTo(dn2) > 0);
    }
    else
    {
      assertEquals(dn1.compareTo(dn2), 0);
    }
  }



  /**
   * Tests the {@code compare} method that takes two DNs.
   *
   * @param  dn1Str         The string representation of first DN to be
   *                        compared.
   * @param  dn2Str         The string representation of the second DN to be
   *                        compared.
   * @param  compareResult  An integer value that has the same sign as the
   *                        expected result.  Note that it may not be exactly
   *                        equal to the {@code compareTo} result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testCompareToDNs")
  public void testCompareDNs(String dn1Str, String dn2Str, int compareResult)
         throws Exception
  {
    DN dn1 = new DN(dn1Str);
    DN dn2 = new DN(dn2Str);

    if (compareResult < 0)
    {
      assertTrue(dn1.compare(dn1, dn2) < 0);
    }
    else if (compareResult > 0)
    {
      assertTrue(dn1.compare(dn1, dn2) > 0);
    }
    else
    {
      assertEquals(dn1.compare(dn1, dn2), 0);
    }
  }



  /**
   * Tests the {@code compare} method that takes two strings.
   *
   * @param  dn1Str         The string representation of first DN to be
   *                        compared.
   * @param  dn2Str         The string representation of the second DN to be
   *                        compared.
   * @param  compareResult  An integer value that has the same sign as the
   *                        expected result.  Note that it may not be exactly
   *                        equal to the {@code compareTo} result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testCompareToDNs")
  public void testCompareStrings(String dn1Str, String dn2Str,
                                 int compareResult)
         throws Exception
  {
    if (compareResult < 0)
    {
      assertTrue(DN.compare(dn1Str, dn2Str) < 0);
    }
    else if (compareResult > 0)
    {
      assertTrue(DN.compare(dn1Str, dn2Str) > 0);
    }
    else
    {
      assertEquals(DN.compare(dn1Str, dn2Str), 0);
    }
  }



  /**
   * Retrieves a set of strings that may be used to create valid DNs.
   *
   * @return  A set of strings that may be used to create valid DNs.
   */
  @DataProvider(name = "testValidDNs")
  public Object[][] getTestValidDNs()
  {
    ArrayList<String> dnStringList = new ArrayList<String>();
    ArrayList<String> normStringList = new ArrayList<String>();

    for (Object[] rdnStrings : new RDNTestCase().getValidRDNStrings())
    {
      String dnString   = (String) rdnStrings[0];
      String normString = (String) rdnStrings[1];

      dnStringList.add(dnString);
      normStringList.add(normString);

      dnStringList.add(dnString + ",dc=example,dc=com");
      normStringList.add(normString + ",dc=example,dc=com");

      dnStringList.add(dnString + ";dc=example;dc=com");
      normStringList.add(normString + ",dc=example,dc=com");

      dnStringList.add("cn=foo," + dnString);
      normStringList.add("cn=foo," + normString);

      dnStringList.add("cn=foo;" + dnString);
      normStringList.add("cn=foo," + normString);
    }

    dnStringList.add("");
    normStringList.add("");

    dnStringList.add(" ");
    normStringList.add("");

    dnStringList.add("    ");
    normStringList.add("");

    dnStringList.add("dc=com");
    normStringList.add("dc=com");

    dnStringList.add("DC=COM");
    normStringList.add("dc=com");

    dnStringList.add("o=example.com+c=US");
    normStringList.add("c=us+o=example.com");

    dnStringList.add("dc=example,dc=com");
    normStringList.add("dc=example,dc=com");

    dnStringList.add("dc=example;dc=com");
    normStringList.add("dc=example,dc=com");

    dnStringList.add(" dc = example , dc = com ");
    normStringList.add("dc=example,dc=com");

    dnStringList.add(" dc = example ; dc = com ");
    normStringList.add("dc=example,dc=com");

    dnStringList.add("  dc  =  example  ,  dc  =  com  ");
    normStringList.add("dc=example,dc=com");

    dnStringList.add("  dc  =  example  ;  dc  =  com  ");
    normStringList.add("dc=example,dc=com");

    dnStringList.add("o=Example Corp.+dc=example,dc=com");
    normStringList.add("dc=example+o=example corp.,dc=com");

    dnStringList.add("o=Example Corp.+dc=example;dc=com");
    normStringList.add("dc=example+o=example corp.,dc=com");

    dnStringList.add("dc=example+o=example corp.+description=foo+a=,dc=com");
    normStringList.add("a=+dc=example+description=foo+o=example corp.,dc=com");

    dnStringList.add("1.2.3.4=foo,5.6.7.8=bar");
    normStringList.add("1.2.3.4=foo,5.6.7.8=bar");

    Object[][] returnArray = new Object[dnStringList.size()][2];
    for (int i=0; i < returnArray.length; i++)
    {
      returnArray[i][0] = dnStringList.get(i);
      returnArray[i][1] = normStringList.get(i);
    }

    return returnArray;
  }



  /**
   * Retrieves a set of strings that cannot be used to create valid DNs.
   *
   * @return  A set of strings that cannot be used to create valid DNs.
   */
  @DataProvider(name = "testInvalidDNs")
  public Object[][] getTestInvalidDNs()
  {
    ArrayList<String> dnStringList = new ArrayList<String>();

    for (Object[] rdnStrings : new RDNTestCase().getInvalidRDNStrings())
    {
      String dnString = (String) rdnStrings[0];

      if (dnString.trim().length() == 0)
      {
        // This isn't a valid RDN but it is a valid DN, so we'll not add it
        // directly to the list.
      }
      else
      {
        dnStringList.add(dnString);
      }

      dnStringList.add("," + dnString);
      dnStringList.add(dnString + ",");
      dnStringList.add("cn=foo," + dnString);
      dnStringList.add(dnString + ",dc=example,dc=com");
    }

    dnStringList.add(",");
    dnStringList.add(";");
    dnStringList.add("dc=exaple,dc=com,");
    dnStringList.add("dc=exaple,,dc=com,");
    dnStringList.add("dc=exaple;;dc=com,");
    dnStringList.add("dc=exaple,;dc=com,");
    dnStringList.add("dc=example,dc=com, ");
    dnStringList.add(",dc=example,dc=com");
    dnStringList.add("dc=example,dc=com+");
    dnStringList.add("dc=example,dc=com+ ");
    dnStringList.add("dc=example+o=example corp.+,dc=com");

    Object[][] returnArray = new Object[dnStringList.size()][1];
    for (int i=0; i < returnArray.length; i++)
    {
      returnArray[i][0] = dnStringList.get(i);
    }

    return returnArray;
  }



  /**
   * Retrieves a set of strings that can be used to create valid DNs only if
   * strict name checking is enforced.
   *
   * @return  A set of strings that cannot be used to create valid DNs.
   */
  @DataProvider(name = "testInvalidDNAttributes")
  public Object[][] getTestInvalidDNAttributes()
  {
    return new Object[][]
    {
      new Object[] { "attribute_with_underscore=foo" },
      new Object[] { "_starts_with_underscore=foo" },
      new Object[] { "-starts-with-hyphen=foo" },
      new Object[] { "0-starts-with-number=foo" },
      new Object[] { "1.2..3.4=foo" },
      new Object[] { "valid=foo+_invalid=bar" },
      new Object[] { "valid=foo,_invalid=bar" },
      new Object[] { "<GUID=f3ddad46-4332-4871-ae1a-92aa29b0887f>" }
    };
  }



  /**
   * Retrieves a set of data that may be used to test the {@code compareTo}
   * method.
   *
   * @return  A set of data that may be used to test the {@code compareTo}
   *          method.
   */
  @DataProvider(name = "testCompareToDNs")
  public Object[][] getTestCompareToDNs()
  {
    return new Object[][]
    {
      new Object[]
      {
        "",
        "",
        0
      },

      new Object[]
      {
        "dc=example,dc=com",
        "",
        1
      },

      new Object[]
      {
        "",
        "dc=example,dc=com",
        -1
      },

      new Object[]
      {
        "dc=example,dc=com",
        "dc=example,dc=com",
        0
      },

      new Object[]
      {
        "o=example.com",
        "dc=example,dc=com",
        1
      },

      new Object[]
      {
        "dc=example,dc=com",
        "o=example.com",
        -1
      },

      new Object[]
      {
        "uid=test.user,ou=People,dc=example,dc=com",
        "uid=test.user,ou=People,dc=example,dc=com",
        0
      },

      new Object[]
      {
        "uid=test.user,ou=People,dc=example,dc=com",
        "uid=test2.user,ou=People,dc=example,dc=com",
        -1
      },

      new Object[]
      {
        "uid=test2.user,ou=People,dc=example,dc=com",
        "uid=test.user,ou=People,dc=example,dc=com",
        1
      },

      new Object[]
      {
        "uid=test.user,ou=People,dc=example,dc=com",
        "cn=Sub Entry,uid=test.user,ou=People,dc=example,dc=com",
        -1
      },

      new Object[]
      {
        "cn=Sub Entry,uid=test.user,ou=People,dc=example,dc=com",
        "uid=test.user,ou=People,dc=example,dc=com",
        1
      },
    };
  }



  /**
   * Provides a set of test data for use with the {@code matchesBaseAndScope}
   * methods.
   *
   * @return  A set of test data for use with the {@code matchesBaseAndScope}
   *          methods.
   */
  @DataProvider(name = "testBaseAndScopeData")
  public Object[][] getTestBaseAndScopeData()
  {
    return new Object[][]
    {
      new Object[]
      {
        "dc=example,dc=com",              // Target DN
        "dc=example,dc=com",              // Base DN
        SearchScope.BASE,                 // Scope
        true,                             // Expect a match?
        false                             // Expect an exception?
      },

      new Object[]
      {
        "dc=example,dc=com",              // Target DN
        "dc=example,dc=com",              // Base DN
        SearchScope.ONE,                  // Scope
        false,                            // Expect a match?
        false                             // Expect an exception?
      },

      new Object[]
      {
        "dc=example,dc=com",              // Target DN
        "dc=example,dc=com",              // Base DN
        SearchScope.SUB,                  // Scope
        true,                             // Expect a match?
        false                             // Expect an exception?
      },

      new Object[]
      {
        "dc=example,dc=com",              // Target DN
        "dc=example,dc=com",              // Base DN
        SearchScope.SUBORDINATE_SUBTREE,  // Scope
        false,                            // Expect a match?
        false                             // Expect an exception?
      },

      new Object[]
      {
        "ou=People,dc=example,dc=com",    // Target DN
        "dc=example,dc=com",              // Base DN
        SearchScope.BASE,                 // Scope
        false,                            // Expect a match?
        false                             // Expect an exception?
      },

      new Object[]
      {
        "ou=People,dc=example,dc=com",    // Target DN
        "dc=example,dc=com",              // Base DN
        SearchScope.ONE,                  // Scope
        true,                             // Expect a match?
        false                             // Expect an exception?
      },

      new Object[]
      {
        "ou=People,dc=example,dc=com",    // Target DN
        "dc=example,dc=com",              // Base DN
        SearchScope.SUB,                  // Scope
        true,                             // Expect a match?
        false                             // Expect an exception?
      },

      new Object[]
      {
        "ou=People,dc=example,dc=com",    // Target DN
        "dc=example,dc=com",              // Base DN
        SearchScope.SUBORDINATE_SUBTREE,  // Scope
        true,                             // Expect a match?
        false                             // Expect an exception?
      },

      new Object[]
      {
        "dc=example,dc=com",              // Target DN
        "ou=People,dc=example,dc=com",    // Base DN
        SearchScope.BASE,                 // Scope
        false,                            // Expect a match?
        false                             // Expect an exception?
      },

      new Object[]
      {
        "dc=example,dc=com",              // Target DN
        "ou=People,dc=example,dc=com",    // Base DN
        SearchScope.ONE,                  // Scope
        false,                            // Expect a match?
        false                             // Expect an exception?
      },

      new Object[]
      {
        "dc=example,dc=com",              // Target DN
        "ou=People,dc=example,dc=com",    // Base DN
        SearchScope.SUB,                  // Scope
        false,                            // Expect a match?
        false                             // Expect an exception?
      },

      new Object[]
      {
        "dc=example,dc=com",              // Target DN
        "ou=People,dc=example,dc=com",    // Base DN
        SearchScope.SUBORDINATE_SUBTREE,  // Scope
        false,                            // Expect a match?
        false                             // Expect an exception?
      },

      new Object[]
      {
        "dc=example,dc=com",              // Target DN
        "invalid",                        // Base DN
        SearchScope.BASE,                 // Scope
        false,                            // Expect a match?
        true                              // Expect an exception?
      },

      new Object[]
      {
        "dc=example,dc=com",              // Target DN
        "dc=example,dc=com",              // Base DN
        SearchScope.valueOf(5),           // Scope
        false,                            // Expect a match?
        true                              // Expect an exception?
      }
    };
  }



  /**
   * Tests the behavior when trying to normalize a DN when a schema is
   * available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNormalizeWithSchema()
         throws Exception
  {
    final Entry testSchemaEntry =
         Schema.getDefaultStandardSchema().getSchemaEntry().duplicate();
    testSchemaEntry.addAttribute("attributeTypes",
         "( 1.2.3.1 " +
              "NAME 'case-exact-attr' " +
              "EQUALITY caseExactMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )");

    final Schema testSchema = new Schema(testSchemaEntry);


    DN dn = new DN("case-exact-attr=This Is A Test,DC=Example,DC=Com");
    assertEquals(dn.toString(),
         "case-exact-attr=This Is A Test,DC=Example,DC=Com");
    assertEquals(dn.toNormalizedString(),
         "case-exact-attr=this is a test,dc=example,dc=com");

    dn = new DN("case-exact-attr=This Is A Test,DC=Example,DC=Com", testSchema);
    assertEquals(dn.toString(),
         "case-exact-attr=This Is A Test,DC=Example,DC=Com");
    assertEquals(dn.toNormalizedString(),
         "case-exact-attr=This Is A Test,dc=example,dc=com");
  }
}
