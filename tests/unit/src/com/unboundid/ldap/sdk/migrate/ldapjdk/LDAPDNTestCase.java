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

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the {@code LDAPDN} class.
 */
public class LDAPDNTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the normalize method with a valid DN string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNormalizeValid()
         throws Exception
  {
    assertEquals(LDAPDN.normalize("dc   =   ExAmPlE ,   DC = COM"),
                 "dc=example,dc=com");
  }



  /**
   * Tests the normalize method with a valid DN string that is already
   * normalized.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNormalizeValidAlreadyNormalized()
         throws Exception
  {
    assertEquals(LDAPDN.normalize("dc=example,dc=com"),
                 "dc=example,dc=com");
  }



  /**
   * Tests the normalize method with a string that cannot be parsed as a valid
   * DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNormalizeInvalid()
         throws Exception
  {
    assertEquals(LDAPDN.normalize("   InVaLiD   "),
                 "invalid");
  }



  /**
   * Tests the {@code explodeDN} method for the null DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExplodeDNNull()
         throws Exception
  {
    String[] s = LDAPDN.explodeDN("", false);

    assertNotNull(s);
    assertEquals(s.length, 0);
  }



  /**
   * Tests the {@code explodeDN} method for a valid DN with a single component
   * and not excluding types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExplodeDNValidSingleComponentNoExclude()
         throws Exception
  {
    String[] s = LDAPDN.explodeDN("dc=com", false);

    assertNotNull(s);
    assertEquals(s.length, 1);
    assertEquals(s[0], "dc=com");
  }



  /**
   * Tests the {@code explodeDN} method for a valid DN with a single component
   * and excluding types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExplodeDNValidSingleComponentWithExclude()
         throws Exception
  {
    String[] s = LDAPDN.explodeDN("dc=com", true);

    assertNotNull(s);
    assertEquals(s.length, 1);
    assertEquals(s[0], "com");
  }



  /**
   * Tests the {@code explodeDN} method for a valid DN with multiple components
   * and not excluding types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExplodeDNValidMultipleComponentNoExclude()
         throws Exception
  {
    String[] s = LDAPDN.explodeDN("dc=example, dc=com", false);

    assertNotNull(s);
    assertEquals(s.length, 2);
    assertEquals(s[0], "dc=example");
    assertEquals(s[1], "dc=com");
  }



  /**
   * Tests the {@code explodeDN} method for a valid DN with multiple components
   * and excluding types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExplodeDNValidMultipleComponentWithExclude()
         throws Exception
  {
    String[] s = LDAPDN.explodeDN("dc=example, dc=com", true);

    assertNotNull(s);
    assertEquals(s.length, 2);
    assertEquals(s[0], "example");
    assertEquals(s[1], "com");
  }



  /**
   * Tests the {@code explodeDN} method for a valid DN with multiple components
   * including a multivalued RDN and not excluding types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExplodeDNValidMultipleComponentWithMultivaluedNoExclude()
         throws Exception
  {
    String[] s =
         LDAPDN.explodeDN("givenName=Test+sn=User , dc=example, dc=com", false);

    assertNotNull(s);
    assertEquals(s.length, 3);
    assertEquals(s[0], "givenName=Test+sn=User");
    assertEquals(s[1], "dc=example");
    assertEquals(s[2], "dc=com");
  }



  /**
   * Tests the {@code explodeDN} method for a valid DN with multiple components
   * including a multivalued RDN and excluding types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExplodeDNValidMultipleComponentWithMultivaluedWithExclude()
         throws Exception
  {
    String[] s =
         LDAPDN.explodeDN("givenName=Test+sn=User , dc=example, dc=com", true);

    assertNotNull(s);
    assertEquals(s.length, 3);
    assertEquals(s[0], "Test+User");
    assertEquals(s[1], "example");
    assertEquals(s[2], "com");
  }



  /**
   * Tests the {@code explodeDN} method for an invalid DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExplodeDNInvalid()
         throws Exception
  {
    String[] s = LDAPDN.explodeDN("invalid", false);

    assertNotNull(s);
    assertEquals(s.length, 1);
    assertEquals(s[0], "invalid");
  }



  /**
   * Tests the {@code explodeRDN} method for a valid RDN with a single value and
   * not excluding types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExplodeRDNValidSingleValueNoExclude()
         throws Exception
  {
    String[] s = LDAPDN.explodeRDN("dc=com", false);

    assertNotNull(s);
    assertEquals(s.length, 1);
    assertEquals(s[0], "dc=com");
  }



  /**
   * Tests the {@code explodeRDN} method for a valid RDN with a single value and
   * excluding types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExplodeRDNValidSingleValueWithExclude()
         throws Exception
  {
    String[] s = LDAPDN.explodeRDN("dc=com", true);

    assertNotNull(s);
    assertEquals(s.length, 1);
    assertEquals(s[0], "com");
  }



  /**
   * Tests the {@code explodeRDN} method for a valid RDN with multiple values
   * and not excluding types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExplodeRDNValidMultipleValuesNoExclude()
         throws Exception
  {
    String[] s = LDAPDN.explodeRDN("givenName=Test+sn=User", false);

    assertNotNull(s);
    assertEquals(s.length, 2);
    assertEquals(s[0], "givenName=Test");
    assertEquals(s[1], "sn=User");
  }



  /**
   * Tests the {@code explodeRDN} method for a valid RDN with multiple values
   * and excluding types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExplodeRDNValidMultipleValuesWithExclude()
         throws Exception
  {
    String[] s = LDAPDN.explodeRDN("givenName=Test+sn=User", true);

    assertNotNull(s);
    assertEquals(s.length, 2);
    assertEquals(s[0], "Test");
    assertEquals(s[1], "User");
  }



  /**
   * Tests the {@code explodeRDN} method for an invalid RDN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExplodeRDNInvalid()
         throws Exception
  {
    String[] s = LDAPDN.explodeRDN("invalid", false);

    assertNotNull(s);
    assertEquals(s.length, 1);
    assertEquals(s[0], "invalid");
  }



  /**
   * Tests the {@code equals} method with two identical valid DN strings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsValidIdentical()
         throws Exception
  {
    assertTrue(LDAPDN.equals("dc=example,dc=com", "dc=example,dc=com"));
  }



  /**
   * Tests the {@code equals} method with two non-identical but equivalent
   * valid DN strings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsValidEquivalentNonIdentical()
         throws Exception
  {
    assertTrue(LDAPDN.equals("DC = ExAmPlE , dc = COM", "dc=example,dc=com"));
  }



  /**
   * Tests the {@code equals} method with two non-equivalent valid DN strings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsValidNonEquivalent()
         throws Exception
  {
    assertFalse(LDAPDN.equals("dc=example", "dc=example,dc=com"));
  }



  /**
   * Tests the {@code equals} method with invalid DN strings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsInvalid()
         throws Exception
  {
    assertFalse(LDAPDN.equals("invalid", "invalid"));
  }
}
