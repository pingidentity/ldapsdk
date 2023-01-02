/*
 * Copyright 2021-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021-2023 Ping Identity Corporation
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
 * Copyright (C) 2021-2023 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tools;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.schema.Schema;



/**
 * This class provides a set of tests for the {@code LDAPDiffCompactDN} class.
 */
public final class LDAPDiffCompactDNTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the compact DN class when the provided DN matches the
   * base DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchesBaseDN()
         throws Exception
  {
    final DN baseDN = new DN("dc=example,dc=com");
    final Schema schema = Schema.getDefaultStandardSchema();

    final LDAPDiffCompactDN compactDN =
         new LDAPDiffCompactDN(baseDN, baseDN);

    assertNotNull(compactDN.toDN(baseDN, schema));
    assertEquals(compactDN.toDN(baseDN, schema), baseDN);

    assertEquals(compactDN.compareTo(compactDN), 0);

    compactDN.hashCode();

    assertTrue(compactDN.equals(compactDN));
    assertTrue(compactDN.equals(new LDAPDiffCompactDN(baseDN, baseDN)));
    assertFalse(compactDN.equals(new LDAPDiffCompactDN(
         new DN("ou=People,dc=example,dc=com"), baseDN)));
    assertFalse(compactDN.equals(null));
    assertFalse(compactDN.equals("foo"));

    assertNotNull(compactDN.toString());
    assertEquals(compactDN.toString(), "");
  }



  /**
   * Tests the behavior of the compact DN class when the provided DN is one
   * level below the base DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOneLevelBelowBaseDN()
         throws Exception
  {
    final DN baseDN = new DN("dc=example,dc=com");
    final DN testDN = new DN("ou=People,dc=example,dc=com");
    final Schema schema = Schema.getDefaultStandardSchema();

    final LDAPDiffCompactDN compactDN =
         new LDAPDiffCompactDN(testDN, baseDN);

    assertNotNull(compactDN.toDN(baseDN, schema));
    assertEquals(compactDN.toDN(baseDN, schema), testDN);

    assertEquals(compactDN.compareTo(compactDN), 0);
    assertTrue(compactDN.compareTo(new LDAPDiffCompactDN(baseDN, baseDN)) > 0);
    assertTrue(new LDAPDiffCompactDN(baseDN, baseDN).compareTo(compactDN) < 0);
    assertTrue(compactDN.compareTo(
         new LDAPDiffCompactDN(new DN("ou=Users,dc=example,dc=com"), baseDN)) <
         0);
    assertTrue(
         new LDAPDiffCompactDN(new DN("ou=Users,dc=example,dc=com"), baseDN).
              compareTo(compactDN) > 0);

    compactDN.hashCode();

    assertTrue(compactDN.equals(compactDN));
    assertTrue(compactDN.equals(new LDAPDiffCompactDN(
         new DN("ou=People,dc=example,dc=com"), baseDN)));
    assertFalse(compactDN.equals(new LDAPDiffCompactDN(
         new DN("ou=Users,dc=example,dc=com"), baseDN)));
    assertFalse(compactDN.equals(new LDAPDiffCompactDN(baseDN, baseDN)));
    assertFalse(compactDN.equals(null));
    assertFalse(compactDN.equals("foo"));

    assertNotNull(compactDN.toString());
    assertEquals(compactDN.toString(), "ou=people");
  }



  /**
   * Tests the behavior of the compact DN class when the provided DN is multiple
   * levels below the base DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleLevelsBelowBaseDN()
         throws Exception
  {
    final DN baseDN = new DN("dc=example,dc=com");
    final DN testDN = new DN("uid=test.user,ou=People,dc=example,dc=com");
    final Schema schema = Schema.getDefaultStandardSchema();

    final LDAPDiffCompactDN compactDN =
         new LDAPDiffCompactDN(testDN, baseDN);

    assertNotNull(compactDN.toDN(baseDN, schema));
    assertEquals(compactDN.toDN(baseDN, schema), testDN);

    assertEquals(compactDN.compareTo(compactDN), 0);
    assertTrue(compactDN.compareTo(new LDAPDiffCompactDN(baseDN, baseDN)) > 0);
    assertTrue(new LDAPDiffCompactDN(baseDN, baseDN).compareTo(compactDN) < 0);
    assertTrue(compactDN.compareTo(
         new LDAPDiffCompactDN(
              new DN("uid=test.user,ou=Users,dc=example,dc=com"), baseDN)) < 0);
    assertTrue(
         new LDAPDiffCompactDN(
              new DN("uid=test.user,ou=Users,dc=example,dc=com"), baseDN).
                   compareTo(compactDN) > 0);

    compactDN.hashCode();

    assertTrue(compactDN.equals(compactDN));
    assertTrue(compactDN.equals(new LDAPDiffCompactDN(
         new DN("uid=test.user,ou=People,dc=example,dc=com"), baseDN)));
    assertFalse(compactDN.equals(new LDAPDiffCompactDN(
         new DN("uid=test.user,ou=Users,dc=example,dc=com"), baseDN)));
    assertFalse(compactDN.equals(new LDAPDiffCompactDN(
         new DN("cn=Test User,ou=People,dc=example,dc=com"), baseDN)));
    assertFalse(compactDN.equals(new LDAPDiffCompactDN(baseDN, baseDN)));
    assertFalse(compactDN.equals(null));
    assertFalse(compactDN.equals("foo"));

    assertNotNull(compactDN.toString());
    assertEquals(compactDN.toString(), "ou=people,uid=test.user");
  }
}
