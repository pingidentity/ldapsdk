/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.util.HashSet;
import java.util.Set;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the assured replication local
 * level enum.
 */
public final class AssuredReplicationLocalLevelTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides general test coverage for the enum.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGeneral()
         throws Exception
  {
    // Test with valid values.
    for (final AssuredReplicationLocalLevel l :
         AssuredReplicationLocalLevel.values())
    {
      assertNotNull(l.name());
      assertNotNull(l.intValue());
      assertEquals(AssuredReplicationLocalLevel.valueOf(l.intValue()),
           l);
      assertEquals(AssuredReplicationLocalLevel.valueOf(l.name()),
           l);
    }

    // Test the integer valueOf method with an undefined value.
    assertNull(AssuredReplicationLocalLevel.valueOf(1234));

    // Test the string valueOf method with an undefined value.
    try
    {
      AssuredReplicationLocalLevel.valueOf("undefined");
      fail("Expected an exception when trying to invoke valueOf with an " +
           "undefined value");
    }
    catch (final IllegalArgumentException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the methods that compare strictness of local level values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStrictnessComparison()
         throws Exception
  {
    // Ensure that the test covers all values.  If any new values are added,
    // then this test will fail and everything below will need to be updated
    // accordingly.
    assertEquals(AssuredReplicationLocalLevel.values().length, 3);

    // Ensure that the "NONE" value is the least strict.
    for (final AssuredReplicationLocalLevel l :
         AssuredReplicationLocalLevel.values())
    {
      assertEquals(
           AssuredReplicationLocalLevel.getLessStrict(
                AssuredReplicationLocalLevel.NONE, l),
           AssuredReplicationLocalLevel.NONE);
    }

    // Ensure that the "PROCESSED_ALL_SERVERS" value is the most strict.
    for (final AssuredReplicationLocalLevel l :
         AssuredReplicationLocalLevel.values())
    {
      assertEquals(
           AssuredReplicationLocalLevel.getMoreStrict(
                AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS, l),
           AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS);
    }

    // Make individual comparisons.
    assertEquals(
         AssuredReplicationLocalLevel.getLessStrict(
              AssuredReplicationLocalLevel.NONE,
              AssuredReplicationLocalLevel.NONE),
         AssuredReplicationLocalLevel.NONE);
    assertEquals(
         AssuredReplicationLocalLevel.getLessStrict(
              AssuredReplicationLocalLevel.NONE,
              AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER),
         AssuredReplicationLocalLevel.NONE);
    assertEquals(
         AssuredReplicationLocalLevel.getLessStrict(
              AssuredReplicationLocalLevel.NONE,
              AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS),
         AssuredReplicationLocalLevel.NONE);

    assertEquals(
         AssuredReplicationLocalLevel.getLessStrict(
              AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER,
              AssuredReplicationLocalLevel.NONE),
         AssuredReplicationLocalLevel.NONE);
    assertEquals(
         AssuredReplicationLocalLevel.getLessStrict(
              AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER,
              AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER),
         AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER);
    assertEquals(
         AssuredReplicationLocalLevel.getLessStrict(
              AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER,
              AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS),
         AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER);

    assertEquals(
         AssuredReplicationLocalLevel.getLessStrict(
              AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS,
              AssuredReplicationLocalLevel.NONE),
         AssuredReplicationLocalLevel.NONE);
    assertEquals(
         AssuredReplicationLocalLevel.getLessStrict(
              AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS,
              AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER),
         AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER);
    assertEquals(
         AssuredReplicationLocalLevel.getLessStrict(
              AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS,
              AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS),
         AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS);

    assertEquals(
         AssuredReplicationLocalLevel.getMoreStrict(
              AssuredReplicationLocalLevel.NONE,
              AssuredReplicationLocalLevel.NONE),
         AssuredReplicationLocalLevel.NONE);
    assertEquals(
         AssuredReplicationLocalLevel.getMoreStrict(
              AssuredReplicationLocalLevel.NONE,
              AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER),
         AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER);
    assertEquals(
         AssuredReplicationLocalLevel.getMoreStrict(
              AssuredReplicationLocalLevel.NONE,
              AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS),
         AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS);

    assertEquals(
         AssuredReplicationLocalLevel.getMoreStrict(
              AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER,
              AssuredReplicationLocalLevel.NONE),
         AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER);
    assertEquals(
         AssuredReplicationLocalLevel.getMoreStrict(
              AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER,
              AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER),
         AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER);
    assertEquals(
         AssuredReplicationLocalLevel.getMoreStrict(
              AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER,
              AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS),
         AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS);

    assertEquals(
         AssuredReplicationLocalLevel.getMoreStrict(
              AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS,
              AssuredReplicationLocalLevel.NONE),
         AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS);
    assertEquals(
         AssuredReplicationLocalLevel.getMoreStrict(
              AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS,
              AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER),
         AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS);
    assertEquals(
         AssuredReplicationLocalLevel.getMoreStrict(
              AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS,
              AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS),
         AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS);
  }



  /**
   * Tests the {@code forName} method with automated tests based on the actual
   * name of the enum values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testForNameAutomated()
         throws Exception
  {
    for (final AssuredReplicationLocalLevel value :
         AssuredReplicationLocalLevel.values())
    {
      for (final String name : getNames(value.name()))
      {
        assertNotNull(AssuredReplicationLocalLevel.forName(name));
        assertEquals(AssuredReplicationLocalLevel.forName(name), value);
      }
    }

    assertNull(AssuredReplicationLocalLevel.forName("some undefined name"));
  }



  /**
   * Retrieves a set of names for testing the {@code forName} method based on
   * the provided set of names.
   *
   * @param  baseNames  The base set of names to use to generate the full set of
   *                    names.  It must not be {@code null} or empty.
   *
   * @return  The full set of names to use for testing.
   */
  private static Set<String> getNames(final String... baseNames)
  {
    final HashSet<String> nameSet = new HashSet<>(10);
    for (final String name : baseNames)
    {
      nameSet.add(name);
      nameSet.add(name.toLowerCase());
      nameSet.add(name.toUpperCase());

      final String nameWithDashesInsteadOfUnderscores = name.replace('_', '-');
      nameSet.add(nameWithDashesInsteadOfUnderscores);
      nameSet.add(nameWithDashesInsteadOfUnderscores.toLowerCase());
      nameSet.add(nameWithDashesInsteadOfUnderscores.toUpperCase());

      final String nameWithUnderscoresInsteadOfDashes = name.replace('-', '_');
      nameSet.add(nameWithUnderscoresInsteadOfDashes);
      nameSet.add(nameWithUnderscoresInsteadOfDashes.toLowerCase());
      nameSet.add(nameWithUnderscoresInsteadOfDashes.toUpperCase());

      final StringBuilder nameWithoutUnderscoresOrDashes = new StringBuilder();
      for (final char c : name.toCharArray())
      {
        if ((c != '-') && (c != '_'))
        {
          nameWithoutUnderscoresOrDashes.append(c);
        }
      }
      nameSet.add(nameWithoutUnderscoresOrDashes.toString());
      nameSet.add(nameWithoutUnderscoresOrDashes.toString().toLowerCase());
      nameSet.add(nameWithoutUnderscoresOrDashes.toString().toUpperCase());
    }

    return nameSet;
  }
}
