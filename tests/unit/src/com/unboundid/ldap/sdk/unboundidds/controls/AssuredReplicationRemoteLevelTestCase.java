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
 * This class provides a set of test cases for the assured replication remote
 * level enum.
 */
public final class AssuredReplicationRemoteLevelTestCase
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
    for (final AssuredReplicationRemoteLevel l :
         AssuredReplicationRemoteLevel.values())
    {
      assertNotNull(l.name());
      assertNotNull(l.intValue());
      assertEquals(AssuredReplicationRemoteLevel.valueOf(l.intValue()),
           l);
      assertEquals(AssuredReplicationRemoteLevel.valueOf(l.name()),
           l);
    }

    // Test the integer valueOf method with an undefined value.
    assertNull(AssuredReplicationRemoteLevel.valueOf(1234));

    // Test the string valueOf method with an undefined value.
    try
    {
      AssuredReplicationRemoteLevel.valueOf("undefined");
      fail("Expected an exception when trying to invoke valueOf with an " +
           "undefined value");
    }
    catch (final IllegalArgumentException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the methods that compare strictness of remote level values.
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
    assertEquals(AssuredReplicationRemoteLevel.values().length, 4);

    // Ensure that the "NONE" value is the least strict.
    for (final AssuredReplicationRemoteLevel l :
         AssuredReplicationRemoteLevel.values())
    {
      assertEquals(
           AssuredReplicationRemoteLevel.getLessStrict(
                AssuredReplicationRemoteLevel.NONE, l),
           AssuredReplicationRemoteLevel.NONE);
    }

    // Ensure that the "PROCESSED_ALL_SERVERS" value is the most strict.
    for (final AssuredReplicationRemoteLevel l :
         AssuredReplicationRemoteLevel.values())
    {
      assertEquals(
           AssuredReplicationRemoteLevel.getMoreStrict(
                AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS, l),
           AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS);
    }

    // Make individual comparisons.
    assertEquals(
         AssuredReplicationRemoteLevel.getLessStrict(
              AssuredReplicationRemoteLevel.NONE,
              AssuredReplicationRemoteLevel.NONE),
         AssuredReplicationRemoteLevel.NONE);
    assertEquals(
         AssuredReplicationRemoteLevel.getLessStrict(
              AssuredReplicationRemoteLevel.NONE,
              AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION),
         AssuredReplicationRemoteLevel.NONE);
    assertEquals(
         AssuredReplicationRemoteLevel.getLessStrict(
              AssuredReplicationRemoteLevel.NONE,
              AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS),
         AssuredReplicationRemoteLevel.NONE);
    assertEquals(
         AssuredReplicationRemoteLevel.getLessStrict(
              AssuredReplicationRemoteLevel.NONE,
              AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS),
         AssuredReplicationRemoteLevel.NONE);

    assertEquals(
         AssuredReplicationRemoteLevel.getLessStrict(
              AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION,
              AssuredReplicationRemoteLevel.NONE),
         AssuredReplicationRemoteLevel.NONE);
    assertEquals(
         AssuredReplicationRemoteLevel.getLessStrict(
              AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION,
              AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION),
         AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION);
    assertEquals(
         AssuredReplicationRemoteLevel.getLessStrict(
              AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION,
              AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS),
         AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION);
    assertEquals(
         AssuredReplicationRemoteLevel.getLessStrict(
              AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION,
              AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS),
         AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION);

    assertEquals(
         AssuredReplicationRemoteLevel.getLessStrict(
              AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS,
              AssuredReplicationRemoteLevel.NONE),
         AssuredReplicationRemoteLevel.NONE);
    assertEquals(
         AssuredReplicationRemoteLevel.getLessStrict(
              AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS,
              AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION),
         AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION);
    assertEquals(
         AssuredReplicationRemoteLevel.getLessStrict(
              AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS,
              AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS),
         AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS);
    assertEquals(
         AssuredReplicationRemoteLevel.getLessStrict(
              AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS,
              AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS),
         AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS);

    assertEquals(
         AssuredReplicationRemoteLevel.getLessStrict(
              AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS,
              AssuredReplicationRemoteLevel.NONE),
         AssuredReplicationRemoteLevel.NONE);
    assertEquals(
         AssuredReplicationRemoteLevel.getLessStrict(
              AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS,
              AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION),
         AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION);
    assertEquals(
         AssuredReplicationRemoteLevel.getLessStrict(
              AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS,
              AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS),
         AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS);
    assertEquals(
         AssuredReplicationRemoteLevel.getLessStrict(
              AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS,
              AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS),
         AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS);

    assertEquals(
         AssuredReplicationRemoteLevel.getMoreStrict(
              AssuredReplicationRemoteLevel.NONE,
              AssuredReplicationRemoteLevel.NONE),
         AssuredReplicationRemoteLevel.NONE);
    assertEquals(
         AssuredReplicationRemoteLevel.getMoreStrict(
              AssuredReplicationRemoteLevel.NONE,
              AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION),
         AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION);
    assertEquals(
         AssuredReplicationRemoteLevel.getMoreStrict(
              AssuredReplicationRemoteLevel.NONE,
              AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS),
         AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS);
    assertEquals(
         AssuredReplicationRemoteLevel.getMoreStrict(
              AssuredReplicationRemoteLevel.NONE,
              AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS),
         AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS);

    assertEquals(
         AssuredReplicationRemoteLevel.getMoreStrict(
              AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION,
              AssuredReplicationRemoteLevel.NONE),
         AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION);
    assertEquals(
         AssuredReplicationRemoteLevel.getMoreStrict(
              AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION,
              AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION),
         AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION);
    assertEquals(
         AssuredReplicationRemoteLevel.getMoreStrict(
              AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION,
              AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS),
         AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS);
    assertEquals(
         AssuredReplicationRemoteLevel.getMoreStrict(
              AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION,
              AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS),
         AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS);

    assertEquals(
         AssuredReplicationRemoteLevel.getMoreStrict(
              AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS,
              AssuredReplicationRemoteLevel.NONE),
         AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS);
    assertEquals(
         AssuredReplicationRemoteLevel.getMoreStrict(
              AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS,
              AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION),
         AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS);
    assertEquals(
         AssuredReplicationRemoteLevel.getMoreStrict(
              AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS,
              AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS),
         AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS);
    assertEquals(
         AssuredReplicationRemoteLevel.getMoreStrict(
              AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS,
              AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS),
         AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS);

    assertEquals(
         AssuredReplicationRemoteLevel.getMoreStrict(
              AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS,
              AssuredReplicationRemoteLevel.NONE),
         AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS);
    assertEquals(
         AssuredReplicationRemoteLevel.getMoreStrict(
              AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS,
              AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION),
         AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS);
    assertEquals(
         AssuredReplicationRemoteLevel.getMoreStrict(
              AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS,
              AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS),
         AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS);
    assertEquals(
         AssuredReplicationRemoteLevel.getMoreStrict(
              AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS,
              AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS),
         AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS);
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
    for (final AssuredReplicationRemoteLevel value :
         AssuredReplicationRemoteLevel.values())
    {
      for (final String name : getNames(value.name()))
      {
        assertNotNull(AssuredReplicationRemoteLevel.forName(name));
        assertEquals(AssuredReplicationRemoteLevel.forName(name), value);
      }
    }

    assertNull(AssuredReplicationRemoteLevel.forName("some undefined name"));
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
