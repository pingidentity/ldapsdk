/*
 * Copyright 2013-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2013-2017 UnboundID Corp.
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
}
