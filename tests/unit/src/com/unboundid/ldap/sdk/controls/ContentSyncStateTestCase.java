/*
 * Copyright 2010-2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2010-2017 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.controls;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the
 * {@code ContentSyncState} class.
 */
public final class ContentSyncStateTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the PRESENT state.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPresent()
         throws Exception
  {
    final ContentSyncState s = ContentSyncState.PRESENT;

    assertNotNull(s.name());
    assertNotNull(s.toString());

    assertEquals(s.intValue(), 0);

    assertNotNull(ContentSyncState.valueOf(s.intValue()));
    assertEquals(ContentSyncState.valueOf(s.intValue()), s);

    assertNotNull(ContentSyncState.valueOf(s.name()));
    assertEquals(ContentSyncState.valueOf(s.name()), s);
  }



  /**
   * Provides test coverage for the ADD state.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAdd()
         throws Exception
  {
    final ContentSyncState s = ContentSyncState.ADD;

    assertNotNull(s.name());
    assertNotNull(s.toString());

    assertEquals(s.intValue(), 1);

    assertNotNull(ContentSyncState.valueOf(s.intValue()));
    assertEquals(ContentSyncState.valueOf(s.intValue()), s);

    assertNotNull(ContentSyncState.valueOf(s.name()));
    assertEquals(ContentSyncState.valueOf(s.name()), s);
  }



  /**
   * Provides test coverage for the MODIFY state.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModify()
         throws Exception
  {
    final ContentSyncState s = ContentSyncState.MODIFY;

    assertNotNull(s.name());
    assertNotNull(s.toString());

    assertEquals(s.intValue(), 2);

    assertNotNull(ContentSyncState.valueOf(s.intValue()));
    assertEquals(ContentSyncState.valueOf(s.intValue()), s);

    assertNotNull(ContentSyncState.valueOf(s.name()));
    assertEquals(ContentSyncState.valueOf(s.name()), s);
  }



  /**
   * Provides test coverage for the DELETE state.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDelete()
         throws Exception
  {
    final ContentSyncState s = ContentSyncState.DELETE;

    assertNotNull(s.name());
    assertNotNull(s.toString());

    assertEquals(s.intValue(), 3);

    assertNotNull(ContentSyncState.valueOf(s.intValue()));
    assertEquals(ContentSyncState.valueOf(s.intValue()), s);

    assertNotNull(ContentSyncState.valueOf(s.name()));
    assertEquals(ContentSyncState.valueOf(s.name()), s);
  }



  /**
   * Provides general test coverage for the enum.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGeneral()
         throws Exception
  {
    for (final ContentSyncState s : ContentSyncState.values())
    {
      assertNotNull(s);

      assertNotNull(ContentSyncState.valueOf(s.intValue()));
      assertEquals(ContentSyncState.valueOf(s.intValue()), s);

      assertNotNull(s.name());
      assertNotNull(ContentSyncState.valueOf(s.name()));
      assertEquals(ContentSyncState.valueOf(s.name()), s);
    }

    try
    {
      ContentSyncState.valueOf("invalid");
      fail("Expected an exception for an invalid valueOf string");
    }
    catch (final Exception e)
    {
      // This was expected.
    }

    assertNull(ContentSyncState.valueOf(-1));
  }
}
