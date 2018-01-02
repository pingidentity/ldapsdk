/*
 * Copyright 2010-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2010-2018 Ping Identity Corporation
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
 * {@code ContentSyncRequestMode} class.
 */
public final class ContentSyncRequestModeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the REFRESH_ONLY mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRefreshOnly()
         throws Exception
  {
    final ContentSyncRequestMode m = ContentSyncRequestMode.REFRESH_ONLY;

    assertNotNull(m.name());
    assertNotNull(m.toString());

    assertEquals(m.intValue(), 1);

    assertNotNull(ContentSyncRequestMode.valueOf(m.intValue()));
    assertEquals(ContentSyncRequestMode.valueOf(m.intValue()), m);

    assertNotNull(ContentSyncRequestMode.valueOf(m.name()));
    assertEquals(ContentSyncRequestMode.valueOf(m.name()), m);
  }



  /**
   * Provides test coverage for the REFRESH_AND_PERSIST mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRefreshAndPersist()
         throws Exception
  {
    final ContentSyncRequestMode m = ContentSyncRequestMode.REFRESH_AND_PERSIST;

    assertNotNull(m.name());
    assertNotNull(m.toString());

    assertEquals(m.intValue(), 3);

    assertNotNull(ContentSyncRequestMode.valueOf(m.intValue()));
    assertEquals(ContentSyncRequestMode.valueOf(m.intValue()), m);

    assertNotNull(ContentSyncRequestMode.valueOf(m.name()));
    assertEquals(ContentSyncRequestMode.valueOf(m.name()), m);
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
    for (final ContentSyncRequestMode m : ContentSyncRequestMode.values())
    {
      assertNotNull(m);

      assertNotNull(ContentSyncRequestMode.valueOf(m.intValue()));
      assertEquals(ContentSyncRequestMode.valueOf(m.intValue()), m);

      assertNotNull(m.name());
      assertNotNull(ContentSyncRequestMode.valueOf(m.name()));
      assertEquals(ContentSyncRequestMode.valueOf(m.name()), m);
    }

    try
    {
      ContentSyncRequestMode.valueOf("invalid");
      fail("Expected an exception for an invalid valueOf string");
    }
    catch (final Exception e)
    {
      // This was expected.
    }

    assertNull(ContentSyncRequestMode.valueOf(-1));
  }
}
