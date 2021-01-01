/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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



import java.util.HashSet;
import java.util.Set;

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
    for (final ContentSyncRequestMode value : ContentSyncRequestMode.values())
    {
      for (final String name : getNames(value.name()))
      {
        assertNotNull(ContentSyncRequestMode.forName(name));
        assertEquals(ContentSyncRequestMode.forName(name), value);
      }
    }

    assertNull(ContentSyncRequestMode.forName("some undefined name"));
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
