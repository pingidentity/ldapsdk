/*
 * Copyright 2018-2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2018-2020 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tasks;



import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the file retention task filename
 * format enumeration.
 */
public final class FileRetentionTaskTimestampFormatTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the various enum methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEnumMethods()
         throws Exception
  {
    for (final FileRetentionTaskTimestampFormat f :
         FileRetentionTaskTimestampFormat.values())
    {
      assertNotNull(f);

      assertNotNull(f.getSimpleDateFormatString());

      assertNotNull(f.getRegexString());

      assertEquals(f.isInUTCTimeZone(), f.name().contains("UTC"));

      assertNotNull(FileRetentionTaskTimestampFormat.valueOf(f.name()));
      assertEquals(FileRetentionTaskTimestampFormat.valueOf(f.name()), f);

      for (final String name :
           Arrays.asList(f.name(), f.name().toLowerCase(),
                f.name().toUpperCase(), f.name().replace('_', '-')))
      {
        assertNotNull(FileRetentionTaskTimestampFormat.forName(name));
        assertEquals(FileRetentionTaskTimestampFormat.forName(name), f);
      }
    }

    assertNull(FileRetentionTaskTimestampFormat.forName("undefined"));

    try
    {
      FileRetentionTaskTimestampFormat.valueOf("undefined");
      fail("Expected an exception from valueOf with an undefined name");
    }
    catch (final IllegalArgumentException e)
    {
      // This was expected.
    }
  }
}
