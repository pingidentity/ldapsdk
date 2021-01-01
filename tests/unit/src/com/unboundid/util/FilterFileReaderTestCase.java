/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
package com.unboundid.util;



import java.io.File;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the filter file reader.
 */
public final class FilterFileReaderTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when reading an empty file when providing the path as a
   * string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPathToEmptyFile()
         throws Exception
  {
    final File f = createTempFile();

    final FilterFileReader r = new FilterFileReader(f.getAbsolutePath());
    assertNull(r.readFilter());
    r.close();
  }



  /**
   * Tests the behavior when reading a file containing only blank lines and
   * comments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFileWithOnlyBlankLinesAndComments()
         throws Exception
  {
    final File f = createTempFile(
         "# This is a comment",
         "",
         "# The above was a blank line",
         "# The below is also a blank line",
         "",
         "# And the file ends with a blank line",
         "");

    final FilterFileReader r = new FilterFileReader(f);
    assertNull(r.readFilter());
    r.close();
  }



  /**
   * Tests the behavior when reading a file containing only a single valid
   * filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFileWithSingleValidFilter()
         throws Exception
  {
    final File f = createTempFile("(uid=user.1234)");

    final FilterFileReader r = new FilterFileReader(f);

    final Filter filter = r.readFilter();
    assertNotNull(filter);
    assertEquals(filter, Filter.createEqualityFilter("uid", "user.1234"));

    assertNull(r.readFilter());
    r.close();
  }



  /**
   * Tests the behavior when reading a file containing only a single invalid
   * filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFileWithSingleInvalidFilter()
         throws Exception
  {
    final File f = createTempFile("this is not a valid filter");

    final FilterFileReader r = new FilterFileReader(f);

    try
    {
      final Filter filter = r.readFilter();
      fail("Expected an exception when trying to read an invalid filter, " +
           "but read " + filter);
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.FILTER_ERROR);
    }

    assertNull(r.readFilter());
    r.close();
  }



  /**
   * Tests the behavior when trying to read from a file with a mix of valid and
   * invalid filters, and also containing comments and blank lines.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadFileWithMultipleValidAndInvalidFilters()
         throws Exception
  {
    final File f = createTempFile(
         "",
         "# A comment before a valid filter",
         "(uid=filter.1)",
         "",
         "# A comment before an invalid filter",
         "invalid 1",
         "",
         "# Another couple of valid filters and then an invalid one",
         "(uid=filter.2)",
         "(uid=filter.3)",
         "(uid=filter.4)",
         "invalid 2",
         "",
         "",
         "",
         "#",
         "# One more valid filter",
         "#",
         "(uid=filter.5)",
         "");

    final FilterFileReader r = new FilterFileReader(f);

    Filter filter = r.readFilter();
    assertNotNull(filter);
    assertEquals(filter, Filter.createEqualityFilter("uid", "filter.1"));

    try
    {
      filter = r.readFilter();
      fail("Expected an exception when trying to read an invalid filter, " +
           "but read " + filter);
    }
    catch (LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.FILTER_ERROR);
    }

    filter = r.readFilter();
    assertNotNull(filter);
    assertEquals(filter, Filter.createEqualityFilter("uid", "filter.2"));

    filter = r.readFilter();
    assertNotNull(filter);
    assertEquals(filter, Filter.createEqualityFilter("uid", "filter.3"));

    filter = r.readFilter();
    assertNotNull(filter);
    assertEquals(filter, Filter.createEqualityFilter("uid", "filter.4"));

    try
    {
      filter = r.readFilter();
      fail("Expected an exception when trying to read an invalid filter, " +
           "but read " + filter);
    }
    catch (LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.FILTER_ERROR);
    }

    filter = r.readFilter();
    assertNotNull(filter);
    assertEquals(filter, Filter.createEqualityFilter("uid", "filter.5"));

    assertNull(r.readFilter());
    r.close();
  }
}
