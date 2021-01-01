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
package com.unboundid.ldap.sdk;



import org.testng.annotations.Test;

import com.unboundid.util.LDAPSDKUsageException;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides a set of test cases for the EntrySourceException class.
 */
public class EntrySourceExceptionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides coverage for a case in which the client may continue reading.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMayContinueReading()
         throws Exception
  {
    EntrySourceException e = new EntrySourceException(true, new Exception());

    assertNotNull(e);

    assertNotNull(e.getCause());

    assertTrue(e.mayContinueReading());

    assertNotNull(e.toString());

    assertNotNull(getExceptionMessage(e));
  }



  /**
   * Provides coverage for a case in which the client may not continue reading.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMayNotContinueReading()
         throws Exception
  {
    EntrySourceException e = new EntrySourceException(false, new Exception());

    assertNotNull(e);

    assertNotNull(e.getCause());

    assertFalse(e.mayContinueReading());

    assertNotNull(e.toString());

    assertNotNull(getExceptionMessage(e));
  }



  /**
   * Ensures that attempting to provide a {@code null} cause will not be
   * allowed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNoCause()
         throws Exception
  {
    new EntrySourceException(false, null);
  }
}
