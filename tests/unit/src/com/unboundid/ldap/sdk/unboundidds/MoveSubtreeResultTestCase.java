/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the MoveSubtreeResult class.
 */
public final class MoveSubtreeResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests with an instance of the move subtree result object that indicates
   * processing completed successfully.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutErrors()
         throws Exception
  {
    final MoveSubtreeResult r = new MoveSubtreeResult(ResultCode.SUCCESS,
         null, null, true, true, 1, 2, 3);

    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    assertNull(r.getErrorMessage());

    assertNull(r.getAdminActionRequired());

    assertTrue(r.sourceServerAltered());

    assertTrue(r.targetServerAltered());

    assertEquals(r.getEntriesReadFromSource(), 1);

    assertEquals(r.getEntriesAddedToTarget(), 2);

    assertEquals(r.getEntriesDeletedFromSource(), 3);

    assertNotNull(r.toString());
  }



  /**
   * Tests with an instance of the move subtree result object that indicates
   * one or more errors occurred.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithErrors()
         throws Exception
  {
    final MoveSubtreeResult r = new MoveSubtreeResult(ResultCode.OTHER,
         "error message", "admin message", false, true, 3, 2, 1);

    assertEquals(r.getResultCode(), ResultCode.OTHER);

    assertEquals(r.getErrorMessage(), "error message");

    assertEquals(r.getAdminActionRequired(), "admin message");

    assertFalse(r.sourceServerAltered());

    assertTrue(r.targetServerAltered());

    assertEquals(r.getEntriesReadFromSource(), 3);

    assertEquals(r.getEntriesAddedToTarget(), 2);

    assertEquals(r.getEntriesDeletedFromSource(), 1);

    assertNotNull(r.toString());
  }
}
