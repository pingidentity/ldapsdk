/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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



import java.util.TreeMap;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResult;



/**
 * This class provides a set of test cases for the subtree deleter result class.
 */
public final class SubtreeDeleterResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a result that indicates complete success with entries deleted.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompletelySuccessfulResultWithEntriesDeleted()
         throws Exception
  {
    final SubtreeDeleterResult result = new SubtreeDeleterResult(null,
         false, null, 12345L, new TreeMap<DN,LDAPResult>());

    assertTrue(result.completelySuccessful());

    assertNull(result.getSetSubtreeAccessibilityError());

    assertFalse(result.subtreeInaccessible());

    assertNull(result.getSearchError());

    assertEquals(result.getEntriesDeleted(), 12345L);

    assertNotNull(result.getDeleteErrors());
    assertTrue(result.getDeleteErrors().isEmpty());

    assertNotNull(result.toString());
  }



  /**
   * Tests a result that indicates complete success without any entries deleted.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompletelySuccessfulResultWithoutEntriesDeleted()
         throws Exception
  {
    final SubtreeDeleterResult result = new SubtreeDeleterResult(null,
         false, null, 0L, new TreeMap<DN,LDAPResult>());

    assertTrue(result.completelySuccessful());

    assertNull(result.getSetSubtreeAccessibilityError());

    assertFalse(result.subtreeInaccessible());

    assertNull(result.getSearchError());

    assertEquals(result.getEntriesDeleted(), 0L);

    assertNotNull(result.getDeleteErrors());
    assertTrue(result.getDeleteErrors().isEmpty());

    assertNotNull(result.toString());
  }



  /**
   * Tests a result that indicates that the attempt to make the subtree
   * inaccessible failed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetInaccessibleFailureResult()
         throws Exception
  {
    final SubtreeDeleterResult result = new SubtreeDeleterResult(
         new LDAPResult(1, ResultCode.UNWILLING_TO_PERFORM),
         false, null, 0L, new TreeMap<DN,LDAPResult>());

    assertFalse(result.completelySuccessful());

    assertNotNull(result.getSetSubtreeAccessibilityError());

    assertFalse(result.subtreeInaccessible());

    assertNull(result.getSearchError());

    assertEquals(result.getEntriesDeleted(), 0L);

    assertNotNull(result.getDeleteErrors());
    assertTrue(result.getDeleteErrors().isEmpty());

    assertNotNull(result.toString());
  }



  /**
   * Tests a result that indicates that the attempt to make the subtree
   * accessible again failed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetAccessibleFailureResult()
         throws Exception
  {
    final SubtreeDeleterResult result = new SubtreeDeleterResult(
         new LDAPResult(1, ResultCode.OTHER),
         true, null, 12345L, new TreeMap<DN,LDAPResult>());

    assertFalse(result.completelySuccessful());

    assertNotNull(result.getSetSubtreeAccessibilityError());

    assertTrue(result.subtreeInaccessible());

    assertNull(result.getSearchError());

    assertEquals(result.getEntriesDeleted(), 12345L);

    assertNotNull(result.getDeleteErrors());
    assertTrue(result.getDeleteErrors().isEmpty());

    assertNotNull(result.toString());
  }



  /**
   * Tests a result that indicates that a search failed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchFailureResult()
         throws Exception
  {
    final SubtreeDeleterResult result = new SubtreeDeleterResult(null, false,
         new SearchResult(1, ResultCode.INSUFFICIENT_ACCESS_RIGHTS, null,
              null, null, 0, 0, null),
         0L, new TreeMap<DN,LDAPResult>());

    assertFalse(result.completelySuccessful());

    assertNull(result.getSetSubtreeAccessibilityError());

    assertFalse(result.subtreeInaccessible());

    assertNotNull(result.getSearchError());

    assertEquals(result.getEntriesDeleted(), 0L);

    assertNotNull(result.getDeleteErrors());
    assertTrue(result.getDeleteErrors().isEmpty());

    assertNotNull(result.toString());
  }



  /**
   * Tests a result that indicates that some of the delete attempts failed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteFailureResult()
         throws Exception
  {
    final TreeMap<DN,LDAPResult> deleteFailures = new TreeMap<>();
    deleteFailures.put(new DN("dc=example,dc=com"),
         new LDAPResult(1, ResultCode.NOT_ALLOWED_ON_NONLEAF));
    deleteFailures.put(new DN("ou=People,dc=example,dc=com"),
         new LDAPResult(1, ResultCode.INSUFFICIENT_ACCESS_RIGHTS));

    final SubtreeDeleterResult result =
         new SubtreeDeleterResult(null, false, null, 0L, deleteFailures);

    assertFalse(result.completelySuccessful());

    assertNull(result.getSetSubtreeAccessibilityError());

    assertFalse(result.subtreeInaccessible());

    assertNull(result.getSearchError());

    assertEquals(result.getEntriesDeleted(), 0L);

    assertNotNull(result.getDeleteErrors());
    assertFalse(result.getDeleteErrors().isEmpty());

    assertNotNull(result.toString());
  }



  /**
   * Tests a result that indicates that everything failed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTotalFailureResult()
         throws Exception
  {
    final TreeMap<DN,LDAPResult> deleteFailures = new TreeMap<>();
    deleteFailures.put(new DN("dc=example,dc=com"),
         new LDAPResult(1, ResultCode.NOT_ALLOWED_ON_NONLEAF));
    deleteFailures.put(new DN("ou=People,dc=example,dc=com"),
         new LDAPResult(1, ResultCode.INSUFFICIENT_ACCESS_RIGHTS));

    final SubtreeDeleterResult result = new SubtreeDeleterResult(
         new LDAPResult(1, ResultCode.OTHER), true,
         new SearchResult(1, ResultCode.INSUFFICIENT_ACCESS_RIGHTS, null,
              null, null, 0, 0, null),
         0L, deleteFailures);

    assertFalse(result.completelySuccessful());

    assertNotNull(result.getSetSubtreeAccessibilityError());

    assertTrue(result.subtreeInaccessible());

    assertNotNull(result.getSearchError());

    assertEquals(result.getEntriesDeleted(), 0L);

    assertNotNull(result.getDeleteErrors());
    assertFalse(result.getDeleteErrors().isEmpty());

    assertNotNull(result.toString());
  }
}
