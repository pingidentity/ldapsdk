/*
 * Copyright 2021-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021-2024 Ping Identity Corporation
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
 * Copyright (C) 2021-2024 Ping Identity Corporation
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
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the matching entry count request
 * control properties.
 */
public final class MatchingEntryCountRequestControlPropertiesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when using the default set of properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultProperties()
         throws Exception
  {
    MatchingEntryCountRequestControlProperties properties =
         new MatchingEntryCountRequestControlProperties();

    assertEquals(properties.getMaxCandidatesToExamine(), 0);
    assertFalse(properties.alwaysExamineCandidates());
    assertFalse(properties.processSearchIfUnindexed());
    assertFalse(properties.skipResolvingExplodedIndexes());
    assertNull(properties.getFastShortCircuitThreshold());
    assertNull(properties.getSlowShortCircuitThreshold());
    assertFalse(properties.includeExtendedResponseData());
    assertFalse(properties.includeDebugInfo());

    assertNotNull(properties.toString());


    properties = new MatchingEntryCountRequestControlProperties(properties);

    assertEquals(properties.getMaxCandidatesToExamine(), 0);
    assertFalse(properties.alwaysExamineCandidates());
    assertFalse(properties.processSearchIfUnindexed());
    assertFalse(properties.skipResolvingExplodedIndexes());
    assertNull(properties.getFastShortCircuitThreshold());
    assertNull(properties.getSlowShortCircuitThreshold());
    assertFalse(properties.includeExtendedResponseData());
    assertFalse(properties.includeDebugInfo());

    assertNotNull(properties.toString());


    properties = new MatchingEntryCountRequestControlProperties(
         new MatchingEntryCountRequestControl(true, properties));

    assertEquals(properties.getMaxCandidatesToExamine(), 0);
    assertFalse(properties.alwaysExamineCandidates());
    assertFalse(properties.processSearchIfUnindexed());
    assertFalse(properties.skipResolvingExplodedIndexes());
    assertNull(properties.getFastShortCircuitThreshold());
    assertNull(properties.getSlowShortCircuitThreshold());
    assertFalse(properties.includeExtendedResponseData());
    assertFalse(properties.includeDebugInfo());

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the maximum candidates to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMaxCandidatesToExamine()
         throws Exception
  {
    MatchingEntryCountRequestControlProperties properties =
         new MatchingEntryCountRequestControlProperties();

    assertEquals(properties.getMaxCandidatesToExamine(), 0);
    assertFalse(properties.alwaysExamineCandidates());
    assertFalse(properties.processSearchIfUnindexed());
    assertFalse(properties.skipResolvingExplodedIndexes());
    assertNull(properties.getFastShortCircuitThreshold());
    assertNull(properties.getSlowShortCircuitThreshold());
    assertFalse(properties.includeExtendedResponseData());
    assertFalse(properties.includeDebugInfo());

    assertNotNull(properties.toString());


    properties.setMaxCandidatesToExamine(1234);
    assertEquals(properties.getMaxCandidatesToExamine(), 1234);

    properties = new MatchingEntryCountRequestControlProperties(properties);

    assertEquals(properties.getMaxCandidatesToExamine(), 1234);
    assertFalse(properties.alwaysExamineCandidates());
    assertFalse(properties.processSearchIfUnindexed());
    assertFalse(properties.skipResolvingExplodedIndexes());
    assertNull(properties.getFastShortCircuitThreshold());
    assertNull(properties.getSlowShortCircuitThreshold());
    assertFalse(properties.includeExtendedResponseData());
    assertFalse(properties.includeDebugInfo());

    assertNotNull(properties.toString());


    properties.setMaxCandidatesToExamine(0);
    assertEquals(properties.getMaxCandidatesToExamine(), 0);

    properties = new MatchingEntryCountRequestControlProperties(
         new MatchingEntryCountRequestControl(true, properties));

    assertEquals(properties.getMaxCandidatesToExamine(), 0);
    assertFalse(properties.alwaysExamineCandidates());
    assertFalse(properties.processSearchIfUnindexed());
    assertFalse(properties.skipResolvingExplodedIndexes());
    assertNull(properties.getFastShortCircuitThreshold());
    assertNull(properties.getSlowShortCircuitThreshold());
    assertFalse(properties.includeExtendedResponseData());
    assertFalse(properties.includeDebugInfo());

    assertNotNull(properties.toString());

    try
    {
      properties.setMaxCandidatesToExamine(-1);
      fail("Expected an exception for a negative maxCandidatesToExamine");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior for the always examine candidates flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAlwaysExamineCandidates()
         throws Exception
  {
    MatchingEntryCountRequestControlProperties properties =
         new MatchingEntryCountRequestControlProperties();

    assertEquals(properties.getMaxCandidatesToExamine(), 0);
    assertFalse(properties.alwaysExamineCandidates());
    assertFalse(properties.processSearchIfUnindexed());
    assertFalse(properties.skipResolvingExplodedIndexes());
    assertNull(properties.getFastShortCircuitThreshold());
    assertNull(properties.getSlowShortCircuitThreshold());
    assertFalse(properties.includeExtendedResponseData());
    assertFalse(properties.includeDebugInfo());

    assertNotNull(properties.toString());


    properties.setAlwaysExamineCandidates(true);
    assertTrue(properties.alwaysExamineCandidates());

    properties = new MatchingEntryCountRequestControlProperties(properties);

    assertEquals(properties.getMaxCandidatesToExamine(), 0);
    assertTrue(properties.alwaysExamineCandidates());
    assertFalse(properties.processSearchIfUnindexed());
    assertFalse(properties.skipResolvingExplodedIndexes());
    assertNull(properties.getFastShortCircuitThreshold());
    assertNull(properties.getSlowShortCircuitThreshold());
    assertFalse(properties.includeExtendedResponseData());
    assertFalse(properties.includeDebugInfo());

    assertNotNull(properties.toString());


    properties.setAlwaysExamineCandidates(false);
    assertFalse(properties.alwaysExamineCandidates());

    properties = new MatchingEntryCountRequestControlProperties(
         new MatchingEntryCountRequestControl(true, properties));

    assertEquals(properties.getMaxCandidatesToExamine(), 0);
    assertFalse(properties.alwaysExamineCandidates());
    assertFalse(properties.processSearchIfUnindexed());
    assertFalse(properties.skipResolvingExplodedIndexes());
    assertNull(properties.getFastShortCircuitThreshold());
    assertNull(properties.getSlowShortCircuitThreshold());
    assertFalse(properties.includeExtendedResponseData());
    assertFalse(properties.includeDebugInfo());

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the process search if unindexed flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProcessSearchIfUnindexed()
         throws Exception
  {
    MatchingEntryCountRequestControlProperties properties =
         new MatchingEntryCountRequestControlProperties();

    assertEquals(properties.getMaxCandidatesToExamine(), 0);
    assertFalse(properties.alwaysExamineCandidates());
    assertFalse(properties.processSearchIfUnindexed());
    assertFalse(properties.skipResolvingExplodedIndexes());
    assertNull(properties.getFastShortCircuitThreshold());
    assertNull(properties.getSlowShortCircuitThreshold());
    assertFalse(properties.includeExtendedResponseData());
    assertFalse(properties.includeDebugInfo());

    assertNotNull(properties.toString());


    properties.setProcessSearchIfUnindexed(true);
    assertTrue(properties.processSearchIfUnindexed());

    properties = new MatchingEntryCountRequestControlProperties(properties);

    assertEquals(properties.getMaxCandidatesToExamine(), 0);
    assertFalse(properties.alwaysExamineCandidates());
    assertTrue(properties.processSearchIfUnindexed());
    assertFalse(properties.skipResolvingExplodedIndexes());
    assertNull(properties.getFastShortCircuitThreshold());
    assertNull(properties.getSlowShortCircuitThreshold());
    assertFalse(properties.includeExtendedResponseData());
    assertFalse(properties.includeDebugInfo());

    assertNotNull(properties.toString());


    properties.setProcessSearchIfUnindexed(false);
    assertFalse(properties.processSearchIfUnindexed());

    properties = new MatchingEntryCountRequestControlProperties(
         new MatchingEntryCountRequestControl(true, properties));

    assertEquals(properties.getMaxCandidatesToExamine(), 0);
    assertFalse(properties.alwaysExamineCandidates());
    assertFalse(properties.processSearchIfUnindexed());
    assertFalse(properties.skipResolvingExplodedIndexes());
    assertNull(properties.getFastShortCircuitThreshold());
    assertNull(properties.getSlowShortCircuitThreshold());
    assertFalse(properties.includeExtendedResponseData());
    assertFalse(properties.includeDebugInfo());

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the skip resolving exploded indexes flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSkipResolvingExplodedIndexes()
         throws Exception
  {
    MatchingEntryCountRequestControlProperties properties =
         new MatchingEntryCountRequestControlProperties();

    assertEquals(properties.getMaxCandidatesToExamine(), 0);
    assertFalse(properties.alwaysExamineCandidates());
    assertFalse(properties.processSearchIfUnindexed());
    assertFalse(properties.skipResolvingExplodedIndexes());
    assertNull(properties.getFastShortCircuitThreshold());
    assertNull(properties.getSlowShortCircuitThreshold());
    assertFalse(properties.includeExtendedResponseData());
    assertFalse(properties.includeDebugInfo());

    assertNotNull(properties.toString());


    properties.setSkipResolvingExplodedIndexes(true);
    assertTrue(properties.skipResolvingExplodedIndexes());

    properties = new MatchingEntryCountRequestControlProperties(properties);

    assertEquals(properties.getMaxCandidatesToExamine(), 0);
    assertFalse(properties.alwaysExamineCandidates());
    assertFalse(properties.processSearchIfUnindexed());
    assertTrue(properties.skipResolvingExplodedIndexes());
    assertNull(properties.getFastShortCircuitThreshold());
    assertNull(properties.getSlowShortCircuitThreshold());
    assertFalse(properties.includeExtendedResponseData());
    assertFalse(properties.includeDebugInfo());

    assertNotNull(properties.toString());


    properties.setSkipResolvingExplodedIndexes(false);
    assertFalse(properties.skipResolvingExplodedIndexes());

    properties = new MatchingEntryCountRequestControlProperties(
         new MatchingEntryCountRequestControl(true, properties));

    assertEquals(properties.getMaxCandidatesToExamine(), 0);
    assertFalse(properties.alwaysExamineCandidates());
    assertFalse(properties.processSearchIfUnindexed());
    assertFalse(properties.skipResolvingExplodedIndexes());
    assertNull(properties.getFastShortCircuitThreshold());
    assertNull(properties.getSlowShortCircuitThreshold());
    assertFalse(properties.includeExtendedResponseData());
    assertFalse(properties.includeDebugInfo());

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the fast short circuit threshold.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFastShortCircuitThreshold()
         throws Exception
  {
    MatchingEntryCountRequestControlProperties properties =
         new MatchingEntryCountRequestControlProperties();

    assertEquals(properties.getMaxCandidatesToExamine(), 0);
    assertFalse(properties.alwaysExamineCandidates());
    assertFalse(properties.processSearchIfUnindexed());
    assertFalse(properties.skipResolvingExplodedIndexes());
    assertNull(properties.getFastShortCircuitThreshold());
    assertNull(properties.getSlowShortCircuitThreshold());
    assertFalse(properties.includeExtendedResponseData());
    assertFalse(properties.includeDebugInfo());

    assertNotNull(properties.toString());


    properties.setFastShortCircuitThreshold(1234L);
    assertEquals(properties.getFastShortCircuitThreshold().longValue(), 1234L);

    properties = new MatchingEntryCountRequestControlProperties(properties);

    assertEquals(properties.getMaxCandidatesToExamine(), 0);
    assertFalse(properties.alwaysExamineCandidates());
    assertFalse(properties.processSearchIfUnindexed());
    assertFalse(properties.skipResolvingExplodedIndexes());
    assertEquals(properties.getFastShortCircuitThreshold().longValue(), 1234L);
    assertNull(properties.getSlowShortCircuitThreshold());
    assertFalse(properties.includeExtendedResponseData());
    assertFalse(properties.includeDebugInfo());

    assertNotNull(properties.toString());


    properties.setFastShortCircuitThreshold(-1L);
    assertEquals(properties.getFastShortCircuitThreshold().longValue(), 0L);

    properties = new MatchingEntryCountRequestControlProperties(
         new MatchingEntryCountRequestControl(true, properties));

    assertEquals(properties.getMaxCandidatesToExamine(), 0);
    assertFalse(properties.alwaysExamineCandidates());
    assertFalse(properties.processSearchIfUnindexed());
    assertFalse(properties.skipResolvingExplodedIndexes());
    assertEquals(properties.getFastShortCircuitThreshold().longValue(), 0L);
    assertNull(properties.getSlowShortCircuitThreshold());
    assertFalse(properties.includeExtendedResponseData());
    assertFalse(properties.includeDebugInfo());

    assertNotNull(properties.toString());


    properties.setFastShortCircuitThreshold(null);
    assertNull(properties.getFastShortCircuitThreshold());
  }



  /**
   * Tests the behavior for the slow short circuit threshold.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSlowShortCircuitThreshold()
         throws Exception
  {
    MatchingEntryCountRequestControlProperties properties =
         new MatchingEntryCountRequestControlProperties();

    assertEquals(properties.getMaxCandidatesToExamine(), 0);
    assertFalse(properties.alwaysExamineCandidates());
    assertFalse(properties.processSearchIfUnindexed());
    assertFalse(properties.skipResolvingExplodedIndexes());
    assertNull(properties.getFastShortCircuitThreshold());
    assertNull(properties.getSlowShortCircuitThreshold());
    assertFalse(properties.includeExtendedResponseData());
    assertFalse(properties.includeDebugInfo());

    assertNotNull(properties.toString());


    properties.setSlowShortCircuitThreshold(1234L);
    assertEquals(properties.getSlowShortCircuitThreshold().longValue(), 1234L);

    properties = new MatchingEntryCountRequestControlProperties(properties);

    assertEquals(properties.getMaxCandidatesToExamine(), 0);
    assertFalse(properties.alwaysExamineCandidates());
    assertFalse(properties.processSearchIfUnindexed());
    assertFalse(properties.skipResolvingExplodedIndexes());
    assertNull(properties.getFastShortCircuitThreshold());
    assertEquals(properties.getSlowShortCircuitThreshold().longValue(), 1234L);
    assertFalse(properties.includeExtendedResponseData());
    assertFalse(properties.includeDebugInfo());

    assertNotNull(properties.toString());


    properties.setSlowShortCircuitThreshold(-1L);
    assertEquals(properties.getSlowShortCircuitThreshold().longValue(), 0L);

    properties = new MatchingEntryCountRequestControlProperties(
         new MatchingEntryCountRequestControl(true, properties));

    assertEquals(properties.getMaxCandidatesToExamine(), 0);
    assertFalse(properties.alwaysExamineCandidates());
    assertFalse(properties.processSearchIfUnindexed());
    assertFalse(properties.skipResolvingExplodedIndexes());
    assertNull(properties.getFastShortCircuitThreshold());
    assertEquals(properties.getSlowShortCircuitThreshold().longValue(), 0L);
    assertFalse(properties.includeExtendedResponseData());
    assertFalse(properties.includeDebugInfo());

    assertNotNull(properties.toString());


    properties.setSlowShortCircuitThreshold(null);
    assertNull(properties.getSlowShortCircuitThreshold());
  }



  /**
   * Tests the behavior for the include extended response data flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeExtendedResponseData()
         throws Exception
  {
    MatchingEntryCountRequestControlProperties properties =
         new MatchingEntryCountRequestControlProperties();

    assertEquals(properties.getMaxCandidatesToExamine(), 0);
    assertFalse(properties.alwaysExamineCandidates());
    assertFalse(properties.processSearchIfUnindexed());
    assertFalse(properties.skipResolvingExplodedIndexes());
    assertNull(properties.getFastShortCircuitThreshold());
    assertNull(properties.getSlowShortCircuitThreshold());
    assertFalse(properties.includeExtendedResponseData());
    assertFalse(properties.includeDebugInfo());

    assertNotNull(properties.toString());


    properties.setIncludeExtendedResponseData(true);
    assertTrue(properties.includeExtendedResponseData());

    properties = new MatchingEntryCountRequestControlProperties(properties);

    assertEquals(properties.getMaxCandidatesToExamine(), 0);
    assertFalse(properties.alwaysExamineCandidates());
    assertFalse(properties.processSearchIfUnindexed());
    assertFalse(properties.skipResolvingExplodedIndexes());
    assertNull(properties.getFastShortCircuitThreshold());
    assertNull(properties.getSlowShortCircuitThreshold());
    assertTrue(properties.includeExtendedResponseData());
    assertFalse(properties.includeDebugInfo());

    assertNotNull(properties.toString());


    properties.setIncludeExtendedResponseData(false);
    assertFalse(properties.includeExtendedResponseData());

    properties = new MatchingEntryCountRequestControlProperties(
         new MatchingEntryCountRequestControl(true, properties));

    assertEquals(properties.getMaxCandidatesToExamine(), 0);
    assertFalse(properties.alwaysExamineCandidates());
    assertFalse(properties.processSearchIfUnindexed());
    assertFalse(properties.skipResolvingExplodedIndexes());
    assertNull(properties.getFastShortCircuitThreshold());
    assertNull(properties.getSlowShortCircuitThreshold());
    assertFalse(properties.includeExtendedResponseData());
    assertFalse(properties.includeDebugInfo());

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the include debug info flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeDebugInfo()
         throws Exception
  {
    MatchingEntryCountRequestControlProperties properties =
         new MatchingEntryCountRequestControlProperties();

    assertEquals(properties.getMaxCandidatesToExamine(), 0);
    assertFalse(properties.alwaysExamineCandidates());
    assertFalse(properties.processSearchIfUnindexed());
    assertFalse(properties.skipResolvingExplodedIndexes());
    assertNull(properties.getFastShortCircuitThreshold());
    assertNull(properties.getSlowShortCircuitThreshold());
    assertFalse(properties.includeExtendedResponseData());
    assertFalse(properties.includeDebugInfo());

    assertNotNull(properties.toString());


    properties.setIncludeDebugInfo(true);
    assertTrue(properties.includeDebugInfo());

    properties = new MatchingEntryCountRequestControlProperties(properties);

    assertEquals(properties.getMaxCandidatesToExamine(), 0);
    assertFalse(properties.alwaysExamineCandidates());
    assertFalse(properties.processSearchIfUnindexed());
    assertFalse(properties.skipResolvingExplodedIndexes());
    assertNull(properties.getFastShortCircuitThreshold());
    assertNull(properties.getSlowShortCircuitThreshold());
    assertFalse(properties.includeExtendedResponseData());
    assertTrue(properties.includeDebugInfo());

    assertNotNull(properties.toString());


    properties.setIncludeDebugInfo(false);
    assertFalse(properties.includeDebugInfo());

    properties = new MatchingEntryCountRequestControlProperties(
         new MatchingEntryCountRequestControl(true, properties));

    assertEquals(properties.getMaxCandidatesToExamine(), 0);
    assertFalse(properties.alwaysExamineCandidates());
    assertFalse(properties.processSearchIfUnindexed());
    assertFalse(properties.skipResolvingExplodedIndexes());
    assertNull(properties.getFastShortCircuitThreshold());
    assertNull(properties.getSlowShortCircuitThreshold());
    assertFalse(properties.includeExtendedResponseData());
    assertFalse(properties.includeDebugInfo());

    assertNotNull(properties.toString());
  }
}
