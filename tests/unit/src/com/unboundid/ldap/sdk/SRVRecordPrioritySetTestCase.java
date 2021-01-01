/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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



import java.util.Arrays;
import java.util.List;

import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the SRVRecordPrioritySet class.
 */
public final class SRVRecordPrioritySetTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of an SRVRecordPrioritySet with a single record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleRecord()
         throws Exception
  {
    final SRVRecordPrioritySet s = new SRVRecordPrioritySet(1L, Arrays.asList(
         new SRVRecord("1 1 389 ds.example.com")));

    assertNotNull(s);

    assertEquals(s.getPriority(), 1L);

    final List<SRVRecord> l = s.getOrderedRecords();
    assertNotNull(l);
    assertEquals(l.size(), 1);

    assertNotNull(s.toString());
  }



  /**
   * Tests the behavior of an SRVRecordPrioritySet with two records with equal
   * weights.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTwoRecordsEqualWeights()
         throws Exception
  {
    final SRVRecordPrioritySet s = new SRVRecordPrioritySet(2L, Arrays.asList(
         new SRVRecord("2 1 389 ds1.example.com"),
         new SRVRecord("2 1 389 ds2.example.com")));

    assertNotNull(s);

    assertEquals(s.getPriority(), 2L);

    int count1 = 0;
    int count2 = 0;

    for (int i=0; i < 1000; i++)
    {
      final List<SRVRecord> l = s.getOrderedRecords();
      assertNotNull(l);
      assertEquals(l.size(), 2);

      final SRVRecord r1 = l.get(0);
      final SRVRecord r2 = l.get(1);

      if (r1.getAddress().equals("ds1.example.com"))
      {
        count1++;
        assertEquals(r2.getAddress(), "ds2.example.com");
      }
      else
      {
        count2++;
        assertEquals(r1.getAddress(), "ds2.example.com");
        assertEquals(r2.getAddress(), "ds1.example.com");
      }
    }

    final double ratio = 1.0d * count1 / count2;
    assertTrue(((ratio >= 0.5d) && (ratio <= 1.5d)),
         "Expected a ratio between 0.5 and 1.5, but got " + ratio);

    assertNotNull(s.toString());
  }



  /**
   * Tests the behavior of an SRVRecordPrioritySet with two records with
   * different weights.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTwoRecordsDifferentWeights()
         throws Exception
  {
    final SRVRecordPrioritySet s = new SRVRecordPrioritySet(3L, Arrays.asList(
         new SRVRecord("3 2 389 ds1.example.com"),
         new SRVRecord("3 1 389 ds2.example.com")));

    assertNotNull(s);

    assertEquals(s.getPriority(), 3L);

    int count1 = 0;
    int count2 = 0;

    for (int i=0; i < 1000; i++)
    {
      final List<SRVRecord> l = s.getOrderedRecords();
      assertNotNull(l);
      assertEquals(l.size(), 2);

      final SRVRecord r1 = l.get(0);
      final SRVRecord r2 = l.get(1);

      if (r1.getAddress().equals("ds1.example.com"))
      {
        count1++;
        assertEquals(r2.getAddress(), "ds2.example.com");
      }
      else
      {
        count2++;
        assertEquals(r1.getAddress(), "ds2.example.com");
        assertEquals(r2.getAddress(), "ds1.example.com");
      }
    }

    final double ratio = 1.0d * count1 / count2;
    assertTrue(((ratio >= 1.25d) && (ratio <= 2.75d)),
         "Expected a ratio between 1.25 and 2.75, but got " + ratio);

    assertNotNull(s.toString());
  }
}
