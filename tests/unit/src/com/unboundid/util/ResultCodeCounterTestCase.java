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
package com.unboundid.util;



import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the {@code ResultCodeCounter}
 * class.
 */
public class ResultCodeCounterTestCase
       extends UtilTestCase
{
  /**
   * Provides a set of tests for the result code counter using a simple set of
   * operations.
   */
  @Test()
  public void testCounter()
  {
    ResultCodeCounter c = new ResultCodeCounter();

    List<ObjectPair<ResultCode,Long>> counts = c.getCounts(true);
    assertTrue(counts.isEmpty());

    ResultCode[] codes = ResultCode.values();
    for (ResultCode rc : codes)
    {
      c.increment(rc);
    }

    counts = c.getCounts(true);
    assertFalse(counts.isEmpty());
    assertEquals(counts.size(), codes.length);
    for (int i=0; i < codes.length; i++)
    {
      ObjectPair<ResultCode,Long> p = counts.get(i);
      assertEquals(p.getFirst(), codes[i]);
      assertEquals(p.getSecond(), Long.valueOf(1L));
    }

    counts = c.getCounts(false);
    assertTrue(counts.isEmpty());

    for (ResultCode rc : codes)
    {
      c.increment(rc, rc.intValue());
    }

    counts = c.getCounts(true);
    assertFalse(counts.isEmpty());
    assertEquals(counts.size(), codes.length);
    for (int i=0,j=codes.length-1; i < codes.length; i++,j--)
    {
      ObjectPair<ResultCode,Long> p = counts.get(i);
      assertEquals(p.getFirst(), codes[j]);
      assertEquals(p.getSecond(), Long.valueOf(codes[j].intValue()));
    }

    counts = c.getCounts(false);
    assertTrue(counts.isEmpty());

    for (ResultCode rc : codes)
    {
      c.increment(rc, (1000 - rc.intValue()));
    }

    counts = c.getCounts(false);
    assertFalse(counts.isEmpty());
    assertEquals(counts.size(), codes.length);
    for (int i=0; i < codes.length; i++)
    {
      ObjectPair<ResultCode,Long> p = counts.get(i);
      assertEquals(p.getFirst(), codes[i]);
    }

    counts = c.getCounts(false);
    assertFalse(counts.isEmpty());

    c.reset();
    counts = c.getCounts(false);
    assertTrue(counts.isEmpty());
  }



  /**
   * Performs a set of multithreaded tests to see if we can hit trigger any of
   * the race conditions that should be handled properly by the code.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultiThreaded()
         throws Exception
  {
    ResultCodeCounter c = new ResultCodeCounter();

    ResultCodeCounterTestThread[] threads = new ResultCodeCounterTestThread[10];
    for (int i=0; i < 10; i++)
    {
      threads[i] = new ResultCodeCounterTestThread(c);
    }

    for (int i=0; i < 10; i++)
    {
      threads[i].start();
    }

    for (int i=0; i < 10; i++)
    {
      threads[i].join();
    }
  }
}
