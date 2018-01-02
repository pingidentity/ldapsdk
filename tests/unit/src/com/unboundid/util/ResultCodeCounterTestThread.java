/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2018 Ping Identity Corporation
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



import java.util.Random;

import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a thread that will be used to test the result code
 * counter.
 */
public class ResultCodeCounterTestThread
       extends Thread
{
  /**
   * The random number generator that will be used to seed the thread-specific
   * generators.
   */
  private static final Random seedRandom = new Random();



  // The random number generator to use for this thread.
  private final Random random;

  // The result code counter to use.
  private final ResultCodeCounter counter;



  /**
   * Creates a new instance of this test thread that will be used to interact
   * with the provided counter.
   *
   * @param  counter  The result code counter to use.
   */
  public ResultCodeCounterTestThread(final ResultCodeCounter counter)
  {
    this.counter = counter;

    synchronized (seedRandom)
    {
      random = new Random(seedRandom.nextLong());
    }
  }



  /**
   * Operates in a loop, repeatedly updating and reading the counter and
   * periodically clearing it.
   */
  @Override()
  public void run()
  {
    final ResultCode[] codes = ResultCode.values();

    for (int i=0; i < 10000; i++)
    {
      for (int j=0; j < 10; j++)
      {
        counter.increment(codes[random.nextInt(codes.length)]);
        counter.getCounts(false);
      }

      counter.getCounts(true);
    }

    counter.reset();
  }
}
