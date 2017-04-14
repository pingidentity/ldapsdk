/*
 * Copyright 2009-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2017 UnboundID Corp.
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



import java.util.concurrent.atomic.AtomicInteger;



/**
 * This class provides an implementation of an intermediate response listener
 * that may be used for testing purposes.
 */
public class TestIntermediateResponseListener
       implements IntermediateResponseListener
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5541959741904470235L;



  // The number of intermediate response messages received.
  private final AtomicInteger count;



  /**
   * Creates a new instance of this test intermediate response listener.
   */
  public TestIntermediateResponseListener()
  {
    count = new AtomicInteger(0);
  }



  /**
   * Retrieves the number of intermediate responses received.
   *
   * @return  The number of intermediate responses received.
   */
  public int getCount()
  {
    return count.get();
  }



  /**
   * Resets the intermediate response count.
   */
  public void reset()
  {
    count.set(0);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void intermediateResponseReturned(
                   final IntermediateResponse intermediateResponse)
  {
    count.incrementAndGet();
  }
}
