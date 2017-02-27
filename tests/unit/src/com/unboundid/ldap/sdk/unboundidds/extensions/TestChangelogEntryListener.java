/*
 * Copyright 2010-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2010-2017 UnboundID Corp.
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.util.concurrent.atomic.AtomicInteger;

import com.unboundid.ldap.sdk.IntermediateResponse;



/**
 * This class provides an implementation of a changelog entry listener that may
 * be used for testing purposes.
 */
public final class TestChangelogEntryListener
       implements ChangelogEntryListener
{
  // The number of entries returned.
  private final AtomicInteger entryCount;

  // The number of missing changes responses returned.
  private final AtomicInteger missingChangesCount;

  // The number of other intermediate responses returned.
  private final AtomicInteger otherCount;




  /**
   * Creates a new instance of this changelog entry listener.
   */
  public TestChangelogEntryListener()
  {
    entryCount          = new AtomicInteger(0);
    missingChangesCount = new AtomicInteger(0);
    otherCount          = new AtomicInteger(0);
  }



  /**
   * {@inheritDoc}
   */
  public void handleChangelogEntry(final ChangelogEntryIntermediateResponse ir)
  {
    entryCount.incrementAndGet();
  }



  /**
   * {@inheritDoc}
   */
  public void handleMissingChangelogEntries(
                   final MissingChangelogEntriesIntermediateResponse ir)
  {
    missingChangesCount.incrementAndGet();
  }



  /**
   * {@inheritDoc}
   */
  public void handleOtherIntermediateResponse(final IntermediateResponse ir)
  {
    otherCount.incrementAndGet();
  }



  /**
   * Retrieves the number of entries that have been returned.
   *
   * @return  The number of entries that have been returned.
   */
  public int getEntryCount()
  {
    return entryCount.get();
  }



  /**
   * Retrieves the number of missing changes results that have been returned.
   *
   * @return  The number of missing changes results that have been returned.
   */
  public int getMissingChangesCount()
  {
    return missingChangesCount.get();
  }



  /**
   * Retrieves the number of other types of intermediate responses that have
   * been returned.
   *
   * @return  The number of other types of intermediate responses that have been
   *          returned.
   */
  public int getOtherCount()
  {
    return otherCount.get();
  }
}
