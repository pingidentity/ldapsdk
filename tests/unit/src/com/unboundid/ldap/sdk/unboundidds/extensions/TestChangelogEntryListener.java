/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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
  @Override()
  public void handleChangelogEntry(final ChangelogEntryIntermediateResponse ir)
  {
    entryCount.incrementAndGet();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void handleMissingChangelogEntries(
                   final MissingChangelogEntriesIntermediateResponse ir)
  {
    missingChangesCount.incrementAndGet();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
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
