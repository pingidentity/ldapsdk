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
import com.unboundid.ldap.sdk.IntermediateResponseListener;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an intermediate response listener that will be used to
 * process entries and other types of intermediate responses returned during the
 * course of processing a get changelog batch extended operation.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
final class GetChangelogBatchIntermediateResponseListener
      implements IntermediateResponseListener
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6143619102991670053L;



  // The counter that will be incremented with the number of entries returned.
  @NotNull private final AtomicInteger entryCounter;

  // The entry listener for the associated extended request.
  @NotNull private final ChangelogEntryListener entryListener;



  /**
   * Creates a new instance of this intermediate response listener with the
   * provided entry listener.
   *
   * @param  entryListener  The changelog batch entry listener to be notified.
   */
  GetChangelogBatchIntermediateResponseListener(
       @NotNull final ChangelogEntryListener entryListener)
  {
    this.entryListener = entryListener;

    entryCounter = new AtomicInteger(0);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void intermediateResponseReturned(
                   @NotNull final IntermediateResponse intermediateResponse)
  {
    final String oid = intermediateResponse.getOID();
    if (oid == null)
    {
      entryListener.handleOtherIntermediateResponse(intermediateResponse);
      return;
    }

    if (oid.equals(ChangelogEntryIntermediateResponse.
             CHANGELOG_ENTRY_INTERMEDIATE_RESPONSE_OID))
    {
      final ChangelogEntryIntermediateResponse r;
      try
      {
        r = new ChangelogEntryIntermediateResponse(intermediateResponse);
      }
      catch (final Exception e)
      {
        // Hopefully this won't happen, but if it does then there's not much
        // that can be done other than treat it like a generic intermediate
        // response.
        Debug.debugException(e);
        entryListener.handleOtherIntermediateResponse(intermediateResponse);
        return;
      }

      entryCounter.incrementAndGet();
      entryListener.handleChangelogEntry(r);
    }
    else if (oid.equals(MissingChangelogEntriesIntermediateResponse.
                  MISSING_CHANGELOG_ENTRIES_INTERMEDIATE_RESPONSE_OID))
    {
      final MissingChangelogEntriesIntermediateResponse r;
      try
      {
        r = new MissingChangelogEntriesIntermediateResponse(
             intermediateResponse);
      }
      catch (final Exception e)
      {
        // Hopefully this won't happen, but if it does then there's not much
        // that can be done other than treat it like a generic intermediate
        // response.
        Debug.debugException(e);
        entryListener.handleOtherIntermediateResponse(intermediateResponse);
        return;
      }

      entryListener.handleMissingChangelogEntries(r);
    }
    else
    {
      entryListener.handleOtherIntermediateResponse(intermediateResponse);
    }
  }



  /**
   * Retrieves the entry listener that will be used to process intermediate
   * responses returned during the course of the extended operation.
   *
   * @return  The entry listener that will be used to process intermediate
   *          responses returned during the course of the extended operation.
   */
  @NotNull()
  ChangelogEntryListener getEntryListener()
  {
    return entryListener;
  }



  /**
   * Retrieves the number of changelog entries returned during the course of
   * processing the extended operation.
   *
   * @return  The number of changelog entries returned during the course of
   *          processing the extended operation.
   */
  int getEntryCount()
  {
    return entryCounter.get();
  }
}
