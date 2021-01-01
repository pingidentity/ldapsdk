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
package com.unboundid.ldap.sdk.persist;



import java.io.Closeable;
import java.io.Serializable;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.EntrySource;
import com.unboundid.ldap.sdk.LDAPEntrySource;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.persist.PersistMessages.*;



/**
 * This class provides a mechanism for iterating through the objects returned
 * by a search operation performed using one of the {@code search} methods in
 * the {@link LDAPPersister} class.  However, it has a couple of notable
 * differences from a standard Java {@code Iterator} object:
 * <UL>
 *   <LI>It does not have a {@code hasNext} method.  Instead, the {@link #next}
 *       method will return {@code null} when there are no more objects in the
 *       set of results.</LI>
 *   <LI>The {@link #next} method may throw an exception if a problem occurs
 *       while trying to read an entry or decode it as an object of the
 *       appropriate type.  This does not necessarily mean that the search is
 *       complete, and the {@link #next} method should be called again to see
 *       if there are any more objects to retrieve.</LI>
 *   <LI>If you wish to stop iterating through the results before all of them
 *       have been retrieved, then you must call the {@link #close} method
 * </UL>
 *
 * @param  <T>  The type of object handled by this class.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class PersistedObjects<T>
       implements Serializable, Closeable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7430494946944736169L;



  // The LDAP entry source that will be used to read matching entries.
  @NotNull private final EntrySource entrySource;

  // The LDAP persister that will be used to decode the entries that are
  // returned.
  @NotNull private final LDAPPersister<T> persister;



  /**
   * Creates a new {@code PersistedObjects} object that will read entries from
   * the provided entry source.
   *
   * @param  persister    The persister that will be used to decode entries that
   *                      are returned.
   * @param  entrySource  The entry source that will be used to read entries
   *                      returned from the search.
   */
  PersistedObjects(@NotNull final LDAPPersister<T> persister,
                   @NotNull final EntrySource entrySource)
  {
    this.persister   = persister;
    this.entrySource = entrySource;
  }



  /**
   * Retrieves the next object returned from the search request.  This method
   * may block until the necessary information  has been received from the
   * server.
   *
   * @return  The next object returned from the search request, or {@code null}
   *          if all objects have been read.
   *
   * @throws  LDAPPersistException  If a problem occurs while reading the next
   *                                entry from the server, or when trying to
   *                                decode that entry as an object.
   */
  @Nullable()
  public T next()
         throws LDAPPersistException
  {
    final Entry entry;
    try
    {
      entry = entrySource.nextEntry();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      final Throwable cause = e.getCause();
      if ((cause != null) && (cause instanceof LDAPException))
      {
        throw new LDAPPersistException((LDAPException) cause);
      }
      else
      {
        throw new LDAPPersistException(
             ERR_OBJECT_SEARCH_RESULTS_ENTRY_SOURCE_EXCEPTION.get(
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }

    if (entry == null)
    {
      return null;
    }
    else
    {
      return persister.decode(entry);
    }
  }



  /**
   * Indicates that you wish to stop iterating through search results and will
   * not be retrieving any additional objects.  This method MUST be called to
   * avoid leaking resources if you stop iterating through results before the
   * {@link #next} method returns {@code null} to indicate that there are no
   * more objects to retrieve.  This method MAY be called after the search has
   * completed (including being called multiple times) with no adverse effects.
   */
  @Override()
  public void close()
  {
    entrySource.close();
  }



  /**
   * Retrieves the search result for the search operation, if available.  It
   * will not be available until the search has completed (as indicated by a
   * {@code null} return value from the {@link #next} method), and for some use
   * cases it may never be available.
   *
   * @return  The search result for the search operation, or {@code null} if it
   *          is not available (e.g., because the search has not yet completed).
   */
  @Nullable()
  public SearchResult getSearchResult()
  {
    if (entrySource instanceof LDAPEntrySource)
    {
      return ((LDAPEntrySource) entrySource).getSearchResult();
    }
    else
    {
      return null;
    }
  }
}
