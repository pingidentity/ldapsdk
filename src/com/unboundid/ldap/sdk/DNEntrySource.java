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
package com.unboundid.ldap.sdk;



import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides an {@link EntrySource} that will retrieve entries
 * referenced by a provided set of DNs.  The connection will remain open after
 * all entries have been read.
 * <BR><BR>
 * It is not necessary to close this entry source when it is no longer needed,
 * although there is no cost or penalty in doing so.  Any exceptions thrown by
 * the {@link #nextEntry()} method will have the {@code mayContinueReading}
 * value set to {@code true}.
 * <H2>Example</H2>
 * The following example demonstrates the process for retrieving a static group
 * entry and using a {@code DNEntrySource} to iterate across the members of that
 * group:
 * <PRE>
 * Entry groupEntry =
 *      connection.getEntry("cn=My Group,ou=Groups,dc=example,dc=com");
 * String[] memberValues = groupEntry.getAttributeValues("member");
 * int entriesReturned = 0;
 * int exceptionsCaught = 0;
 *
 * if (memberValues != null)
 * {
 *   DNEntrySource entrySource =
 *        new DNEntrySource(connection, memberValues, "cn");
 *   try
 *   {
 *     while (true)
 *     {
 *       Entry memberEntry;
 *       try
 *       {
 *         memberEntry = entrySource.nextEntry();
 *       }
 *       catch (EntrySourceException ese)
 *       {
 *         // A problem was encountered while attempting to obtain an entry.
 *         // We may be able to continue reading entries (e.g., if the problem
 *         // was that the group referenced an entry that doesn't exist), or
 *         // we may not (e.g., if the problem was a significant search error
 *         // or problem with the connection).
 *         exceptionsCaught++;
 *         if (ese.mayContinueReading())
 *         {
 *           continue;
 *         }
 *         else
 *         {
 *           break;
 *         }
 *       }
 *
 *       if (memberEntry == null)
 *       {
 *         // We've retrieved all of the entries for the given set of DNs.
 *         break;
 *       }
 *       else
 *       {
 *         entriesReturned++;
 *       }
 *     }
 *   }
 *   finally
 *   {
 *     entrySource.close();
 *   }
 * }
 * </PRE>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class DNEntrySource
       extends EntrySource
{
  // The iterator to use to access the DNs.  It will either be across DN or
  // String objects.
  @NotNull private final Iterator<?> dnIterator;

  // The connection to use to communicate with the directory server.
  @NotNull private final LDAPInterface connection;

  // The set of attributes to include in entries that are returned.
  @NotNull private final String[] attributes;



  /**
   * Creates a new DN entry source with the provided information.
   *
   * @param  connection  The connection to the directory server from which the
   *                     entries will be read.  It must not be {@code null}.
   * @param  dns         The set of DNs to be read.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes to include in entries that are
   *                     returned.  If this is empty or {@code null}, then all
   *                     user attributes will be requested.
   */
  public DNEntrySource(@NotNull final LDAPInterface connection,
                       @NotNull final DN[] dns,
                       @Nullable final String... attributes)
  {
    Validator.ensureNotNull(connection, dns);

    this.connection = connection;
    dnIterator = Arrays.asList(dns).iterator();

    if (attributes == null)
    {
      this.attributes = StaticUtils.NO_STRINGS;
    }
    else
    {
      this.attributes = attributes;
    }
  }



  /**
   * Creates a new DN entry source with the provided information.
   *
   * @param  connection  The connection to the directory server from which the
   *                     entries will be read.  It must not be {@code null}.
   * @param  dns         The set of DNs to be read.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes to include in entries that are
   *                     returned.  If this is empty or {@code null}, then all
   *                     user attributes will be requested.
   */
  public DNEntrySource(@NotNull final LDAPInterface connection,
                       @NotNull final String[] dns,
                       @Nullable final String... attributes)
  {
    this(connection, Arrays.asList(dns), attributes);
  }



  /**
   * Creates a new DN entry source with the provided information.
   *
   * @param  connection  The connection to the directory server from which the
   *                     entries will be read.  It must not be {@code null}.
   * @param  dns         The set of DNs to be read.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes to include in entries that are
   *                     returned.  If this is empty or {@code null}, then all
   *                     user attributes will be requested.
   */
  public DNEntrySource(@NotNull final LDAPInterface connection,
                       @NotNull final Collection<String> dns,
                       @Nullable final String... attributes)
  {
    Validator.ensureNotNull(connection, dns);

    this.connection = connection;
    dnIterator = dns.iterator();

    if (attributes == null)
    {
      this.attributes = StaticUtils.NO_STRINGS;
    }
    else
    {
      this.attributes = attributes;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public Entry nextEntry()
         throws EntrySourceException
  {
    if (! dnIterator.hasNext())
    {
      return null;
    }

    final String dn = String.valueOf(dnIterator.next());
    try
    {
      final Entry e = connection.getEntry(dn, attributes);
      if (e == null)
      {
        throw new EntrySourceException(true,
             ERR_DN_ENTRY_SOURCE_NO_SUCH_ENTRY.get(dn),
             new LDAPException(ResultCode.NO_RESULTS_RETURNED));
      }
      else
      {
        return e;
      }
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw new EntrySourceException(true,
           ERR_DN_ENTRY_SOURCE_ERR_RETRIEVING_ENTRY.get(dn,
                StaticUtils.getExceptionMessage(le)),
           le);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void close()
  {
    // No implementation is required.
  }
}
