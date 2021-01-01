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
package com.unboundid.ldif;



import java.util.concurrent.atomic.AtomicBoolean;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.EntrySource;
import com.unboundid.ldap.sdk.EntrySourceException;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides an {@link EntrySource} that will read entries from an
 * LDIF file.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process that may be used for iterating
 * through all entries in an LDIF file using the entry source API:
 * <PRE>
 * LDIFEntrySource entrySource =
 *      new LDIFEntrySource(new LDIFReader(pathToLDIFFile));
 *
 * int entriesRead = 0;
 * int errorsEncountered = 0;
 * try
 * {
 *   while (true)
 *   {
 *     try
 *     {
 *       Entry entry = entrySource.nextEntry();
 *       if (entry == null)
 *       {
 *         // There are no more entries to be read.
 *         break;
 *       }
 *       else
 *       {
 *         // Do something with the entry here.
 *         entriesRead++;
 *       }
 *     }
 *     catch (EntrySourceException e)
 *     {
 *       // Some kind of problem was encountered (e.g., a malformed entry
 *       // found in the LDIF file, or an I/O error when trying to read).  See
 *       // if we can continue reading entries.
 *       errorsEncountered++;
 *       if (! e.mayContinueReading())
 *       {
 *         break;
 *       }
 *     }
 *   }
 * }
 * finally
 * {
 *   entrySource.close();
 * }
 * </PRE>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class LDIFEntrySource
       extends EntrySource
{
  // Indicates whether this entry source has been closed.
  @NotNull private final AtomicBoolean closed;

  // The LDIF reader from which entries will be read.
  @NotNull private final LDIFReader ldifReader;



  /**
   * Creates a new LDAP entry source that will obtain entries from the provided
   * LDIF reader.
   *
   * @param  ldifReader  The LDIF reader from which to read entries.  It must
   *                     not be {@code null}.
   */
  public LDIFEntrySource(@NotNull final LDIFReader ldifReader)
  {
    Validator.ensureNotNull(ldifReader);

    this.ldifReader = ldifReader;

    closed = new AtomicBoolean(false);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public Entry nextEntry()
         throws EntrySourceException
  {
    if (closed.get())
    {
      return null;
    }

    try
    {
      final Entry e = ldifReader.readEntry();
      if (e == null)
      {
        close();
      }

      return e;
    }
    catch (final LDIFException le)
    {
      Debug.debugException(le);
      if (le.mayContinueReading())
      {
        throw new EntrySourceException(true, le);
      }
      else
      {
        close();
        throw new EntrySourceException(false, le);
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      close();
      throw new EntrySourceException(false, e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void close()
  {
    if (closed.compareAndSet(false, true))
    {
      try
      {
        ldifReader.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }
  }
}
