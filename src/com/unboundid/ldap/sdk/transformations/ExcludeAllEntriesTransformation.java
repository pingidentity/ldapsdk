/*
 * Copyright 2019-2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2019-2020 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.transformations;



import java.io.Serializable;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an entry transformation that will simply suppress all
 * entries.  It can be useful when processing a series of LDIF records if you
 * only want to preserve change records and suppress all entries.
 */
@NotMutable()
@ThreadSafety(level = ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ExcludeAllEntriesTransformation
       implements EntryTransformation, Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 8203086326365856962L;



  /**
   * Creates a new instance of this transformation.
   */
  public ExcludeAllEntriesTransformation()
  {
    // No implementation is required.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Entry transformEntry(final Entry entry)
  {
    return null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Entry translate(final Entry original, final long firstLineNumber)
  {
    return null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Entry translateEntryToWrite(final Entry original)
  {
    return null;
  }
}
