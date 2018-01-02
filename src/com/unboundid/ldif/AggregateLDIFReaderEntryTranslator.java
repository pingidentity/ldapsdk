/*
 * Copyright 2016-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2016-2018 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an implementation of an LDIF reader entry translator that
 * can be used to invoke multiple LDIF reader entry translators for each entry
 * to be processed.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AggregateLDIFReaderEntryTranslator
       implements LDIFReaderEntryTranslator
{
  // The set of LDIF reader entry translators to be invoked for each entry to
  // process.
  private final List<LDIFReaderEntryTranslator> translators;



  /**
   * Creates a new aggregate LDIF reader entry translator that will invoke all
   * of the provided translators for each entry to be processed.
   *
   * @param  translators  The set of LDIF reader entry translators to be invoked
   *                      for each entry to be processed.
   */
  public AggregateLDIFReaderEntryTranslator(
              final LDIFReaderEntryTranslator... translators)
  {
    this(StaticUtils.toList(translators));
  }



  /**
   * Creates a new aggregate LDIF reader entry translator that will invoke all
   * of the provided translators for each entry to be processed.
   *
   * @param  translators  The set of LDIF reader entry translators to be invoked
   *                      for each entry to be processed.
   */
  public AggregateLDIFReaderEntryTranslator(
              final Collection<? extends LDIFReaderEntryTranslator> translators)
  {
    if (translators == null)
    {
      this.translators = Collections.emptyList();
    }
    else
    {
      this.translators = Collections.unmodifiableList(
           new ArrayList<LDIFReaderEntryTranslator>(translators));
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Entry translate(final Entry original, final long firstLineNumber)
         throws LDIFException
  {
    if (original == null)
    {
      return null;
    }

    Entry e = original;
    for (final LDIFReaderEntryTranslator t : translators)
    {
      e = t.translate(e, firstLineNumber);
      if (e == null)
      {
        return null;
      }
    }

    return e;
  }
}
