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
 * This class provides an implementation of an LDIF writer entry translator that
 * can be used to invoke multiple LDIF writer entry translators for each entry
 * to be processed.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AggregateLDIFWriterEntryTranslator
       implements LDIFWriterEntryTranslator
{
  // The set of LDIF writer entry translators to be invoked for each entry to
  // process.
  private final List<LDIFWriterEntryTranslator> translators;



  /**
   * Creates a new aggregate LDIF writer entry translator that will invoke all
   * of the provided translators for each entry to be processed.
   *
   * @param  translators  The set of LDIF writer entry translators to be invoked
   *                      for each entry to be processed.
   */
  public AggregateLDIFWriterEntryTranslator(
              final LDIFWriterEntryTranslator... translators)
  {
    this(StaticUtils.toList(translators));
  }



  /**
   * Creates a new aggregate LDIF writer entry translator that will invoke all
   * of the provided translators for each entry to be processed.
   *
   * @param  translators  The set of LDIF writer entry translators to be invoked
   *                      for each entry to be processed.
   */
  public AggregateLDIFWriterEntryTranslator(
              final Collection<? extends LDIFWriterEntryTranslator> translators)
  {
    if (translators == null)
    {
      this.translators = Collections.emptyList();
    }
    else
    {
      this.translators = Collections.unmodifiableList(
           new ArrayList<LDIFWriterEntryTranslator>(translators));
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Entry translateEntryToWrite(final Entry original)
  {
    if (original == null)
    {
      return null;
    }

    Entry e = original;
    for (final LDIFWriterEntryTranslator t : translators)
    {
      e = t.translateEntryToWrite(e);
      if (e == null)
      {
        return null;
      }
    }

    return e;
  }
}
