/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
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
  @NotNull private final List<LDIFWriterEntryTranslator> translators;



  /**
   * Creates a new aggregate LDIF writer entry translator that will invoke all
   * of the provided translators for each entry to be processed.
   *
   * @param  translators  The set of LDIF writer entry translators to be invoked
   *                      for each entry to be processed.
   */
  public AggregateLDIFWriterEntryTranslator(
              @Nullable final LDIFWriterEntryTranslator... translators)
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
       @Nullable final Collection<? extends LDIFWriterEntryTranslator>
            translators)
  {
    if (translators == null)
    {
      this.translators = Collections.emptyList();
    }
    else
    {
      this.translators =
           Collections.unmodifiableList(new ArrayList<>(translators));
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public Entry translateEntryToWrite(@Nullable final Entry original)
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
