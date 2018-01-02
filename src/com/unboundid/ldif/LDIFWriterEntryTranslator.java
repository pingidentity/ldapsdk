/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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



import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.Extensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This interface is used by the LDIFWriter to translate or exclude entries
 * before they are written.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface LDIFWriterEntryTranslator
{
  /**
   * Applies some special transformation or filtering to the original Entry.
   *
   * @param original  The original Entry that was to be written.
   *
   * @return  The Entry that should be written.  This can be the original
   *          parameter Entry, a newly-constructed Entry, or {@code null} to
   *          signal that this Entry should not be written.  Note, however, that
   *          if the original entry provided as a parameter is altered, then
   *          the change will be visible to anything that references that entry.
   *          If you are not sure about whether changes to the original entry
   *          are acceptable, it is recommended that you use the
   *          {@code duplicate()} method to create a copy of the original and
   *          make the necessary changes to that duplicate.
   */
  Entry translateEntryToWrite(Entry original);
}
