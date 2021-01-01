/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
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
  @Nullable()
  Entry translateEntryToWrite(@NotNull Entry original);
}
