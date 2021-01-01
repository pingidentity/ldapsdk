/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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



import com.unboundid.util.Extensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This interface is used by the LDIFWriter to translate or exclude change
 * records before they are written.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface LDIFWriterChangeRecordTranslator
{
  /**
   * Applies some special transformation or filtering to the original change
   * record.
   *
   * @param  original  The original change record that was to be written.
   *
   * @return  The change record that should be written.  This can be the
   *          original parameter change record, a newly-constructed change
   *          record, or {@code null} to signal that the change record should
   *          not be written.  Note, however, that if the original record
   *          provided as a parameter is altered, then the change will be
   *          visible to anything that references that change record.  If you
   *          are not sure about whether changes to the original change record
   *          are acceptable, it is recommended that you use the
   *          {@code duplicate()} method to create a copy of the original and
   *          make the necessary changes to that duplicate.
   */
  @Nullable
  LDIFChangeRecord translateChangeRecordToWrite(
       @NotNull LDIFChangeRecord original);
}
