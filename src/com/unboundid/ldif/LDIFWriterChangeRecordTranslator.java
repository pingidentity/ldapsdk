/*
 * Copyright 2015-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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
  LDIFChangeRecord translateChangeRecordToWrite(LDIFChangeRecord original);
}
