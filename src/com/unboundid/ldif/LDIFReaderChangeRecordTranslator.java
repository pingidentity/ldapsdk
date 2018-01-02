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
 * This interface is used by the LDIFReader to translate change records read
 * from the input or filter them out before they are returned via
 * {@link LDIFReader#readChangeRecord}.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface LDIFReaderChangeRecordTranslator
{
  /**
   * Applies some special transformation or filtering to the original change
   * record.
   *
   * @param  original         The original change record that was read and
   *                          parsed from the input file.
   * @param  firstLineNumber  The first line number of the LDIF change record.
   *                          This is most useful when throwing an
   *                          {@code LDIFException}.
   *
   * @return  The LDIF change record that should be returned in the call to
   *          {@link LDIFReader#readChangeRecord}. This can be the original
   *          parameter change record, a newly constructed change record, or
   *          {@code null} to signal that the provided change record should be
   *          skipped.
   *
   * @throws  LDIFException  If there is an exception during processing.  This
   *                         exception will be re-thrown to the caller of
   *                         readChangeRecord.
   */
  LDIFChangeRecord translate(LDIFChangeRecord original, long firstLineNumber)
       throws LDIFException;
}
