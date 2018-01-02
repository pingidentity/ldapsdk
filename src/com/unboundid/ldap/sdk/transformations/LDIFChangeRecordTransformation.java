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
package com.unboundid.ldap.sdk.transformations;



import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.ldif.LDIFReaderChangeRecordTranslator;
import com.unboundid.ldif.LDIFWriterChangeRecordTranslator;
import com.unboundid.util.Extensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines an API that may be used to apply some kind of
 * transformation to an LDIF change record to alter its contents or suppress it
 * from further processing.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface LDIFChangeRecordTransformation
       extends LDIFReaderChangeRecordTranslator,
               LDIFWriterChangeRecordTranslator
{
  /**
   * Applies an appropriate transformation to the provided LDIF change record.
   *
   * @param  changeRecord  The LDIF change record to transform.
   *
   * @return  A copy of the change record with any appropriate transformation
   *          applied, the original change record if no transformations were
   *          necessary, or {@code null} if the change record should be
   *          suppressed.
   */
  LDIFChangeRecord transformChangeRecord(LDIFChangeRecord changeRecord);
}
