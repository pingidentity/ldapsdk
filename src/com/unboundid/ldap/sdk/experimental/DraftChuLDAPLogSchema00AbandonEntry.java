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
package com.unboundid.ldap.sdk.experimental;



import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.experimental.ExperimentalMessages.*;



/**
 * This class represents an entry that holds information about an abandon
 * operation processed by an LDAP server, as per the specification described in
 * draft-chu-ldap-logschema-00.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DraftChuLDAPLogSchema00AbandonEntry
       extends DraftChuLDAPLogSchema00Entry
{
  /**
   * The name of the attribute used to hold the message ID of the operation to
   * abandon.
   */
  @NotNull public static final String ATTR_ID_TO_ABANDON = "reqId";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5205545654036097510L;



  // The message ID of the operation to abandon.
  private final int idToAbandon;



  /**
   * Creates a new instance of this abandon access log entry from the provided
   * entry.
   *
   * @param  entry  The entry used to create this abandon access log entry.
   *
   * @throws  LDAPException  If the provided entry cannot be decoded as a valid
   *                         abandon access log entry as per the specification
   *                         contained in draft-chu-ldap-logschema-00.
   */
  public DraftChuLDAPLogSchema00AbandonEntry(@NotNull final Entry entry)
         throws LDAPException
  {
    super(entry, OperationType.ABANDON);

    final String idString = entry.getAttributeValue(ATTR_ID_TO_ABANDON);
    if (idString == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_LOGSCHEMA_DECODE_MISSING_REQUIRED_ATTR.get(entry.getDN(),
                ATTR_ID_TO_ABANDON));
    }
    else
    {
      try
      {
        idToAbandon = Integer.parseInt(idString);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_LOGSCHEMA_DECODE_ABANDON_ID_ERROR.get(entry.getDN(),
                  ATTR_ID_TO_ABANDON, idString),
             e);
      }
    }
  }



  /**
   * Retrieves the target message ID (i.e., the message ID of the operation to
   * abandon) for the abandon request described by this abandon access log
   * entry.
   *
   * @return  The target message ID for the abandon request described by this
   *          abandon access log entry.
   */
  public int getIDToAbandon()
  {
    return idToAbandon;
  }
}
