/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import com.unboundid.util.LDAPSDKException;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an exception that may be thrown when attempting to obtain
 * the value of an updated attribute as it appeared before or after a change
 * was processed, but the number of values for that attribute exceeded the
 * maximum number to include in a changelog entry.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ChangeLogEntryAttributeExceededMaxValuesException
       extends LDAPSDKException
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -9108989779921909512L;



  // The object providing information about the attribute that had more values
  // than could be included in a changelog entry.
  @NotNull private final ChangeLogEntryAttributeExceededMaxValuesCount attrInfo;



  /**
   * Creates a new instance of this exception with the provided object.
   *
   * @param  message   The message to use for the exception.
   * @param  attrInfo  An object providing information about the attribute that
   *                   had more values than could be included in a changelog
   *                   entry before and/or after the change was processed.
   */
  public ChangeLogEntryAttributeExceededMaxValuesException(
       @NotNull final String message,
       @NotNull final ChangeLogEntryAttributeExceededMaxValuesCount attrInfo)
  {
    super(message);

    this.attrInfo = attrInfo;
  }



  /**
   * Retrieves an object providing information about the attribute that had more
   * values than could be included in a changelog entry before and/or after the
   * change was processed.
   *
   * @return  An object providing information about the attribute that had more
   *          values than could be included in a changelog entry before and/or
   *          after the change was processed.
   */
  @NotNull()
  public ChangeLogEntryAttributeExceededMaxValuesCount getAttributeInfo()
  {
    return attrInfo;
  }
}
