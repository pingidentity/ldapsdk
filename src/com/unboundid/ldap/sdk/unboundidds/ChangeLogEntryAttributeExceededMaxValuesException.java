/*
 * Copyright 2011-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import com.unboundid.util.LDAPSDKException;
import com.unboundid.util.NotMutable;
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
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
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
  private final ChangeLogEntryAttributeExceededMaxValuesCount attrInfo;



  /**
   * Creates a new instance of this exception with the provided object.
   *
   * @param  message   The message to use for the exception.
   * @param  attrInfo  An object providing information about the attribute that
   *                   had more values than could be included in a changelog
   *                   entry before and/or after the change was processed.
   */
  public ChangeLogEntryAttributeExceededMaxValuesException(
              final String message,
              final ChangeLogEntryAttributeExceededMaxValuesCount attrInfo)
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
  public ChangeLogEntryAttributeExceededMaxValuesCount getAttributeInfo()
  {
    return attrInfo;
  }
}
