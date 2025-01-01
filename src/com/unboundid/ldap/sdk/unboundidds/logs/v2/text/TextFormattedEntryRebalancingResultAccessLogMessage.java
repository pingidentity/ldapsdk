/*
 * Copyright 2022-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2025 Ping Identity Corporation
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
 * Copyright (C) 2022-2025 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs.v2.text;



import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.unboundidds.logs.AccessLogMessageType;
import com.unboundid.ldap.sdk.unboundidds.logs.LogException;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.
            EntryRebalancingResultAccessLogMessage;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about a
 * text-formatted entry rebalancing result access log message.
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
public final class TextFormattedEntryRebalancingResultAccessLogMessage
       extends TextFormattedEntryRebalancingRequestAccessLogMessage
       implements EntryRebalancingResultAccessLogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7982343893371640864L;



  // Indicates whether the source server was altered in the course of
  // processing.
  @Nullable private final Boolean sourceAltered;

  // Indicates whether the target server was altered in the course of
  // processing.
  @Nullable private final Boolean targetAltered;

  // The number of entries added to the target server.
  @Nullable private final Integer entriesAddedToTarget;

  // The number of entries deleted from the source server.
  @Nullable private final Integer entriesDeletedFromSource;

  // The number of entries read from the source server.
  @Nullable private final Integer entriesReadFromSource;

  // The result code for this log message.
  @Nullable private final ResultCode resultCode;

  // The admin action message for this log message.
  @Nullable private final String adminActionMessage;

  // The error message for this log message.
  @Nullable private final String errorMessage;



  /**
   * Creates a new text-formatted entry rebalancing request access log message
   * from the provided message string.
   *
   * @param  logMessageString  The string representation of this log message.
   *                           It must not be {@code null}.
   *
   * @throws  LogException  If the provided string cannot be parsed as a valid
   *                        log message.
   */
  public TextFormattedEntryRebalancingResultAccessLogMessage(
              @NotNull final String logMessageString)
         throws LogException
  {
    this(new TextFormattedLogMessage(logMessageString));
  }



  /**
   * Creates a new text-formatted entry rebalancing request access log message
   * from the provided message string.
   *
   * @param  logMessage  The log message to use to create this entry-rebalancing
   *                     result access log message.  It must not be
   *                     {@code null}.
   */
  TextFormattedEntryRebalancingResultAccessLogMessage(
       @NotNull final TextFormattedLogMessage logMessage)
  {
    super(logMessage);

    errorMessage = getString(
         TextFormattedAccessLogFields.ENTRY_REBALANCING_ERROR_MESSAGE);
    adminActionMessage = getString(
         TextFormattedAccessLogFields.ENTRY_REBALANCING_ADMIN_ACTION_MESSAGE);
    sourceAltered = getBooleanNoThrow(
         TextFormattedAccessLogFields.ENTRY_REBALANCING_SOURCE_SERVER_ALTERED);
    targetAltered = getBooleanNoThrow(
         TextFormattedAccessLogFields.ENTRY_REBALANCING_TARGET_SERVER_ALTERED);
    entriesReadFromSource = getIntegerNoThrow(TextFormattedAccessLogFields.
         ENTRY_REBALANCING_ENTRIES_READ_FROM_SOURCE);
    entriesAddedToTarget = getIntegerNoThrow(TextFormattedAccessLogFields.
         ENTRY_REBALANCING_ENTRIES_ADDED_TO_TARGET);
    entriesDeletedFromSource = getIntegerNoThrow(TextFormattedAccessLogFields.
         ENTRY_REBALANCING_ENTRIES_DELETED_FROM_SOURCE);

    final Integer resultCodeValue = getIntegerNoThrow(
         TextFormattedAccessLogFields.RESULT_CODE_VALUE);
    if (resultCodeValue == null)
    {
      resultCode = null;
    }
    else
    {
      resultCode = ResultCode.valueOf(resultCodeValue);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public AccessLogMessageType getMessageType()
  {
    return AccessLogMessageType.ENTRY_REBALANCING_RESULT;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public ResultCode getResultCode()
  {
    return resultCode;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public String getErrorMessage()
  {
    return errorMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public String getAdminActionMessage()
  {
    return adminActionMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public Boolean getSourceServerAltered()
  {
    return sourceAltered;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public Boolean getTargetServerAltered()
  {
    return targetAltered;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public Integer getEntriesReadFromSource()
  {
    return entriesReadFromSource;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public Integer getEntriesAddedToTarget()
  {
    return entriesAddedToTarget;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public Integer getEntriesDeletedFromSource()
  {
    return entriesDeletedFromSource;
  }
}
