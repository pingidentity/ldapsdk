/*
 * Copyright 2012-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs;



import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about a log
 * message that may appear in the Directory Server access log about a the
 * result of an entry rebalancing operation.
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
public final class EntryRebalancingResultAccessLogMessage
       extends EntryRebalancingRequestAccessLogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5593721315305821425L;



  // Indicates whether any changes were made to data in the source backend set.
  private final Boolean sourceAltered;

  // Indicates whether any changes were made to data in the target backend set.
  private final Boolean targetAltered;

  // The number of entries added to the target server.
  private final Integer entriesAddedToTarget;

  // The number of entries deleted from the source server.
  private final Integer entriesDeletedFromSource;

  // The number of entries read from the source server.
  private final Integer entriesReadFromSource;

  // The result code for the entry rebalancing operation.
  private final ResultCode resultCode;

  // A message with information about any administrative action that may be
  // required to complete the entry rebalancing processing.
  private final String adminActionRequired;

  // A message with additional information about any errors that occurred during
  // entry rebalancing processing.
  private final String errorMessage;



  /**
   * Creates a new entry rebalancing result access log message from the provided
   * message string.
   *
   * @param  s  The string to be parsed as an entry rebalancing result access
   *            log message.
   *
   * @throws  LogException  If the provided string cannot be parsed as a valid
   *                        log message.
   */
  public EntryRebalancingResultAccessLogMessage(final String s)
         throws LogException
  {
    this(new LogMessage(s));
  }



  /**
   * Creates a new entry rebalancing result access log message from the provided
   * log message.
   *
   * @param  m  The log message to be parsed as an entry rebalancing result
   *            access log message.
   */
  public EntryRebalancingResultAccessLogMessage(final LogMessage m)
  {
    super(m);

    final Integer rcInteger = getNamedValueAsInteger("resultCode");
    if (rcInteger == null)
    {
      resultCode = null;
    }
    else
    {
      resultCode = ResultCode.valueOf(rcInteger);
    }

    adminActionRequired      = getNamedValue("adminActionRequired");
    entriesAddedToTarget     = getNamedValueAsInteger("entriesAddedToTarget");
    entriesDeletedFromSource =
         getNamedValueAsInteger("entriesDeletedFromSource");
    entriesReadFromSource    = getNamedValueAsInteger("entriesReadFromSource");
    errorMessage             = getNamedValue("errorMessage");
    sourceAltered            = getNamedValueAsBoolean("sourceAltered");
    targetAltered            = getNamedValueAsBoolean("targetAltered");
  }



  /**
   * Retrieves the result code for the entry-rebalancing operation.
   *
   * @return  The result code for the entry-rebalancing operation, or
   *          {@code null} if it is not included in the log message.
   */
  public ResultCode getResultCode()
  {
    return resultCode;
  }



  /**
   * Retrieves a message with information about any errors that were encountered
   * during processing.
   *
   * @return  A message with information about any errors that were encountered
   *          during processing, or {@code null} if no errors were encountered
   *          or it is not included in the log message.
   */
  public String getErrorMessage()
  {
    return errorMessage;
  }



  /**
   * Retrieves a message with information about any administrative action that
   * may be required to bring the source and target servers back to a consistent
   * state with regard to the migrated subtree.
   *
   * @return  A message with information about any administrative action that
   *          may be required to bring the source and target servers back to a
   *          consistent state with regard to the migrated subtree, or
   *          {@code null} if no administrative action is required or it is not
   *          included in the log message.
   */
  public String getAdminActionRequired()
  {
    return adminActionRequired;
  }



  /**
   * Indicates whether data in the source server was altered as a result of
   * processing for this entry-rebalancing operation.
   *
   * @return  {@code true} if data in the source server was altered as a result
   *          of processing for this entry-rebalancing operation, {@code false}
   *          if no data in the source server was altered as a result of
   *          entry-rebalancing processing, or {@code null} if it is not
   *          included in the log message.
   */
  public Boolean sourceAltered()
  {
    return sourceAltered;
  }



  /**
   * Indicates whether data in the target server was altered as a result of
   * processing for this entry-rebalancing operation.
   *
   * @return  {@code true} if data in the target server was altered as a result
   *          of processing for this entry-rebalancing operation, {@code false}
   *          if no data in the target server was altered as a result of
   *          entry-rebalancing processing, or {@code null} if it is not
   *          included in the log message.
   */
  public Boolean targetAltered()
  {
    return targetAltered;
  }



  /**
   * Retrieves the number of entries that were read from the source server.
   *
   * @return  The number of entries that were read from the source server, or
   *          {@code null} if it is not included in the log message.
   */
  public Integer getEntriesReadFromSource()
  {
    return entriesReadFromSource;
  }



  /**
   * Retrieves the number of entries that were added to the target server.
   *
   * @return  The number of entries that were added to the target server, or
   *          {@code null} if it is not included in the log message.
   */
  public Integer getEntriesAddedToTarget()
  {
    return entriesAddedToTarget;
  }



  /**
   * Retrieves the number of entries that were deleted from the source server.
   *
   * @return  The number of entries that were deleted from the source server, or
   *          {@code null} if it is not included in the log message.
   */
  public Integer getEntriesDeletedFromSource()
  {
    return entriesDeletedFromSource;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public AccessLogMessageType getMessageType()
  {
    return AccessLogMessageType.ENTRY_REBALANCING_RESULT;
  }
}
