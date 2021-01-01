/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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



import java.io.Serializable;

import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about the result
 * of a move subtree operation.
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
public final class MoveSubtreeResult
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2881207705643180021L;



  // Indicates whether any changes were made to the data in the source server.
  private final boolean sourceServerAltered;

  // Indicates whether any changes were made to the data in the target server.
  private final boolean targetServerAltered;

  // The number of entries added to the target server.
  private final int entriesAddedToTarget;

  // The number of entries deleted from the source server.
  private final int entriesDeletedFromSource;

  // The number of entries read from the source server.
  private final int entriesReadFromSource;

  // The result code resulting from processing.
  @NotNull private final ResultCode resultCode;

  // A string providing details of any administrative processing that may be
  // required to either complete the move or restore servers to their original
  // state.
  @Nullable private final String adminActionRequired;

  // A message with information about any error that may have occurred.
  @Nullable private final String errorMessage;



  /**
   * Creates a new move subtree result object with the provided information.
   *
   * @param  resultCode                A result code indicating the ultimate
   *                                   state of the move subtree processing.
   * @param  errorMessage              A message with information about any
   *                                   error that occurred.
   * @param  adminActionRequired       A message with information about any
   *                                   administrative action that may be
   *                                   required to bring the servers back to a
   *                                   consistent state.
   * @param  sourceServerAltered       Indicates whether any changes were made
   *                                   to data in the source server.
   * @param  targetServerAltered       Indicates whether any changes were made
   *                                   to data in the target server.
   * @param  entriesReadFromSource     The number of entries that were read from
   *                                   the source server.
   * @param  entriesAddedToTarget      The number of entries that were
   *                                   successfully added to the target server.
   * @param  entriesDeletedFromSource  The number of entries that were
   *                                   successfully removed from the source
   *                                   server.
   */
  MoveSubtreeResult(@NotNull final ResultCode resultCode,
                    @Nullable final String errorMessage,
                    @Nullable final String adminActionRequired,
                    final boolean sourceServerAltered,
                    final boolean targetServerAltered,
                    final int entriesReadFromSource,
                    final int entriesAddedToTarget,
                    final int entriesDeletedFromSource)
  {
    this.resultCode               = resultCode;
    this.errorMessage             = errorMessage;
    this.adminActionRequired      = adminActionRequired;
    this.sourceServerAltered      = sourceServerAltered;
    this.targetServerAltered      = targetServerAltered;
    this.entriesReadFromSource    = entriesReadFromSource;
    this.entriesAddedToTarget     = entriesAddedToTarget;
    this.entriesDeletedFromSource = entriesDeletedFromSource;
  }



  /**
   * Retrieves a result code which indicates the ultimate state of the move
   * subtree processing.  A result of {@code SUCCESS} indicates that all
   * processing was successful and the subtree was moved from one server to
   * another.  Any other result indicates that some kind of error occurred.
   *
   * @return  A result code which indicates the ultimate state of the move
   *          subtree processing.
   */
  @NotNull()
  public ResultCode getResultCode()
  {
    return resultCode;
  }



  /**
   * Retrieves an error message with information about a problem that occurred
   * during processing, if any.
   *
   * @return  An error message with information about a problem that occurred
   *          during processing, or {@code null} if no errors were encountered.
   */
  @Nullable()
  public String getErrorMessage()
  {
    return errorMessage;
  }



  /**
   * Retrieves a message with information about any administrative action which
   * may be required to bring data in the servers back into a consistent state
   * so that the entries in the target subtree will only exist in one of the
   * two servers.
   *
   * @return  A message with information about any administrative action which
   *          may be required to bring the data in the servers back into a
   *          consistent state, or {@code null} if no administrative action is
   *          necessary.
   */
  @Nullable()
  public String getAdminActionRequired()
  {
    return adminActionRequired;
  }



  /**
   * Indicates whether any data in the source server has been altered as a
   * result of the processing performed during the subtree move.  A successful
   * subtree move will cause entries to be removed from the source server, but
   * there may be error conditions which also result in source server changes.
   *
   * @return  {@code true} if any data in the source server has been altered as
   *          a result of the processing performed, or {@code false} if not.
   */
  public boolean sourceServerAltered()
  {
    return sourceServerAltered;
  }



  /**
   * Indicates whether any data in the target server has been altered as a
   * result of the processing performed during the subtree move.  A successful
   * subtree move will cause entries to be added to the target server, but
   * there may be error conditions which also result in target server changes.
   *
   * @return  {@code true} if any data in the target server has been altered as
   *          a result of the processing performed, or {@code false} if not.
   */
  public boolean targetServerAltered()
  {
    return targetServerAltered;
  }



  /**
   * Retrieves the number of entries within the specified subtree read from the
   * source server.
   *
   * @return  The number of entries within the specified subtree read from the
   *          source server.
   */
  public int getEntriesReadFromSource()
  {
    return entriesReadFromSource;
  }



  /**
   * Retrieves the number of entries added to the target server as a result of
   * the subtree move.  Note that even in a completely successful subtree move,
   * it is possible for this number to be less than the number of entries read
   * from the source server if a {@link MoveSubtreeListener} is in use and its
   * {@code doPreAddProcessing} method returns null for one or more entries to
   * indicate that those entries should not be added to the target.
   *
   * @return  The number of entries added to the target server as a result of
   *          the subtree move.
   */
  public int getEntriesAddedToTarget()
  {
    return entriesAddedToTarget;
  }



  /**
   * Retrieves the number of entries deleted from the source server as a result
   * of the subtree move.  If all processing is successful, then this value
   * should match the number of entries read from the source server.
   *
   * @return  The number of entries deleted from the target server as a result
   *          of the subtree move.
   */
  public int getEntriesDeletedFromSource()
  {
    return entriesDeletedFromSource;
  }



  /**
   * Retrieves a string representation of this move subtree result object.
   *
   * @return  A string representation of this move subtree result object.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this move subtree result object to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("MoveSubtreeResult(resultCode=");
    buffer.append(resultCode.getName());

    if (errorMessage != null)
    {
      buffer.append(", errorMessage='");
      buffer.append(errorMessage);
      buffer.append('\'');
    }

    if (adminActionRequired != null)
    {
      buffer.append(", adminActionRequired='");
      buffer.append(adminActionRequired);
      buffer.append('\'');
    }

    buffer.append(", sourceServerAltered=");
    buffer.append(sourceServerAltered);
    buffer.append(", targetServerAltered=");
    buffer.append(targetServerAltered);
    buffer.append(", entriesReadFromSource=");
    buffer.append(entriesReadFromSource);
    buffer.append(", entriesAddedToTarget=");
    buffer.append(entriesAddedToTarget);
    buffer.append(", entriesDeletedFromSource=");
    buffer.append(entriesDeletedFromSource);
    buffer.append(')');
  }
}
