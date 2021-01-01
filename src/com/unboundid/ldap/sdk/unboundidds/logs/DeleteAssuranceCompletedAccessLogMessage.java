/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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



import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about a log
 * message that may appear in the Directory Server access log about the result
 * of replication assurance processing for a delete operation.
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
public final class DeleteAssuranceCompletedAccessLogMessage
       extends DeleteResultAccessLogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8053481412117123593L;



  // Indicates whether the local assurance requirement was satisfied.
  @Nullable private final Boolean localAssuranceSatisfied;

  // Indicates whether the remote assurance requirement was satisfied.
  @Nullable private final Boolean remoteAssuranceSatisfied;

  // A string with information about the per-server assurance results.
  @Nullable private final String serverAssuranceResults;



  /**
   * Creates a new delete assurance complete access log message from the
   * provided message string.
   *
   * @param  s  The string to be parsed as an delete assurance complete access
   *            log message.
   *
   * @throws  LogException  If the provided string cannot be parsed as a valid
   *                        log message.
   */
  public DeleteAssuranceCompletedAccessLogMessage(@NotNull final String s)
         throws LogException
  {
    this(new LogMessage(s));
  }



  /**
   * Creates a new delete assurance complete access log message from the
   * provided message string.
   *
   * @param  m  The log message to be parsed as an delete assurance complete
   *            access log message.
   */
  public DeleteAssuranceCompletedAccessLogMessage(@NotNull final LogMessage m)
  {
    super(m);

    localAssuranceSatisfied = getNamedValueAsBoolean("localAssuranceSatisfied");
    remoteAssuranceSatisfied =
         getNamedValueAsBoolean("remoteAssuranceSatisfied");
    serverAssuranceResults = getNamedValue("serverAssuranceResults");
  }



  /**
   * Indicates whether the local assurance requirement was satisfied.
   *
   * @return  {@code true} if the local assurance requirement was satisfied,
   *          {@code false} if the local assurance requirement was not
   *          satisfied, or {@code null} if it was not included in the log
   *          message.
   */
  @Nullable()
  public Boolean getLocalAssuranceSatisfied()
  {
    return localAssuranceSatisfied;
  }



  /**
   * Indicates whether the remote assurance requirement was satisfied.
   *
   * @return  {@code true} if the remote assurance requirement was satisfied,
   *          {@code false} if the remote assurance requirement was not
   *          satisfied, or {@code null} if it was not included in the log
   *          message.
   */
  @Nullable()
  public Boolean getRemoteAssuranceSatisfied()
  {
    return remoteAssuranceSatisfied;
  }



  /**
   * Retrieves information about the assurance processing performed by
   * individual servers in the replication environment.
   *
   * @return  Information about the assurance processing performed by
   *          individual servers in the replication environment, or
   *          {@code null} if it was not included in the log message.
   */
  @Nullable()
  public String getServerAssuranceResults()
  {
    return serverAssuranceResults;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public AccessLogMessageType getMessageType()
  {
    return AccessLogMessageType.ASSURANCE_COMPLETE;
  }
}
