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



import java.io.Serializable;
import java.util.List;

import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a helper for use in assurance complete access log
 * messages.
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
final class TextFormattedAssuranceCompletedAccessLogMessageHelper
      implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1660878235825975297L;



  // Indicates whether local assurance was satisfied.
  @Nullable private final Boolean localAssuranceSatisfied;

  // Indicates whether remote assurance was satisfied.
  @Nullable private final Boolean remoteAssuranceSatisfied;

  // The list of server results.
  @NotNull private final List<String> serverResults;



  /**
   * Creates a new text-formatted forward access log message helper for the
   * provided log message.
   *
   * @param  logMessage  The log message to use to create this forward helper.
   */

  TextFormattedAssuranceCompletedAccessLogMessageHelper(
       @NotNull final TextFormattedRequestAccessLogMessage logMessage)
  {
    localAssuranceSatisfied = logMessage.getBooleanNoThrow(
         TextFormattedAccessLogFields.LOCAL_ASSURANCE_SATISFIED);
    remoteAssuranceSatisfied = logMessage.getBooleanNoThrow(
         TextFormattedAccessLogFields.REMOTE_ASSURANCE_SATISFIED);
    serverResults = logMessage.getCommaDelimitedStringList(
         TextFormattedAccessLogFields.SERVER_ASSURANCE_RESULTS);
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
  Boolean getLocalAssuranceSatisfied()
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
  Boolean getRemoteAssuranceSatisfied()
  {
    return remoteAssuranceSatisfied;
  }



  /**
   * Retrieves the list of server results.
   *
   * @return  The list of server results, or an empty list if it was not
   *          included in the log message.
   */
  @NotNull()
  List<String> getServerResults()
  {
    return serverResults;
  }
}
