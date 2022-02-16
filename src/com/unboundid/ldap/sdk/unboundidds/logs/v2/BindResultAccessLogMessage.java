/*
 * Copyright 2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022 Ping Identity Corporation
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
 * Copyright (C) 2022 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs.v2;



import com.unboundid.util.NotExtensible;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about a bind
 * operation result access log message.
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
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface BindResultAccessLogMessage
       extends OperationResultAccessLogMessage,
               BindForwardAccessLogMessage
{
  /**
   * Retrieves the DN of the user authenticated by the bind operation.
   *
   * @return  The DN of the user authenticated by the bind operation, or
   *          {@code null} if it is not included in the log message.
   */
  @Nullable()
  String getAuthenticationDN();



  /**
   * Retrieves the DN of the alternate authorization identity for the bind
   * operation.
   *
   * @return  The DN of the alternate authorization identity for the bind
   *          operation, or {@code null} if it is not included in the log
   *          message.
   */
  @Nullable()
  String getAuthorizationDN();



  /**
   * Retrieves the numeric identifier for the authentication failure reason.
   *
   * @return  The numeric identifier for the authentication failure reason, or
   *          {@code null} if it is not included in the log message.
   */
  @Nullable()
  Long getAuthenticationFailureID();



  /**
   * Retrieves the name for the authentication failure reason.
   *
   * @return  The name for the authentication failure reason, or {@code null} if
   *          it is not included in the log message.
   */
  @Nullable()
  String getAuthenticationFailureName();



  /**
   * Retrieves a message with information about the reason that the
   * authentication attempt failed.
   *
   * @return  A message with information about the reason that the
   *          authentication attempt failed, or {@code null} if it is not
   *          included in the log message.
   */
  @Nullable()
  String getAuthenticationFailureMessage();



  /**
   * Indicates whether a retired password was used in the course of processing
   * the bind.
   *
   * @return  {@code true} if a retired password was used in the course of
   *          processing the bind, {@code false} if a retired password was not
   *          used in the course of processing the bind, or {@code null} if
   *          this was not included in the log message (and a retired password
   *          was likely not used in the course of processing the operation).
   */
  @Nullable()
  Boolean getRetiredPasswordUsed();



  /**
   * Retrieves the name of the client connection policy that was selected for
   * the client connection.
   *
   * @return  The name of the client connection policy that was selected for the
   *          client connection, or {@code null} if it is not included in the
   *          log message.
   */
  @Nullable()
  String getClientConnectionPolicy();
}
