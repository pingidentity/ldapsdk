/*
 * Copyright 2022-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2023 Ping Identity Corporation
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
 * Copyright (C) 2022-2023 Ping Identity Corporation
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



import java.util.List;

import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about a search
 * request access log message.
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
public interface SearchRequestAccessLogMessage
       extends OperationRequestAccessLogMessage
{
  /**
   * Retrieves the base DN for the search request.
   *
   * @return  The base DN for the search request, or {@code null} if it is not
   *          included in the log message.
   */
  @Nullable()
  String getBaseDN();



  /**
   * Retrieves the scope for the search request.
   *
   * @return  The scope for the search request, or {@code null} if it is not
   *          included in the log message.
   */
  @Nullable()
  SearchScope getScope();



  /**
   * Retrieves a string representation of the filter for the search request.
   *
   * @return  A string representation of the filter for the search request, or
   *          {@code null} if it is not included in the log message.
   */
  @Nullable()
  String getFilter();



  /**
   * Retrieves the dereference policy for the search request.
   *
   * @return  The dereference policy for the search request, or {@code null} if
   *          it is not included in the log message or the value cannot be
   *          parsed as a valid {@code DereferencePolicy} value.
   */
  @Nullable()
  DereferencePolicy getDereferencePolicy();



  /**
   * Retrieves the size limit for the search request.
   *
   * @return  The size limit for the search request, or {@code null} if it is
   *          not included in the log message or the value cannot be parsed as
   *          an integer.
   */
  @Nullable()
  Integer getSizeLimit();



  /**
   * Retrieves the time limit for the search request, in seconds.
   *
   * @return  The time limit for the search request, or {@code null} if it is
   *          not included in the log message or the value cannot be parsed as
   *          an integer.
   */
  @Nullable()
  Integer getTimeLimitSeconds();



  /**
   * Retrieves the typesOnly value for the search request.
   *
   * @return  {@code true} if only attribute type names should be included in
   *          entries that are returned, {@code false} if both attribute types
   *          and values should be returned, or {@code null} if is not included
   *          in the log message or cannot be parsed as a Boolean.
   */
  @Nullable()
  Boolean getTypesOnly();



  /**
   * Retrieves the list of requested attributes for the search request.
   *
   * @return  The list of requested attributes for the search request, an empty
   *          list if the client did not explicitly request any attributes, or
   *          {@code null} if it is not included in the log message.
   */
  @NotNull()
  List<String> getRequestedAttributes();
}
