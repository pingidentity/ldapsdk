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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;



/**
 * This enum defines the set of possible error behavior values that may be used
 * in the multi-update extended request.
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
 *
 * @see MultiUpdateExtendedRequest
 */
public enum MultiUpdateErrorBehavior
{
  /**
   * The behavior which indicates that all operations must be processed
   * atomically.  The entire set of updates will succeed or fail as a single
   * unit, and directory clients will not see any updates while the multi-update
   * request is in progress.  Note that the server may place constraints on
   * the ability to use this error behavior such that it may not be usable in
   * all circumstances (e.g., when passing through a Directory Proxy Server with
   * entry balancing enabled or that would otherwise need to communicate with
   * multiple servers, or if it is necessary to interact with entries in
   * multiple Directory Server backends).
   */
  ATOMIC(0),



  /**
   * The behavior which indicates that processing will end for the multi-update
   * operation after the first failure is encountered while attempting to
   * apply a change.  Any changes processed before the first failure was
   * encountered will still have been applied, and clients accessing the server
   * in the course of processing the multi-update request may see changes after
   * only some of them have been completed.
   */
  ABORT_ON_ERROR(1),



  /**
   * The behavior which indicates that the server should attempt to process all
   * elements of the multi-update request even if one or more failures are
   * encountered.  Clients accessing the server in the course of processing the
   * multi-update request may see changes after only some of them have been
   * completed.
   */
  CONTINUE_ON_ERROR(2);



  // The integer value associated with this error behavior.
  private final int intValue;



  /**
   * Creates a new multi-update error behavior value with the provided integer
   * representation.
   *
   * @param  intValue  The integer value associated with this error behavior.
   */
  MultiUpdateErrorBehavior(final int intValue)
  {
    this.intValue = intValue;
  }



  /**
   * Retrieves the integer value associated with this error behavior.
   *
   * @return  The integer value associated with this error behavior.
   */
  public int intValue()
  {
    return intValue;
  }



  /**
   * Retrieves the multi-update error behavior value with the specified integer
   * value.
   *
   * @param  intValue  The integer value for the error behavior to retrieve.
   *
   * @return  The multi-update error behavior with the specified integer value,
   *          or {@code null} if there is no error behavior with the specified
   *          value.
   */
  @Nullable()
  public static MultiUpdateErrorBehavior valueOf(final int intValue)
  {
    for (final MultiUpdateErrorBehavior v : values())
    {
      if (intValue == v.intValue)
      {
        return v;
      }
    }

    return null;
  }



  /**
   * Retrieves the multi-update error behavior with the specified name.
   *
   * @param  name  The name of the multi-update error behavior to retrieve.  It
   *               must not be {@code null}.
   *
   * @return  The requested multi-update error behavior, or {@code null} if no
   *          such behavior is defined.
   */
  @Nullable()
  public static MultiUpdateErrorBehavior forName(@NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "atomic":
        return ATOMIC;
      case "abortonerror":
      case "abort-on-error":
      case "abort_on_error":
        return ABORT_ON_ERROR;
      case "continueonerror":
      case "continue-on-error":
      case "continue_on_error":
        return CONTINUE_ON_ERROR;
      default:
        return null;
    }
  }
}
