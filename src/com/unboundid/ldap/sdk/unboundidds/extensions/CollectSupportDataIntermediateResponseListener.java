/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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



import com.unboundid.ldap.sdk.IntermediateResponse;
import com.unboundid.util.Extensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This interface provide an API that may be used to handle intermediate
 * response messages returned as part of processing for an
 * {@link CollectSupportDataExtendedRequest}.  It provides specific support for
 * the {@link CollectSupportDataOutputIntermediateResponse} and
 * {@link CollectSupportDataArchiveFragmentIntermediateResponse} intermediate
 * response types, but also allows handling other types of intermediate
 * responses as well.
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
 * @see  CollectSupportDataExtendedRequest
 * @see  CollectSupportDataExtendedResult
 * @see  CollectSupportDataArchiveFragmentIntermediateResponse
 * @see  CollectSupportDataOutputIntermediateResponse
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface CollectSupportDataIntermediateResponseListener
{
  /**
   * Performs any processing that may be necessary for the provided collect
   * support data output intermediate response.
   *
   * @param  response  The collect support data output intermediate response to
   *                   be processed.  It must not be {@code null}.
   */
  void handleOutputIntermediateResponse(
            @NotNull CollectSupportDataOutputIntermediateResponse response);



  /**
   * Performs any processing that may be necessary for the provided collect
   * support data archive fragment intermediate response.
   *
   * @param  response  The collect support data archive fragment intermediate
   *                   response to be processed.  It must not be {@code null}.
   */
  void handleArchiveFragmentIntermediateResponse(
       @NotNull CollectSupportDataArchiveFragmentIntermediateResponse response);



  /**
   * Performs any processing that may be necessary for any other type of
   * intermediate response that may be returned in response to a
   * {@link CollectSupportDataExtendedRequest}.
   *
   * @param  response  The generic intermediate response to be processed.  It
   *                   must not be {@code null}.
   */
  void handleOtherIntermediateResponse(@NotNull IntermediateResponse response);
}
