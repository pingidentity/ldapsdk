/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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
 * This interface defines a set of methods that will be invoked when an
 * intermediate response is returned in the course of processing a get changelog
 * batch extended operation.  It may be used to process changelog entries as
 * they are returned by the server rather than accessing them in a list when the
 * extended result has been received.
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
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface ChangelogEntryListener
{
  /**
   * Performs any processing necessary for a changelog entry intermediate
   * response returned by the server.
   *
   * @param  ir  The changelog entry intermediate response that was returned by
   *            the server.
   */
  void handleChangelogEntry(@NotNull ChangelogEntryIntermediateResponse ir);



  /**
   * Performs any processing necessary for a missing changelog entries
   * intermediate response returned by the server.
   *
   * @param  ir  The missing changelog entries intermediate response that was
   *             returned by the server.
   */
  void handleMissingChangelogEntries(
            @NotNull MissingChangelogEntriesIntermediateResponse ir);



  /**
   * Performs any processing necessary for some other type of intermediate
   * response returned during processing for a get changelog batch extended
   * operation.  This method may do nothing if this implementation does not
   * provide support for any other types of intermediate responses.
   *
   * @param  ir  The generic entry intermediate response that was returned by
   *             the server.
   */
  void handleOtherIntermediateResponse(@NotNull IntermediateResponse ir);
}
