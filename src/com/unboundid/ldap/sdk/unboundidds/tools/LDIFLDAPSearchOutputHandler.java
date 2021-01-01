/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.util.ArrayList;

import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an {@link LDAPSearchOutputHandler} instance that formats
 * results in LDIF.
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
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
final class LDIFLDAPSearchOutputHandler
      extends LDAPSearchOutputHandler
{
  // A list used to hold the lines for a formatted representation of a search
  // result entry or reference.
  @NotNull private final ArrayList<String> formattedLines;

  // The maximum width to use for output content.
  private final int maxWidth;

  // The associated LDAPSearch tool instance.
  @NotNull private final LDAPSearch ldapSearch;

  // A string builder used to hold the formatted representation of the lines
  // that comprise a search result entry or reference.
  @NotNull private final StringBuilder formattedLineBuffer;



  /**
   * Creates a new instance of this output handler.
   *
   * @param  ldapSearch  The {@link LDAPSearch} tool instance.
   * @param  maxWidth    The maximum width to use for the output.
   */
  LDIFLDAPSearchOutputHandler(@NotNull final LDAPSearch ldapSearch,
                              final int maxWidth)
  {
    this.ldapSearch = ldapSearch;
    this.maxWidth   = maxWidth;

    formattedLines = new ArrayList<>(20);
    formattedLineBuffer = new StringBuilder(100);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void formatHeader()
  {
    // No header is required for this format.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void formatSearchResultEntry(@NotNull final SearchResultEntry entry)
  {
    formattedLines.clear();
    formattedLineBuffer.setLength(0);

    ResultUtils.formatSearchResultEntry(formattedLines, entry, maxWidth);
    for (final String s : formattedLines)
    {
      formattedLineBuffer.append(s);
      formattedLineBuffer.append(StaticUtils.EOL);
    }

    ldapSearch.writeOut(formattedLineBuffer.toString());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void formatSearchResultReference(
                   @NotNull final SearchResultReference ref)
  {
    formattedLines.clear();
    formattedLineBuffer.setLength(0);

    ResultUtils.formatSearchResultReference(formattedLines, ref, maxWidth);
    for (final String s : formattedLines)
    {
      formattedLineBuffer.append(s);
      formattedLineBuffer.append(StaticUtils.EOL);
    }

    ldapSearch.writeOut(formattedLineBuffer.toString());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void formatResult(@NotNull final LDAPResult result)
  {
    formattedLines.clear();
    formattedLineBuffer.setLength(0);

    ResultUtils.formatResult(formattedLines, result, true, false, 0, maxWidth);
    for (final String s : formattedLines)
    {
      formattedLineBuffer.append(s);
      formattedLineBuffer.append(StaticUtils.EOL);
    }
    ldapSearch.writeOut(formattedLineBuffer.toString());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void formatUnsolicitedNotification(
                   @NotNull final LDAPConnection connection,
                   @NotNull final ExtendedResult notification)
  {
    formattedLines.clear();
    formattedLineBuffer.setLength(0);

    ResultUtils.formatUnsolicitedNotification(formattedLines, notification,
         true, 0, maxWidth);
    for (final String s : formattedLines)
    {
      formattedLineBuffer.append(s);
      formattedLineBuffer.append(StaticUtils.EOL);
    }
    ldapSearch.writeOut(formattedLineBuffer.toString());
  }
}
