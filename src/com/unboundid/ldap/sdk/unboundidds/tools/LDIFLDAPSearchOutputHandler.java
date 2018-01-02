/*
 * Copyright 2017-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2017-2018 Ping Identity Corporation
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
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
final class LDIFLDAPSearchOutputHandler
      extends LDAPSearchOutputHandler
{
  // A list used to hold the lines for a formatted representation of a search
  // result entry or reference.
  private final ArrayList<String> formattedLines;

  // The maximum width to use for output content.
  private final int maxWidth;

  // The associated LDAPSearch tool instance.
  private final LDAPSearch ldapSearch;

  // A string builder used to hold the formatted representation of the lines
  // that comprise a search result entry or reference.
  private final StringBuilder formattedLineBuffer;



  /**
   * Creates a new instance of this output handler.
   *
   * @param  ldapSearch  The {@link LDAPSearch} tool instance.
   * @param  maxWidth    The maximum width to use for the output.
   */
  LDIFLDAPSearchOutputHandler(final LDAPSearch ldapSearch, final int maxWidth)
  {
    this.ldapSearch = ldapSearch;
    this.maxWidth   = maxWidth;

    formattedLines = new ArrayList<String>(20);
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
  public void formatSearchResultEntry(final SearchResultEntry entry)
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
  public void formatSearchResultReference(final SearchResultReference ref)
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
  public void formatResult(final LDAPResult result)
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
  public void formatUnsolicitedNotification(final LDAPConnection connection,
                                            final ExtendedResult notification)
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
