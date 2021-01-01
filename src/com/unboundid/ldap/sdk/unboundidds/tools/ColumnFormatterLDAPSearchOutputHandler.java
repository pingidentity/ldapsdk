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
import java.util.List;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.util.ColumnFormatter;
import com.unboundid.util.FormattableColumn;
import com.unboundid.util.HorizontalAlignment;
import com.unboundid.util.NotNull;
import com.unboundid.util.OutputFormat;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an {@link LDAPSearchOutputHandler} instance that uses a
 * {@link ColumnFormatter} to output search result entries in a format like CSV
 * or tab-delimited text.  Only a single value from each attribute will be used,
 * and an empty string will be used for attributes without any values.
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
final class ColumnFormatterLDAPSearchOutputHandler
      extends LDAPSearchOutputHandler
{
  // A list used to hold the lines for a formatted representation of a search
  // result entry or reference.
  @NotNull private final ArrayList<String> formattedLines;

  // Indicates whether to include all values of a multivalued attribute.
  private final boolean includeAllValues;

  // The column formatter that will be used to generate the output.
  @NotNull private final ColumnFormatter formatter;

  // The maximum width to use for comments in the output.
  private final int maxCommentWidth;

  // The associated LDAPSearch tool instance.
  @NotNull private final LDAPSearch ldapSearch;

  // An array that holds the values for each of the columns to be output.
  @NotNull private final Object[] columnValues;

  // The names of the requested attributes.
  @NotNull private final String[] attributes;

  // A string builder used to hold the formatted representation of the lines
  // that comprise a search result entry or reference.
  @NotNull private final StringBuilder formattedLineBuffer;



  /**
   * Creates a new instance of this output handler.
   *
   * @param  ldapSearch           The {@link LDAPSearch} tool instance.
   * @param  outputFormat         The output format to use for search entry
   *                              attributes.
   * @param  requestedAttributes  The names of the requested attributes.
   * @param  maxCommentWidth      The maximum width to use for comments in the
   *                              output.  This will be ignored for information
   *                              about search result entries.
   * @param  includeAllValues     Indicates whether to include all values of a
   *                              multivalued attribute.  If this is
   *                              {@code true}, then a vertical bar (|) will be
   *                              used to separate the values within each field.
   */
  ColumnFormatterLDAPSearchOutputHandler(@NotNull final LDAPSearch ldapSearch,
       @NotNull final OutputFormat outputFormat,
       @NotNull final List<String> requestedAttributes,
       final int maxCommentWidth,
       final boolean includeAllValues)
  {
    this.ldapSearch = ldapSearch;
    this.maxCommentWidth = maxCommentWidth;
    this.includeAllValues = includeAllValues;

    attributes = new String[requestedAttributes.size()];
    requestedAttributes.toArray(attributes);

    columnValues = new Object[attributes.length + 1];

    final FormattableColumn[] columns =
         new FormattableColumn[attributes.length + 1];
    columns[0] = new FormattableColumn(10, HorizontalAlignment.LEFT, "DN");

    for (int i=0; i < attributes.length; i++)
    {
      columns[i+1] =
           new FormattableColumn(10, HorizontalAlignment.LEFT, attributes[i]);
    }

    formatter = new ColumnFormatter(false, null, outputFormat, " ", columns);

    formattedLines = new ArrayList<>(20);
    formattedLineBuffer = new StringBuilder(100);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void formatHeader()
  {
    for (final String headerLine : formatter.getHeaderLines(false))
    {
      ldapSearch.writeOut("# " + headerLine);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void formatSearchResultEntry(@NotNull final SearchResultEntry entry)
  {
    columnValues[0] = entry.getDN();

    int i=1;
    for (final String attributeName : attributes)
    {
      final Attribute a = entry.getAttribute(attributeName);
      if ((a ==  null) || (a.size() == 0))
      {
        columnValues[i] = "";
      }
      else if (includeAllValues && (a.size() > 1))
      {
        final StringBuilder buffer = new StringBuilder();
        for (final String v : a.getValues())
        {
          if (buffer.length() > 0)
          {
            buffer.append('|');
          }
          buffer.append(v);
        }

        columnValues[i] = buffer.toString();
      }
      else
      {
        columnValues[i] = a.getValue();
      }

      i++;
    }

    ldapSearch.writeOut(formatter.formatRow(columnValues));
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

    ResultUtils.formatSearchResultReference(formattedLines, ref,
         maxCommentWidth);
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

    ResultUtils.formatResult(formattedLines, result, true, false, 0,
         maxCommentWidth);
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
         true, 0, maxCommentWidth);
    for (final String s : formattedLines)
    {
      formattedLineBuffer.append(s);
      formattedLineBuffer.append(StaticUtils.EOL);
    }
    ldapSearch.writeOut(formattedLineBuffer.toString());
  }
}
