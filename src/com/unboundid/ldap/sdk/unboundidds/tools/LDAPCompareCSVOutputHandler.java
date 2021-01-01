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
package com.unboundid.ldap.sdk.unboundidds.tools;



import com.unboundid.ldap.sdk.CompareRequest;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.util.ColumnFormatter;
import com.unboundid.util.FormattableColumn;
import com.unboundid.util.HorizontalAlignment;
import com.unboundid.util.NotNull;
import com.unboundid.util.OutputFormat;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides an {@link LDAPCompare} output handler that will format
 * messages in column-separated values (CSV) format.
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
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class LDAPCompareCSVOutputHandler
      extends LDAPCompareOutputHandler
{
  // THe column formatter that will do the heavy lifting.
  @NotNull private final ColumnFormatter formatter;



  /**
   * Creates a new instance of this output handler.
   */
  LDAPCompareCSVOutputHandler()
  {
    formatter = new ColumnFormatter(false, null,
         OutputFormat.CSV, "",
         new FormattableColumn(1, HorizontalAlignment.LEFT,
              INFO_LDAPCOMPARE_FORMAT_HEADER_DN.get()),
         new FormattableColumn(1, HorizontalAlignment.LEFT,
              INFO_LDAPCOMPARE_FORMAT_HEADER_ATTR.get()),
         new FormattableColumn(1, HorizontalAlignment.LEFT,
              INFO_LDAPCOMPARE_FORMAT_HEADER_VALUE.get()),
         new FormattableColumn(1, HorizontalAlignment.LEFT,
              INFO_LDAPCOMPARE_FORMAT_HEADER_RC_INT.get()),
         new FormattableColumn(1, HorizontalAlignment.LEFT,
              INFO_LDAPCOMPARE_FORMAT_HEADER_RC_NAME.get()));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  String[] getHeaderLines()
  {
    return formatter.getHeaderLines(false);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  String formatResult(@NotNull final CompareRequest request,
                      @NotNull final LDAPResult result)
  {
    return formatter.formatRow(request.getDN(), request.getAttributeName(),
         request.getAssertionValue(), result.getResultCode().intValue(),
         result.getResultCode().getName());
  }
}
