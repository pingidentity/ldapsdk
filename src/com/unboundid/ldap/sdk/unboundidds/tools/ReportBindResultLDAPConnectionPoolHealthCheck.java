/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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

import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionPoolHealthCheck;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.CommandLineTool;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides an implementation of a connection pool health check that
 * can display information about the result of a bind operation.  It will always
 * report information about an unsuccessful bind.  It may optionally report
 * information about a successful bind, and optionally only if the successful
 * bind includes one or more response controls.
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
 * <BR>
 * Note that this health check is only intended to generate output when
 * appropriate and will never throw an exception to indicate that a connection
 * is unusable.  If additional health checking is required, then this health
 * check may be combined with others via an aggregate health check in a manner
 * that ensures this health check will be invoked before any others that may
 * throw an exception.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ReportBindResultLDAPConnectionPoolHealthCheck
       extends LDAPConnectionPoolHealthCheck
{
  // Indicates whether to display result details for successful binds that
  // include one or more response controls.
  private final boolean displaySuccessResultWithControls;

  // Indicates whether to display result details for successful binds that do
  // not include any response controls.
  private final boolean displaySuccessResultWithoutControls;

  // The tool whose output and error streams will be used for displaying result
  // details.
  @NotNull private final CommandLineTool tool;

  // The column at which to wrap long lines.
  private final int wrapColumn;



  /**
   * Creates a new instance of this health check with the provided information.
   *
   * @param  tool                                 The tool with which this
   *                                              health check is associated.
   *                                              Any success messages written
   *                                              will be sent to the tool's
   *                                              standard output stream.  Any
   *                                              failure messages written will
   *                                              be sent to the tool's standard
   *                                              error stream.
   * @param  displaySuccessResultWithControls     Indicates whether to display
   *                                              information about a bind
   *                                              result with a result code of
   *                                              {@code SUCCESS} that has one
   *                                              or more response controls.
   * @param  displaySuccessResultWithoutControls  Indicates whether to display
   *                                              information about a bind
   *                                              result with a result code of
   *                                              {@code SUCCESS} that has no
   *                                              response controls.
   */
  public ReportBindResultLDAPConnectionPoolHealthCheck(
              @NotNull final CommandLineTool tool,
              final boolean displaySuccessResultWithControls,
              final boolean displaySuccessResultWithoutControls)
  {
    this.tool = tool;
    this.displaySuccessResultWithControls = displaySuccessResultWithControls;
    this.displaySuccessResultWithoutControls =
         displaySuccessResultWithoutControls;

    wrapColumn = StaticUtils.TERMINAL_WIDTH_COLUMNS - 1;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void ensureConnectionValidAfterAuthentication(
                   @NotNull final LDAPConnection connection,
                   @NotNull final BindResult bindResult)
         throws LDAPException
  {
    if (bindResult.getResultCode() == ResultCode.SUCCESS)
    {
      final boolean displayResult;
      if (bindResult.hasResponseControl())
      {
        displayResult = displaySuccessResultWithControls;
      }
      else
      {
        displayResult = displaySuccessResultWithoutControls;
      }

      if (displayResult)
      {
        final ArrayList<String> lines = new ArrayList<>(10);
        lines.add("# " + INFO_REPORT_BIND_RESULT_HEADER.get());

        ResultUtils.formatResult(lines, bindResult, true, false, 5, wrapColumn);
        for (final String line : lines)
        {
          tool.out(line);
        }
        tool.out();
      }
    }
    else
    {
      final ArrayList<String> lines = new ArrayList<>(10);
      lines.add("# " + INFO_REPORT_BIND_RESULT_HEADER.get());

      ResultUtils.formatResult(lines, bindResult, true, false, 0, wrapColumn);
      for (final String line : lines)
      {
        tool.err(line);
      }
      tool.err();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ReportBindResultLDAPConnectionPoolHealthCheck(" +
         "displaySuccessResultWithControls=");
    buffer.append(displaySuccessResultWithControls);
    buffer.append(", displaySuccessResultWithoutControls=");
    buffer.append(displaySuccessResultWithoutControls);
    buffer.append(')');
  }
}
