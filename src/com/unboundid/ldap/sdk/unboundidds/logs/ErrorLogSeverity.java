/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs;



import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum contains the set of error log severities defined in the Directory
 * Server.
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
public enum ErrorLogSeverity
{
  /**
   * The severity that will be used for messages providing debugging
   * information.
   */
  DEBUG,



  /**
   * The severity that will be used for fatal error messages, which indicate
   * that the server can no longer continue functioning normally.
   */
  FATAL_ERROR,


  /**
   * The severity that will be used for informational messages which may be
   * useful but generally do not need to be written to log files.
   */
  INFORMATION,



  /**
   * The severity that will be used for messages about errors that are small in
   * scope and do not generally impact the operation of the server.
   */
  MILD_ERROR,



  /**
   * The severity that will be used for warnings about conditions that do not
   * generally impact the operation of the server.
   */
  MILD_WARNING,


  /**
   * The severity that will be used for significant informational messages that
   * should generally be visible to administrators.
   */
  NOTICE,


  /**
   * The severity that will be used for messages about errors that may impact
   * the operation of the server or one of its components.
   */
  SEVERE_ERROR,


  /**
   * The severity that will be used for warning messages about conditions that
   * may impact the operation of the server or one of its components.
   */
  SEVERE_WARNING;



  /**
   * Retrieves the error log severity with the specified name.
   *
   * @param  name  The name of the error log severity to retrieve.  It must not
   *               be {@code null}.
   *
   * @return  The requested error log severity, or {@code null} if no such
   *          severity is defined.
   */
  @Nullable()
  public static ErrorLogSeverity forName(@NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "debug":
        return DEBUG;
      case "fatalerror":
      case "fatal-error":
      case "fatal_error":
        return FATAL_ERROR;
      case "information":
        return INFORMATION;
      case "milderror":
      case "mild-error":
      case "mild_error":
        return MILD_ERROR;
      case "mildwarning":
      case "mild-warning":
      case "mild_warning":
        return MILD_WARNING;
      case "notice":
        return NOTICE;
      case "severeerror":
      case "severe-error":
      case "severe_error":
        return SEVERE_ERROR;
      case "severewarning":
      case "severe-warning":
      case "severe_warning":
        return SEVERE_WARNING;
      default:
        return null;
    }
  }
}
