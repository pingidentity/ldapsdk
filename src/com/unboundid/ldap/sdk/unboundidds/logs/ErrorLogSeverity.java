/*
 * Copyright 2009-2016 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2016 UnboundID Corp.
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



import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum contains the set of error log severities defined in the Directory
 * Server.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class is part of the Commercial Edition of the UnboundID
 *   LDAP SDK for Java.  It is not available for use in applications that
 *   include only the Standard Edition of the LDAP SDK, and is not supported for
 *   use in conjunction with non-UnboundID products.
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
  SEVERE_WARNING
}
