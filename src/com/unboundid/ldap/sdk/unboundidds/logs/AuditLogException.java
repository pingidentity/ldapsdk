/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.unboundid.util.LDAPSDKException;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class defines an exception that may be thrown if a problem occurs while
 * attempting to parse an audit log message.
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
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AuditLogException
       extends LDAPSDKException
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long  serialVersionUID = -3928437646247214211L;



  // The malformed log message that triggered this exception.
  private final List<String> logMessageLines;



  /**
   * Creates a new audit log exception with the provided information.
   *
   * @param  logMessageLines  A list of the lines that comprise the audit log
   *                          message.  It may be {@code null} but must not be
   *                          empty.
   * @param  explanation      A message explaining the problem that occurred.
   *                          It must not be {@code null}.
   */
  public AuditLogException(final List<String> logMessageLines,
                           final String explanation)
  {
    this(logMessageLines, explanation, null);
  }



  /**
   * Creates a new audit log exception with the provided information.
   *
   * @param  logMessageLines  A list of the lines that comprise the audit log
   *                          message.  It may be {@code null} but must not be
   *                          empty.
   * @param  explanation      A message explaining the problem that occurred.
   *                          It must not be {@code null}.
   * @param  cause            An underlying exception that triggered this
   *                          exception.
   */
  public AuditLogException(final List<String> logMessageLines,
                           final String explanation, final Throwable cause)
  {
    super(explanation, cause);

    Validator.ensureNotNull(logMessageLines);
    Validator.ensureNotNull(explanation);

    this.logMessageLines =
         Collections.unmodifiableList(new ArrayList<>(logMessageLines));
  }



  /**
   * Retrieves a list of the lines that comprise the audit log message that
   * triggered this exception.
   *
   * @return  A list of the lines that comprise the audit log message that
   *          triggered this exception, or an empty list if no log message lines
   *          are available.
   */
  public List<String> getLogMessageLines()
  {
    return logMessageLines;
  }
}
