/*
 * Copyright 2013-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2017 UnboundID Corp.
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



import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about a log
 * message that may appear in the Directory Server access log about the result
 * of replication assurance processing for an add operation.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class is part of the Commercial Edition of the UnboundID
 *   LDAP SDK for Java.  It is not available for use in applications that
 *   include only the Standard Edition of the LDAP SDK, and is not supported for
 *   use in conjunction with non-UnboundID products.
 * </BLOCKQUOTE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AddAssuranceCompletedAccessLogMessage
       extends AddResultAccessLogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1941067013045984669L;



  // Indicates whether the local assurance requirement was satisfied.
  private final Boolean localAssuranceSatisfied;

  // Indicates whether the remote assurance requirement was satisfied.
  private final Boolean remoteAssuranceSatisfied;

  // A string with information about the per-server assurance results.
  private final String serverAssuranceResults;



  /**
   * Creates a new add assurance complete access log message from the provided
   * message string.
   *
   * @param  s  The string to be parsed as an add assurance complete access log
   *            message.
   *
   * @throws  LogException  If the provided string cannot be parsed as a valid
   *                        log message.
   */
  public AddAssuranceCompletedAccessLogMessage(final String s)
         throws LogException
  {
    this(new LogMessage(s));
  }



  /**
   * Creates a new add assurance complete access log message from the provided
   * message string.
   *
   * @param  m  The log message to be parsed as an add assurance complete access
   *            log message.
   */
  public AddAssuranceCompletedAccessLogMessage(final LogMessage m)
  {
    super(m);

    localAssuranceSatisfied = getNamedValueAsBoolean("localAssuranceSatisfied");
    remoteAssuranceSatisfied =
         getNamedValueAsBoolean("remoteAssuranceSatisfied");
    serverAssuranceResults = getNamedValue("serverAssuranceResults");
  }



  /**
   * Indicates whether the local assurance requirement was satisfied.
   *
   * @return  {@code true} if the local assurance requirement was satisfied,
   *          {@code false} if the local assurance requirement was not
   *          satisfied, or {@code null} if it was not included in the log
   *          message.
   */
  public Boolean getLocalAssuranceSatisfied()
  {
    return localAssuranceSatisfied;
  }



  /**
   * Indicates whether the remote assurance requirement was satisfied.
   *
   * @return  {@code true} if the remote assurance requirement was satisfied,
   *          {@code false} if the remote assurance requirement was not
   *          satisfied, or {@code null} if it was not included in the log
   *          message.
   */
  public Boolean getRemoteAssuranceSatisfied()
  {
    return remoteAssuranceSatisfied;
  }



  /**
   * Retrieves information about the assurance processing performed by
   * individual servers in the replication environment.
   *
   * @return  Information about the assurance processing performed by
   *          individual servers in the replication environment, or
   *          {@code null} if it was not included in the log message.
   */
  public String getServerAssuranceResults()
  {
    return serverAssuranceResults;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public AccessLogMessageType getMessageType()
  {
    return AccessLogMessageType.ASSURANCE_COMPLETE;
  }
}
