/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.io.Serializable;

import com.unboundid.ldap.protocol.LDAPResponse;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a special instance of an LDAPResponse object that is used
 * as a marker to indicate that the connection has been closed while a response
 * listener was waiting for a response from the directory server.
 */
@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class ConnectionClosedResponse
      implements LDAPResponse, Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3931112652935496193L;



  // The result code that should be used for the closure.
  private final ResultCode resultCode;

  // A message providing additional information about the closure.
  private final String message;



  /**
   * Creates a new instance of this class.
   *
   * @param  resultCode  The result code that should be used for the closure.
   *                     It must not be {@code null}.
   * @param  message     The message that provides additional information about
   *                     the reason for the closure, or {@code null} if no
   *                     reason is available.
   */
  ConnectionClosedResponse(final ResultCode resultCode,
                           final String message)
  {
    this.resultCode = resultCode;
    this.message    = message;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int getMessageID()
  {
    return -1;
  }



  /**
   * Retrieves a message with additional information about the closure.
   *
   * @return  A message with additional information about the closure, or
   *          {@code null} if no such information is available.
   */
  String getMessage()
  {
    return message;
  }



  /**
   * Retrieves the result code that should be used for the closure.
   *
   * @return  The result code that should be used for the closure.
   */
  ResultCode getResultCode()
  {
    return resultCode;
  }



  /**
   * Retrieves a string representation of this connection closed response.
   *
   * @return  A string representation of this connection closed response.
   */
  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this connection closed response to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("ConnectionClosedResponse(resultCode='");
    buffer.append(resultCode);
    buffer.append('\'');

    if (message != null)
    {
      buffer.append(", message='");
      buffer.append(message);
      buffer.append('\'');
    }

    buffer.append(')');
  }
}
