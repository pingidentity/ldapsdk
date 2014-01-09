/*
 * Copyright 2009-2014 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2014 UnboundID Corp.
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
package com.unboundid.util;



/**
 * This class serves as the base class for all custom runtime exception types
 * defined in the LDAP SDK.
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public abstract class LDAPSDKRuntimeException
       extends RuntimeException
{
  /**
   * Creates a new instance of this exception with the provided message.
   *
   * @param  message  The message to use for this exception.
   */
  protected LDAPSDKRuntimeException(final String message)
  {
    super(message);
  }



  /**
   * Creates a new instance of this exception with the provided message and
   * cause.
   *
   * @param  message  The message to use for this exception.
   * @param  cause    The underlying cause for this exception.  It may be
   *                  {@code null} if no cause is available.
   */
  protected LDAPSDKRuntimeException(final String message, final Throwable cause)
  {
    super(message, cause);
  }



  /**
   * Retrieves a string representation of this exception.
   *
   * @return  A string representation of this exception.
   */
  @Override()
  public final String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this exception to the provided buffer.
   *
   * @param  buffer  The buffer to which the string representation of this
   *                 exception is to be appended.
   */
  public void toString(final StringBuilder buffer)
  {
    buffer.append(super.toString());
  }



  /**
   * Retrieves a string representation of this exception suitable for use in
   * messages.
   *
   * @return  A string representation of this exception suitable for use in
   *          messages.
   */
  public String getExceptionMessage()
  {
    final String message = getMessage();
    if (message == null)
    {
      return toString();
    }
    else
    {
      return message;
    }
  }
}
