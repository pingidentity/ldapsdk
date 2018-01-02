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
package com.unboundid.util;



/**
 * This class provides a runtime exception that may be thrown by the LDAP SDK
 * if it detects a problem with the usage of the SDK itself (e.g., a
 * {@code null} value provided for an argument that must not be {@code null}, or
 * an argument value that violates a documented constraint).
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPSDKUsageException
       extends LDAPSDKRuntimeException
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4488711069492709961L;



  /**
   * Creates a new instance of this exception with the provided message.
   *
   * @param  message  The message to use for this exception.
   */
  public LDAPSDKUsageException(final String message)
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
  public LDAPSDKUsageException(final String message, final Throwable cause)
  {
    super(message, cause);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("LDAPSDKUsageException(message='");
    buffer.append(getMessage());
    buffer.append('\'');

    final Throwable cause = getCause();
    if (cause != null)
    {
      buffer.append(", cause=");
      buffer.append(StaticUtils.getExceptionMessage(cause));
    }

    buffer.append(')');
  }
}
