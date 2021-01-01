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
package com.unboundid.util;



import com.unboundid.ldap.sdk.Version;



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
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -805259180160427851L;



  /**
   * Creates a new instance of this exception with the provided message.
   *
   * @param  message  The message to use for this exception.
   */
  protected LDAPSDKRuntimeException(@NotNull final String message)
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
  protected LDAPSDKRuntimeException(@NotNull final String message,
                                    @Nullable final Throwable cause)
  {
    super(message, cause);
  }



  /**
   * Retrieves a string representation of this exception.
   *
   * @return  A string representation of this exception.
   */
  @Override()
  @NotNull()
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
  public void toString(@NotNull final StringBuilder buffer)
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
  @NotNull()
  public String getExceptionMessage()
  {
    final boolean includeCause =
         Boolean.getBoolean(Debug.PROPERTY_INCLUDE_CAUSE_IN_EXCEPTION_MESSAGES);
    final boolean includeStackTrace = Boolean.getBoolean(
         Debug.PROPERTY_INCLUDE_STACK_TRACE_IN_EXCEPTION_MESSAGES);

    return getExceptionMessage(includeCause, includeStackTrace);
  }



  /**
   * Retrieves a string representation of this exception suitable for use in
   * messages.
   *
   * @param  includeCause       Indicates whether to include information about
   *                            the cause (if any) in the exception message.
   * @param  includeStackTrace  Indicates whether to include a condensed
   *                            representation of the stack trace in the
   *                            exception message.
   *
   * @return  A string representation of this exception suitable for use in
   *          messages.
   */
  @NotNull()
  public String getExceptionMessage(final boolean includeCause,
                                    final boolean includeStackTrace)
  {
    final StringBuilder buffer = new StringBuilder();
    final String message = getMessage();
    if ((message == null) || message.isEmpty())
    {
      toString(buffer);
    }
    else
    {
      buffer.append(message);
    }

    if (includeStackTrace)
    {
      buffer.append(" stackTrace='");
      StaticUtils.getStackTrace(this, buffer);
    }
    else if (includeCause)
    {
      final Throwable cause = getCause();
      if (cause != null)
      {
        buffer.append(", cause=");
        buffer.append(StaticUtils.getExceptionMessage(cause));
      }
    }

    final String ldapSDKVersionString = ", ldapSDKVersion=" +
         Version.NUMERIC_VERSION_STRING + ", revision=" + Version.REVISION_ID;
    if (buffer.indexOf(ldapSDKVersionString) < 0)
    {
      buffer.append(ldapSDKVersionString);
    }

    return buffer.toString();
  }
}
