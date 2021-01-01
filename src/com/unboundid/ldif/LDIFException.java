/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
package com.unboundid.ldif;



import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import com.unboundid.ldap.sdk.Version;
import com.unboundid.util.Debug;
import com.unboundid.util.LDAPSDKException;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class defines an exception that may be thrown if a problem occurs while
 * attempting to decode data read from an LDIF source.  It has a flag to
 * indicate whether it is possible to try to continue reading additional
 * information from the LDIF source, and also the approximate line number on
 * which the problem was encountered.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDIFException
       extends LDAPSDKException
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1665883395956836732L;



  // Indicates whether it is possible to continue attempting to read from the
  // LDIF source.
  private final boolean mayContinueReading;

  // The line number in the LDIF source on which the problem occurred.
  private final long lineNumber;

  // A list of the lines comprising the LDIF data being parsed, if available.
  @Nullable private final List<String> dataLines;



  /**
   * Creates a new LDIF exception with the provided information.
   *
   * @param  message             A message explaining the problem that occurred.
   *                             It must not be {@code null}.
   * @param  lineNumber          The line number in the LDIF source on which the
   *                             problem occurred.
   * @param  mayContinueReading  Indicates whether it is possible to continue
   *                             attempting to read from the LDIF source.
   */
  public LDIFException(@NotNull final String message, final long lineNumber,
                       final boolean mayContinueReading)
  {
    this(message, lineNumber, mayContinueReading, (List<CharSequence>) null,
         null);
  }



  /**
   * Creates a new LDIF exception with the provided information.
   *
   * @param  message             A message explaining the problem that occurred.
   *                             It must not be {@code null}.
   * @param  lineNumber          The line number in the LDIF source on which the
   *                             problem occurred.
   * @param  mayContinueReading  Indicates whether it is possible to continue
   *                             attempting to read from the LDIF source.
   * @param  cause               The underlying exception that triggered this
   *                             exception.
   */
  public LDIFException(@NotNull final String message, final long lineNumber,
                       final boolean mayContinueReading,
                       @Nullable final Throwable cause)
  {
    this(message, lineNumber, mayContinueReading, (List<CharSequence>) null,
         cause);
  }



  /**
   * Creates a new LDIF exception with the provided information.
   *
   * @param  message             A message explaining the problem that occurred.
   *                             It must not be {@code null}.
   * @param  lineNumber          The line number in the LDIF source on which the
   *                             problem occurred.
   * @param  mayContinueReading  Indicates whether it is possible to continue
   *                             attempting to read from the LDIF source.
   * @param  dataLines           The lines that comprise the data that could not
   *                             be parsed as valid LDIF.  It may be
   *                             {@code null} if this is not available.
   * @param  cause               The underlying exception that triggered this
   *                             exception.
   */
  public LDIFException(@NotNull final String message, final long lineNumber,
                       final boolean mayContinueReading,
                       @Nullable final CharSequence[] dataLines,
                       @Nullable final Throwable cause)
  {
    this(message, lineNumber, mayContinueReading,
         (dataLines == null) ? null : Arrays.asList(dataLines),
         cause);
  }



  /**
   * Creates a new LDIF exception with the provided information.
   *
   * @param  message             A message explaining the problem that occurred.
   *                             It must not be {@code null}.
   * @param  lineNumber          The line number in the LDIF source on which the
   *                             problem occurred.
   * @param  mayContinueReading  Indicates whether it is possible to continue
   *                             attempting to read from the LDIF source.
   * @param  dataLines           The lines that comprise the data that could not
   *                             be parsed as valid LDIF.  It may be
   *                             {@code null} if this is not available.
   * @param  cause               The underlying exception that triggered this
   *                             exception.
   */
  public LDIFException(@NotNull final String message, final long lineNumber,
                       final boolean mayContinueReading,
                       @Nullable final List<? extends CharSequence> dataLines,
                       @Nullable final Throwable cause)
  {
    super(message, cause);

    Validator.ensureNotNull(message);

    this.lineNumber         = lineNumber;
    this.mayContinueReading = mayContinueReading;

    if (dataLines == null)
    {
      this.dataLines = null;
    }
    else
    {
      final ArrayList<String> lineList = new ArrayList<>(dataLines.size());
      for (final CharSequence s : dataLines)
      {
        lineList.add(s.toString());
      }

      this.dataLines = Collections.unmodifiableList(lineList);
    }
  }



  /**
   * Retrieves the line number on which the problem occurred.
   *
   * @return  The line number on which the problem occurred.
   */
  public long getLineNumber()
  {
    return lineNumber;
  }



  /**
   * Indicates whether it is possible to continue attempting to read from the
   * LDIF source.
   *
   * @return  {@code true} if it is possible to continue attempting to read from
   *          the LDIF source, or {@code false} if it is not possible to
   *          continue.
   */
  public boolean mayContinueReading()
  {
    return mayContinueReading;
  }



  /**
   * Retrieves the lines comprising the data that could not be parsed as valid
   * LDIF, if available.
   *
   * @return  An unmodifiable list of the lines comprising the data that could
   *          not be parsed as valid LDIF, or {@code null} if that is not
   *          available.
   */
  @Nullable()
  public List<String> getDataLines()
  {
    return dataLines;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    final boolean includeCause =
         Boolean.getBoolean(Debug.PROPERTY_INCLUDE_CAUSE_IN_EXCEPTION_MESSAGES);
    final boolean includeStackTrace = Boolean.getBoolean(
         Debug.PROPERTY_INCLUDE_STACK_TRACE_IN_EXCEPTION_MESSAGES);

    toString(buffer, includeCause, includeStackTrace);
  }



  /**
   * Appends a string representation of this {@code LDIFException} to the
   * provided buffer.
   *
   * @param  buffer             The buffer to which the information should be
   *                            appended.  This must not be {@code null}.
   * @param  includeCause       Indicates whether to include information about
   *                            the cause (if any) in the exception message.
   * @param  includeStackTrace  Indicates whether to include a condensed
   *                            representation of the stack trace in the
   *                            exception message.  If a stack trace is
   *                            included, then the cause (if any) will
   *                            automatically be included, regardless of the
   *                            value of the {@code includeCause} argument.
   */
  public void toString(@NotNull final StringBuilder buffer,
                       final boolean includeCause,
                       final boolean includeStackTrace)
  {
    buffer.append("LDIFException(lineNumber=");
    buffer.append(lineNumber);
    buffer.append(", mayContinueReading=");
    buffer.append(mayContinueReading);
    buffer.append(", message='");
    buffer.append(getMessage());

    if (dataLines != null)
    {
      buffer.append("', dataLines='");
      for (final CharSequence s : dataLines)
      {
        buffer.append(s);
        buffer.append("{end-of-line}");
      }
    }

    if (includeStackTrace)
    {
      buffer.append(", trace='");
      StaticUtils.getStackTrace(getStackTrace(), buffer);
      buffer.append('\'');
    }

    if (includeCause || includeStackTrace)
    {
      final Throwable cause = getCause();
      if (cause != null)
      {
        buffer.append(", cause=");
        buffer.append(StaticUtils.getExceptionMessage(cause, true,
             includeStackTrace));
      }
    }

    final String ldapSDKVersionString = ", ldapSDKVersion=" +
         Version.NUMERIC_VERSION_STRING + ", revision=" + Version.REVISION_ID;
    if (buffer.indexOf(ldapSDKVersionString) < 0)
    {
      buffer.append(ldapSDKVersionString);
    }

    buffer.append(')');
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExceptionMessage()
  {
    return toString();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExceptionMessage(final boolean includeCause,
                                    final boolean includeStackTrace)
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer, includeCause, includeStackTrace);
    return buffer.toString();
  }
}
