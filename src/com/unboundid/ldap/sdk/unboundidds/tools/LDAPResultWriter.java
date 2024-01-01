/*
 * Copyright 2017-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2024 Ping Identity Corporation
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
 * Copyright (C) 2017-2024 Ping Identity Corporation
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



import java.io.OutputStream;
import java.io.PrintStream;

import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an API that may be implemented by classes that format
 * and output the results for LDAP-related tools.
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
@InternalUseOnly()
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public abstract class LDAPResultWriter
{
  // The print stream
  @NotNull private volatile PrintStream printStream;



  /**
   * Creates a new LDAP result writer that will write to the provided output
   * stream.
   *
   * @param  outputStream  The output stream to which the output will be
   *                       written.  It must not be {@code null}.
   */
  protected LDAPResultWriter(@NotNull final OutputStream outputStream)
  {
    printStream = getPrintStream(outputStream);
  }



  /**
   * Updates the output stream to which output will be written.
   *
   * @param  outputStream  The output stream to which the output will be
   *                       written.  It must not be {@code null}.
   */
  public final void updateOutputStream(@NotNull final OutputStream outputStream)
  {
    printStream = getPrintStream(outputStream);
  }



  /**
   * Retrieves a {@code PrintStream} that wraps the provided
   * {@code OutputStream}.  If the given stream is already a
   * {@code PrintStream}, then that stream will be returned without creating a
   * new object.
   *
   * @param  outputStream  The output stream to be wrapped by a print stream
   *                       (or to be returned directly if it is already a print
   *                       stream).  It must not be {@code null}.
   *
   * @return  The print stream for the provided output stream.
   */
  @NotNull()
  private static PrintStream getPrintStream(
               @NotNull final OutputStream outputStream)
  {
    if (outputStream instanceof PrintStream)
    {
      return (PrintStream) outputStream;
    }
    else
    {
      return new PrintStream(outputStream);
    }
  }



  /**
   * Writes a blank line to the associated print stream.
   */
  protected void println()
  {
    printStream.println();
  }



  /**
   * Writes the provided string to the associated print stream without a
   * subsequent newline.
   *
   * @param  string  The string to be written.  It must not be {@code null}.
   */
  protected void print(@NotNull final String string)
  {
    printStream.print(string);
  }



  /**
   * Writes the provided string to the associated print stream with a subsequent
   * newline.
   *
   * @param  string  The string to be written.  It must not be {@code null}.
   */
  protected void println(@NotNull final String string)
  {
    printStream.println(string);
  }



  /**
   * Retrieves the print stream that may be used to write output.
   *
   * @return  The print stream that may be used to write output.
   */
  @NotNull()
  protected final PrintStream getPrintStream()
  {
    return printStream;
  }



  /**
   * Flushes any buffered output.
   */
  public final void flush()
  {
    printStream.flush();
  }



  /**
   * Writes the provided comment to the output.
   *
   * @param  comment  The comment to be written.  It must not be {@code null}.
   */
  public abstract void writeComment(@NotNull final String comment);



  /**
   * Formats and writes a header that describes the way in which the data will
   * be formatted.  This will be displayed at the beginning of the output
   * (including at the beginning of each file, if output should be spread
   * across multiple files).
   */
  public abstract void writeHeader();



  /**
   * Formats and writes the provided search result entry.
   *
   * @param  entry  The search result entry to be processed.
   */
  public abstract void writeSearchResultEntry(
              @NotNull SearchResultEntry entry);



  /**
   * Formats and writes the provided search result reference.
   *
   * @param  ref  The search result reference to be processed.
   */
  public abstract void writeSearchResultReference(
              @NotNull SearchResultReference ref);



  /**
   * Formats and writes the provided LDAP result.
   *
   * @param  result  The LDAP result to be processed.  It may or may not be a
   *                 search result.
   */
  public abstract void writeResult(@NotNull LDAPResult result);



  /**
   * Formats and writes the provided unsolicited notification.
   *
   * @param  connection    The connection on which the unsolicited notification
   *                       was received.
   * @param  notification  The unsolicited notification that was received.
   */
  public abstract void writeUnsolicitedNotification(
              @NotNull LDAPConnection connection,
              @NotNull ExtendedResult notification);
}
