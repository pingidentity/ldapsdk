/*
 * Copyright 2018-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2018-2021 Ping Identity Corporation
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
 * Copyright (C) 2018-2021 Ping Identity Corporation
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



import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.FileReader;
import java.io.InputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;

import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.ldif.LDIFDeleteChangeRecord;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.ldif.LDIFModifyDNChangeRecord;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.logs.LogMessages.*;



/**
 * This class provides a mechanism for reading messages from a Directory Server
 * audit log.
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
public final class AuditLogReader
       implements Closeable
{
  // The reader used to read the contents of the log file.
  @NotNull private final BufferedReader reader;



  /**
   * Creates a new audit log reader that will read messages from the specified
   * log file.
   *
   * @param  path  The path of the log file to read.
   *
   * @throws  IOException  If a problem occurs while opening the file for
   *                       reading.
   */
  public AuditLogReader(@NotNull final String path)
         throws IOException
  {
    reader = new BufferedReader(new FileReader(path));
  }



  /**
   * Creates a new audit log reader that will read messages from the specified
   * log file.
   *
   * @param  file  The log file to read.
   *
   * @throws  IOException  If a problem occurs while opening the file for
   *                       reading.
   */
  public AuditLogReader(@NotNull final File file)
         throws IOException
  {
    reader = new BufferedReader(new FileReader(file));
  }



  /**
   * Creates a new audit log reader that will read messages using the provided
   * {@code Reader} object.
   *
   * @param  reader  The reader to use to read log messages.
   */
  public AuditLogReader(@NotNull final Reader reader)
  {
    if (reader instanceof BufferedReader)
    {
      this.reader = (BufferedReader) reader;
    }
    else
    {
      this.reader = new BufferedReader(reader);
    }
  }



  /**
   * Creates a new audit log reader that will read messages from the provided
   * input stream.
   *
   * @param  inputStream  The input stream from which to read log messages.
   */
  public AuditLogReader(@NotNull final InputStream inputStream)
  {
    reader = new BufferedReader(new InputStreamReader(inputStream));
  }



  /**
   * Reads the next audit log message from the log file.
   *
   * @return  The audit log message read from the log file, or {@code null} if
   *          there are no more messages to be read.
   *
   * @throws  IOException  If an error occurs while trying to read from the
   *                       file.
   *
   * @throws  AuditLogException  If an error occurs while trying to parse the
   *                             log message.
   */
  @Nullable()
  public AuditLogMessage read()
         throws IOException, AuditLogException
  {
    // Read a list of lines until we find the end of the file or a blank line
    // after a series of non-blank lines.
    final List<String> fullMessageLines = new ArrayList<>(20);
    final List<String> nonCommentLines = new ArrayList<>(20);
    while (true)
    {
      final String line = reader.readLine();
      if (line == null)
      {
        // We hit the end of the audit log file.  We obviously can't read any
        // more.
        break;
      }

      if (line.isEmpty())
      {
        if (nonCommentLines.isEmpty())
        {
          // This means that we encountered consecutive blank lines, or blank
          // lines with only comments between them.  This is okay.  We'll just
          // clear the list of full message lines and keep reading.
          fullMessageLines.clear();
          continue;
        }
        else
        {
          // We found a blank line after some non-blank lines that included at
          // least one non-comment line.  Break out of the loop and process what
          // we read as an audit log message.
          break;
        }
      }
      else
      {
        // We read a non-empty line.  Add it to the list of full message lines,
        // and if it's not a comment, then add it to the list of non-comment
        // lines.
        fullMessageLines.add(line);
        if (! line.startsWith("#"))
        {
          nonCommentLines.add(line);
        }
      }
    }


    // If we've gotten here and the list of non-comment lines is empty, then
    // that must mean that we hit the end of the audit log without finding any
    // more messages.  In that case, return null to indicate that we've hit the
    // end of the file.
    if (nonCommentLines.isEmpty())
    {
      return null;
    }


    // Try to parse the set of non-comment lines as an LDIF change record.  If
    // that fails, then throw a log exception.
    final LDIFChangeRecord changeRecord;
    try
    {
      final String[] ldifLines =
           StaticUtils.toArray(nonCommentLines, String.class);
      changeRecord = LDIFReader.decodeChangeRecord(ldifLines);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      final String concatenatedLogLines = StaticUtils.concatenateStrings(
           "[ ", "\"", ", ", "\"", " ]", fullMessageLines);
      throw new AuditLogException(fullMessageLines,
           ERR_AUDIT_LOG_READER_CANNOT_PARSE_CHANGE_RECORD.get(
                concatenatedLogLines, StaticUtils.getExceptionMessage(e)),
           e);
    }


    // Create the appropriate type of audit log message based on the change
    // record.
    if (changeRecord instanceof LDIFAddChangeRecord)
    {
      return new AddAuditLogMessage(fullMessageLines,
           (LDIFAddChangeRecord) changeRecord);
    }
    else if (changeRecord instanceof LDIFDeleteChangeRecord)
    {
      return new DeleteAuditLogMessage(fullMessageLines,
           (LDIFDeleteChangeRecord) changeRecord);
    }
    else if (changeRecord instanceof LDIFModifyChangeRecord)
    {
      return new ModifyAuditLogMessage(fullMessageLines,
           (LDIFModifyChangeRecord) changeRecord);
    }
    else if (changeRecord instanceof LDIFModifyDNChangeRecord)
    {
      return new ModifyDNAuditLogMessage(fullMessageLines,
           (LDIFModifyDNChangeRecord) changeRecord);
    }
    else
    {
      // This should never happen.
      final String concatenatedLogLines = StaticUtils.concatenateStrings(
           "[ ", "\"", ", ", "\"", " ]", fullMessageLines);
      throw new AuditLogException(fullMessageLines,
           ERR_AUDIT_LOG_READER_UNSUPPORTED_CHANGE_RECORD.get(
                concatenatedLogLines, changeRecord.getChangeType().getName()));
    }
  }



  /**
   * Closes this error log reader.
   *
   * @throws  IOException  If a problem occurs while closing the reader.
   */
  @Override()
  public void close()
         throws IOException
  {
    reader.close();
  }
}
