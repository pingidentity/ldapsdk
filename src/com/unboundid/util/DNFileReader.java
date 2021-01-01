/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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



import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.text.ParseException;
import java.util.concurrent.atomic.AtomicLong;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides a mechanism for reading DNs from a file.  The file is
 * expected to have one DN per line.  Blank lines and lines beginning with the
 * octothorpe (#) character will be ignored.  Lines may contain just the raw DN,
 * or they may start with "dn:" followed by an optional space and the DN, or
 * "dn::" followed by an optional space and the base64-encoded representation of
 * the DN.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DNFileReader
       implements Closeable
{
  // A counter used to keep track of the line number for information read from
  // the file.
  @NotNull private final AtomicLong lineNumberCounter;

  // The reader to use to read the DNs.
  @NotNull private final BufferedReader reader;

  // The file from which the DNs are being read.
  @NotNull private final File dnFile;



  /**
   * Creates a new DN file reader that will read from the file with the
   * specified path.
   *
   * @param  path  The path to the file to be read.  It must not be {@code null}
   *               and the file must exist.
   *
   * @throws  IOException  If a problem is encountered while opening the file
   *                       for reading.
   */
  public DNFileReader(@NotNull final String path)
         throws IOException
  {
    this(new File(path));
  }



  /**
   * Creates a new DN file reader that will read from the specified file.
   *
   * @param  dnFile  The file to be read.  It must not be {@code null} and the
   *                 file must exist.
   *
   * @throws  IOException  If a problem is encountered while opening the file
   *                       for reading.
   */
  public DNFileReader(@NotNull final File dnFile)
         throws IOException
  {
    this.dnFile = dnFile;

    reader = new BufferedReader(new FileReader(dnFile));
    lineNumberCounter = new AtomicLong(0L);
  }



  /**
   * Reads the next DN from the file.
   *
   * @return  The DN read from the file, or {@code null} if there are no more
   *          DNs to be read.
   *
   * @throws  IOException  If a problem is encountered while trying to read from
   *                       the file.
   *
   * @throws  LDAPException  If data read from the file can't be parsed as a DN.
   */
  @Nullable()
  public DN readDN()
         throws IOException, LDAPException
  {
    while (true)
    {
      final long lineNumber;
      final String line;
      synchronized (this)
      {
        line = reader.readLine();
        lineNumber = lineNumberCounter.incrementAndGet();
      }

      if (line == null)
      {
        return null;
      }

      final String trimmedLine = line.trim();
      if (trimmedLine.isEmpty() || trimmedLine.startsWith("#"))
      {
        continue;
      }

      String dnString = trimmedLine;
      if (trimmedLine.charAt(2) == ':')
      {
        final String lowerLine = StaticUtils.toLowerCase(trimmedLine);
        if (lowerLine.startsWith("dn::"))
        {
          final String base64String = line.substring(4).trim();

          try
          {
            dnString = Base64.decodeToString(base64String);
          }
          catch (final ParseException pe)
          {
            Debug.debugException(pe);
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_DN_FILE_READER_CANNOT_BASE64_DECODE.get(base64String,
                      lineNumber, dnFile.getAbsolutePath(), pe.getMessage()),
                 pe);
          }
        }
        else if (lowerLine.startsWith("dn:"))
        {
          dnString = line.substring(3).trim();
        }
      }

      try
      {
        return new DN(dnString);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
             ERR_DN_FILE_READER_CANNOT_PARSE_DN.get(dnString, lineNumber,
                  dnFile.getAbsolutePath(), le.getMessage()),
             le);
      }
    }
  }



  /**
   * Closes this DN file reader.
   *
   * @throws  IOException  If a problem is encountered while closing the reader.
   */
  @Override()
  public void close()
         throws IOException
  {
    reader.close();
  }
}
