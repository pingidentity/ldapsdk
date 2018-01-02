/*
 * Copyright 2016-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2016-2018 Ping Identity Corporation
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
import java.util.concurrent.atomic.AtomicLong;

import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides a mechanism for reading LDAP search filters from a file.
 * The file is expected to have one filter per line.  Blank lines and lines
 * beginning with the octothorpe (#) character will be ignored.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class FilterFileReader
       implements Closeable
{
  // A counter used to keep track of the line number for information read from
  // the file.
  private final AtomicLong lineNumberCounter;

  // The reader to use to read the filters.
  private final BufferedReader reader;

  // The file from which the filters are being read.
  private final File filterFile;



  /**
   * Creates a new filter file reader that will read from the file with the
   * specified path.
   *
   * @param  path  The path to the file to be read.  It must not be {@code null}
   *               and the file must exist.
   *
   * @throws  IOException  If a problem is encountered while opening the file
   *                       for reading.
   */
  public FilterFileReader(final String path)
         throws IOException
  {
    this(new File(path));
  }



  /**
   * Creates a new filter file reader that will read from the specified file.
   *
   * @param  filterFile  The file to be read.  It must not be {@code null} and
   *                     the file must exist.
   *
   * @throws  IOException  If a problem is encountered while opening the file
   *                       for reading.
   */
  public FilterFileReader(final File filterFile)
         throws IOException
  {
    this.filterFile = filterFile;

    reader = new BufferedReader(new FileReader(filterFile));
    lineNumberCounter = new AtomicLong(0L);
  }



  /**
   * Reads the next filter from the file.
   *
   * @return  The filter read from the file, or {@code null} if there are no
   *          more filters to be read.
   *
   * @throws  IOException  If a problem is encountered while trying to read from
   *                       the file.
   *
   * @throws  LDAPException  If data read from the file can't be parsed as an
   *                         LDAP search filter.
   */
  public Filter readFilter()
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

      final String filterString = line.trim();
      if ((filterString.length() == 0) || filterString.startsWith("#"))
      {
        continue;
      }

      try
      {
        return Filter.create(filterString);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        throw new LDAPException(ResultCode.FILTER_ERROR,
             ERR_FILTER_FILE_READER_CANNOT_PARSE_FILTER.get(filterString,
                  lineNumber, filterFile.getAbsolutePath(), le.getMessage()),
             le);
      }
    }
  }



  /**
   * Closes this filter file reader.
   *
   * @throws  IOException  If a problem is encountered while closing the reader.
   */
  public void close()
         throws IOException
  {
    reader.close();
  }
}
