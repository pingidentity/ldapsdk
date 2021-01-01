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



import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.nio.charset.Charset;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.matchingrules.CaseIgnoreStringMatchingRule;
import com.unboundid.ldap.matchingrules.MatchingRule;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.AggregateInputStream;
import com.unboundid.util.Base64;
import com.unboundid.util.Debug;
import com.unboundid.util.LDAPSDKThreadFactory;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;
import com.unboundid.util.parallel.AsynchronousParallelProcessor;
import com.unboundid.util.parallel.Result;
import com.unboundid.util.parallel.ParallelProcessor;
import com.unboundid.util.parallel.Processor;

import static com.unboundid.ldif.LDIFMessages.*;

/**
 * This class provides an LDIF reader, which can be used to read and decode
 * entries and change records from a data source using the LDAP Data Interchange
 * Format as per <A HREF="http://www.ietf.org/rfc/rfc2849.txt">RFC 2849</A>.
 * <BR>
 * This class is not synchronized.  If multiple threads read from the
 * LDIFReader, they must be synchronized externally.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example iterates through all entries contained in an LDIF file
 * and attempts to add them to a directory server:
 * <PRE>
 * LDIFReader ldifReader = new LDIFReader(pathToLDIFFile);
 *
 * int entriesRead = 0;
 * int entriesAdded = 0;
 * int errorsEncountered = 0;
 * while (true)
 * {
 *   Entry entry;
 *   try
 *   {
 *     entry = ldifReader.readEntry();
 *     if (entry == null)
 *     {
 *       // All entries have been read.
 *       break;
 *     }
 *
 *     entriesRead++;
 *   }
 *   catch (LDIFException le)
 *   {
 *     errorsEncountered++;
 *     if (le.mayContinueReading())
 *     {
 *       // A recoverable error occurred while attempting to read a change
 *       // record, at or near line number le.getLineNumber()
 *       // The entry will be skipped, but we'll try to keep reading from the
 *       // LDIF file.
 *       continue;
 *     }
 *     else
 *     {
 *       // An unrecoverable error occurred while attempting to read an entry
 *       // at or near line number le.getLineNumber()
 *       // No further LDIF processing will be performed.
 *       break;
 *     }
 *   }
 *   catch (IOException ioe)
 *   {
 *     // An I/O error occurred while attempting to read from the LDIF file.
 *     // No further LDIF processing will be performed.
 *     errorsEncountered++;
 *     break;
 *   }
 *
 *   LDAPResult addResult;
 *   try
 *   {
 *     addResult = connection.add(entry);
 *     // If we got here, then the change should have been processed
 *     // successfully.
 *     entriesAdded++;
 *   }
 *   catch (LDAPException le)
 *   {
 *     // If we got here, then the change attempt failed.
 *     addResult = le.toLDAPResult();
 *     errorsEncountered++;
 *   }
 * }
 *
 * ldifReader.close();
 * </PRE>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class LDIFReader
       implements Closeable
{
  /**
   * The default buffer size (128KB) that will be used when reading from the
   * data source.
   */
  public static final int DEFAULT_BUFFER_SIZE = 128 * 1024;



  /*
   * When processing asynchronously, this determines how many of the allocated
   * worker threads are used to parse each batch of read entries.
   */
  private static final int ASYNC_MIN_PER_PARSING_THREAD = 3;



  /**
   * When processing asynchronously, this specifies the size of the pending and
   * completed queues.
   */
  private static final int ASYNC_QUEUE_SIZE = 500;



  /**
   * Special entry used internally to signal that the LDIFReaderEntryTranslator
   * has signalled that a read Entry should be skipped by returning null,
   * which normally implies EOF.
   */
  @NotNull private static final Entry SKIP_ENTRY = new Entry("cn=skipped");



  /**
   * The default base path that will be prepended to relative paths.  It will
   * end with a trailing slash.
   */
  @NotNull private static final String DEFAULT_RELATIVE_BASE_PATH;
  static
  {
    final File currentDir;
    final String currentDirString = StaticUtils.getSystemProperty("user.dir");
    if (currentDirString == null)
    {
      currentDir = new File(".");
    }
    else
    {
      currentDir = new File(currentDirString);
    }

    final String currentDirAbsolutePath = currentDir.getAbsolutePath();
    if (currentDirAbsolutePath.endsWith(File.separator))
    {
      DEFAULT_RELATIVE_BASE_PATH = currentDirAbsolutePath;
    }
    else
    {
      DEFAULT_RELATIVE_BASE_PATH = currentDirAbsolutePath + File.separator;
    }
  }



  // The buffered reader that will be used to read LDIF data.
  @NotNull private final BufferedReader reader;

  // The behavior that should be exhibited when encountering duplicate attribute
  // values.
  @NotNull private volatile DuplicateValueBehavior duplicateValueBehavior;

  // A line number counter.
  private long lineNumberCounter = 0;

  // The change record translator to use, if any.
  @Nullable private final LDIFReaderChangeRecordTranslator
       changeRecordTranslator;

  // The entry translator to use, if any.
  @Nullable private final LDIFReaderEntryTranslator entryTranslator;

  // The schema that will be used when processing, if applicable.
  @Nullable private Schema schema;

  // Specifies the base path that will be prepended to relative paths for file
  // URLs.
  @NotNull private volatile String relativeBasePath;

  // The behavior that should be exhibited with regard to illegal trailing
  // spaces in attribute values.
  @NotNull private volatile TrailingSpaceBehavior trailingSpaceBehavior;

  // True iff we are processing asynchronously.
  private final boolean isAsync;

  //
  // The following only apply to asynchronous processing.
  //

  // Parses entries asynchronously.
  @Nullable private final
       AsynchronousParallelProcessor<UnparsedLDIFRecord,LDIFRecord> asyncParser;

  // Set to true when the end of the input is reached.
  @Nullable private final AtomicBoolean asyncParsingComplete;

  // The records that have been read and parsed.
  @Nullable private final BlockingQueue<Result<UnparsedLDIFRecord,LDIFRecord>>
       asyncParsedRecords;



  /**
   * Creates a new LDIF reader that will read data from the specified file.
   *
   * @param  path  The path to the file from which the data is to be read.  It
   *               must not be {@code null}.
   *
   * @throws  IOException  If a problem occurs while opening the file for
   *                       reading.
   */
  public LDIFReader(@NotNull final String path)
         throws IOException
  {
    this(new FileInputStream(path));
  }



  /**
   * Creates a new LDIF reader that will read data from the specified file
   * and parses the LDIF records asynchronously using the specified number of
   * threads.
   *
   * @param  path  The path to the file from which the data is to be read.  It
   *               must not be {@code null}.
   * @param  numParseThreads  If this value is greater than zero, then the
   *                          specified number of threads will be used to
   *                          asynchronously read and parse the LDIF file.
   *
   * @throws  IOException  If a problem occurs while opening the file for
   *                       reading.
   *
   * @see #LDIFReader(BufferedReader, int, LDIFReaderEntryTranslator)
   *      constructor for more details about asynchronous processing.
   */
  public LDIFReader(@NotNull final String path, final int numParseThreads)
         throws IOException
  {
    this(new FileInputStream(path), numParseThreads);
  }



  /**
   * Creates a new LDIF reader that will read data from the specified file.
   *
   * @param  file  The file from which the data is to be read.  It must not be
   *               {@code null}.
   *
   * @throws  IOException  If a problem occurs while opening the file for
   *                       reading.
   */
  public LDIFReader(@NotNull final File file)
         throws IOException
  {
    this(new FileInputStream(file));
  }



  /**
   * Creates a new LDIF reader that will read data from the specified file
   * and optionally parses the LDIF records asynchronously using the specified
   * number of threads.
   *
   * @param  file             The file from which the data is to be read.  It
   *                          must not be {@code null}.
   * @param  numParseThreads  If this value is greater than zero, then the
   *                          specified number of threads will be used to
   *                          asynchronously read and parse the LDIF file.
   *
   * @throws  IOException  If a problem occurs while opening the file for
   *                       reading.
   */
  public LDIFReader(@NotNull final File file, final int numParseThreads)
         throws IOException
  {
    this(new FileInputStream(file), numParseThreads);
  }



  /**
   * Creates a new LDIF reader that will read data from the specified files in
   * the order in which they are provided and optionally parses the LDIF records
   * asynchronously using the specified number of threads.
   *
   * @param  files            The files from which the data is to be read.  It
   *                          must not be {@code null} or empty.
   * @param  numParseThreads  If this value is greater than zero, then the
   *                          specified number of threads will be used to
   *                          asynchronously read and parse the LDIF file.
   * @param entryTranslator   The LDIFReaderEntryTranslator to apply to entries
   *                          before they are returned.  This is normally
   *                          {@code null}, which causes entries to be returned
   *                          unaltered. This is particularly useful when
   *                          parsing the input file in parallel because the
   *                          entry translation is also done in parallel.
   *
   * @throws  IOException  If a problem occurs while opening the file for
   *                       reading.
   */
  public LDIFReader(@NotNull final File[] files, final int numParseThreads,
                    @Nullable final LDIFReaderEntryTranslator entryTranslator)
         throws IOException
  {
    this(files, numParseThreads, entryTranslator, null);
  }



  /**
   * Creates a new LDIF reader that will read data from the specified files in
   * the order in which they are provided and optionally parses the LDIF records
   * asynchronously using the specified number of threads.
   *
   * @param  files                   The files from which the data is to be
   *                                 read.  It must not be {@code null} or
   *                                 empty.
   * @param  numParseThreads         If this value is greater than zero, then
   *                                 the specified number of threads will be
   *                                 used to asynchronously read and parse the
   *                                 LDIF file.
   * @param  entryTranslator         The LDIFReaderEntryTranslator to apply to
   *                                 entries before they are returned.  This is
   *                                 normally {@code null}, which causes entries
   *                                 to be returned unaltered.  This is
   *                                 particularly useful when parsing the input
   *                                 file in parallel because the entry
   *                                 translation is also done in parallel.
   * @param  changeRecordTranslator  The LDIFReaderChangeRecordTranslator to
   *                                 apply to change records before they are
   *                                 returned.  This is normally {@code null},
   *                                 which causes change records to be returned
   *                                 unaltered.  This is particularly useful
   *                                 when parsing the input file in parallel
   *                                 because the change record translation is
   *                                 also done in parallel.
   *
   * @throws  IOException  If a problem occurs while opening the file for
   *                       reading.
   */
  public LDIFReader(@NotNull final File[] files, final int numParseThreads,
       @Nullable final LDIFReaderEntryTranslator entryTranslator,
       @Nullable final LDIFReaderChangeRecordTranslator changeRecordTranslator)
       throws IOException
  {
    this(files, numParseThreads, entryTranslator, changeRecordTranslator,
         "UTF-8");
  }



  /**
   * Creates a new LDIF reader that will read data from the specified files in
   * the order in which they are provided and optionally parses the LDIF records
   * asynchronously using the specified number of threads.
   *
   * @param  files                   The files from which the data is to be
   *                                 read.  It must not be {@code null} or
   *                                 empty.
   * @param  numParseThreads         If this value is greater than zero, then
   *                                 the specified number of threads will be
   *                                 used to asynchronously read and parse the
   *                                 LDIF file.
   * @param  entryTranslator         The LDIFReaderEntryTranslator to apply to
   *                                 entries before they are returned.  This is
   *                                 normally {@code null}, which causes entries
   *                                 to be returned unaltered.  This is
   *                                 particularly useful when parsing the input
   *                                 file in parallel because the entry
   *                                 translation is also done in parallel.
   * @param  changeRecordTranslator  The LDIFReaderChangeRecordTranslator to
   *                                 apply to change records before they are
   *                                 returned.  This is normally {@code null},
   *                                 which causes change records to be returned
   *                                 unaltered.  This is particularly useful
   *                                 when parsing the input file in parallel
   *                                 because the change record translation is
   *                                 also done in parallel.
   * @param  characterSet            The character set to use when reading from
   *                                 the input stream.  It must not be
   *                                 {@code null}.
   *
   * @throws  IOException  If a problem occurs while opening the file for
   *                       reading.
   */
  public LDIFReader(@NotNull final File[] files, final int numParseThreads,
       @Nullable final LDIFReaderEntryTranslator entryTranslator,
       @Nullable final LDIFReaderChangeRecordTranslator changeRecordTranslator,
       @NotNull final String characterSet)
       throws IOException
  {
    this(createAggregateInputStream(files), numParseThreads, entryTranslator,
         changeRecordTranslator, characterSet);
  }



  /**
   * Creates a new aggregate input stream that will read data from the specified
   * files.  If there are multiple files, then a "padding" file will be inserted
   * between them to ensure that there is at least one blank line between the
   * end of one file and the beginning of another.
   *
   * @param  files  The files from which the data is to be read.  It must not be
   *                {@code null} or empty.
   *
   * @return  The input stream to use to read data from the provided files.
   *
   * @throws  IOException  If a problem is encountered while attempting to
   *                       create the input stream.
   */
  @NotNull()
  private static InputStream createAggregateInputStream(
                                  @NotNull final File... files)
          throws IOException
  {
    if (files.length == 0)
    {
      throw new IOException(ERR_READ_NO_LDIF_FILES.get());
    }
    else
    {
      return new AggregateInputStream(true, files);
    }
  }



  /**
   * Creates a new LDIF reader that will read data from the provided input
   * stream.
   *
   * @param  inputStream  The input stream from which the data is to be read.
   *                      It must not be {@code null}.
   */
  public LDIFReader(@NotNull final InputStream inputStream)
  {
    this(inputStream, 0);
  }



  /**
   * Creates a new LDIF reader that will read data from the specified stream
   * and parses the LDIF records asynchronously using the specified number of
   * threads.
   *
   * @param  inputStream  The input stream from which the data is to be read.
   *                      It must not be {@code null}.
   * @param  numParseThreads  If this value is greater than zero, then the
   *                          specified number of threads will be used to
   *                          asynchronously read and parse the LDIF file.
   *
   * @see #LDIFReader(BufferedReader, int, LDIFReaderEntryTranslator)
   *      constructor for more details about asynchronous processing.
   */
  public LDIFReader(@NotNull final InputStream inputStream,
                    final int numParseThreads)
  {
    // UTF-8 is required by RFC 2849.  Java guarantees it's always available.
    this(new BufferedReader(
         new InputStreamReader(inputStream, StandardCharsets.UTF_8),
              DEFAULT_BUFFER_SIZE),
         numParseThreads);
  }



  /**
   * Creates a new LDIF reader that will read data from the specified stream
   * and parses the LDIF records asynchronously using the specified number of
   * threads.
   *
   * @param  inputStream  The input stream from which the data is to be read.
   *                      It must not be {@code null}.
   * @param  numParseThreads  If this value is greater than zero, then the
   *                          specified number of threads will be used to
   *                          asynchronously read and parse the LDIF file.
   * @param entryTranslator  The LDIFReaderEntryTranslator to apply to read
   *                         entries before they are returned.  This is normally
   *                         {@code null}, which causes entries to be returned
   *                         unaltered. This is particularly useful when parsing
   *                         the input file in parallel because the entry
   *                         translation is also done in parallel.
   *
   * @see #LDIFReader(BufferedReader, int, LDIFReaderEntryTranslator)
   *      constructor for more details about asynchronous processing.
   */
  public LDIFReader(@NotNull final InputStream inputStream,
                    final int numParseThreads,
                    @Nullable final LDIFReaderEntryTranslator entryTranslator)
  {
    this(inputStream, numParseThreads, entryTranslator, null);
  }



  /**
   * Creates a new LDIF reader that will read data from the specified stream
   * and parses the LDIF records asynchronously using the specified number of
   * threads.
   *
   * @param  inputStream             The input stream from which the data is to
   *                                 be read.  It must not be {@code null}.
   * @param  numParseThreads         If this value is greater than zero, then
   *                                 the specified number of threads will be
   *                                 used to asynchronously read and parse the
   *                                 LDIF file.
   * @param  entryTranslator         The LDIFReaderEntryTranslator to apply to
   *                                 entries before they are returned.  This is
   *                                 normally {@code null}, which causes entries
   *                                 to be returned unaltered.  This is
   *                                 particularly useful when parsing the input
   *                                 file in parallel because the entry
   *                                 translation is also done in parallel.
   * @param  changeRecordTranslator  The LDIFReaderChangeRecordTranslator to
   *                                 apply to change records before they are
   *                                 returned.  This is normally {@code null},
   *                                 which causes change records to be returned
   *                                 unaltered.  This is particularly useful
   *                                 when parsing the input file in parallel
   *                                 because the change record translation is
   *                                 also done in parallel.
   *
   * @see #LDIFReader(BufferedReader, int, LDIFReaderEntryTranslator)
   *      constructor for more details about asynchronous processing.
   */
  public LDIFReader(@NotNull final InputStream inputStream,
       final int numParseThreads,
       @Nullable final LDIFReaderEntryTranslator entryTranslator,
       @Nullable final LDIFReaderChangeRecordTranslator changeRecordTranslator)
  {
    // UTF-8 is required by RFC 2849.  Java guarantees it's always available.
    this(inputStream, numParseThreads, entryTranslator, changeRecordTranslator,
         "UTF-8");
  }



  /**
   * Creates a new LDIF reader that will read data from the specified stream
   * and parses the LDIF records asynchronously using the specified number of
   * threads.
   *
   * @param  inputStream             The input stream from which the data is to
   *                                 be read.  It must not be {@code null}.
   * @param  numParseThreads         If this value is greater than zero, then
   *                                 the specified number of threads will be
   *                                 used to asynchronously read and parse the
   *                                 LDIF file.
   * @param  entryTranslator         The LDIFReaderEntryTranslator to apply to
   *                                 entries before they are returned.  This is
   *                                 normally {@code null}, which causes entries
   *                                 to be returned unaltered.  This is
   *                                 particularly useful when parsing the input
   *                                 file in parallel because the entry
   *                                 translation is also done in parallel.
   * @param  changeRecordTranslator  The LDIFReaderChangeRecordTranslator to
   *                                 apply to change records before they are
   *                                 returned.  This is normally {@code null},
   *                                 which causes change records to be returned
   *                                 unaltered.  This is particularly useful
   *                                 when parsing the input file in parallel
   *                                 because the change record translation is
   *                                 also done in parallel.
   * @param  characterSet            The character set to use when reading from
   *                                 the input stream.  It must not be
   *                                 {@code null}.
   *
   * @see #LDIFReader(BufferedReader, int, LDIFReaderEntryTranslator)
   *      constructor for more details about asynchronous processing.
   */
  public LDIFReader(@NotNull final InputStream inputStream,
       final int numParseThreads,
       @Nullable final LDIFReaderEntryTranslator entryTranslator,
       @Nullable final LDIFReaderChangeRecordTranslator changeRecordTranslator,
       @NotNull final String characterSet)
  {
    this(new BufferedReader(
              new InputStreamReader(inputStream, Charset.forName(characterSet)),
              DEFAULT_BUFFER_SIZE),
         numParseThreads, entryTranslator, changeRecordTranslator);
  }



  /**
   * Creates a new LDIF reader that will use the provided buffered reader to
   * read the LDIF data.  The encoding of the underlying Reader must be set to
   * "UTF-8" as required by RFC 2849.
   *
   * @param  reader  The buffered reader that will be used to read the LDIF
   *                 data.  It must not be {@code null}.
   */
  public LDIFReader(@NotNull final BufferedReader reader)
  {
    this(reader, 0);
  }



  /**
   * Creates a new LDIF reader that will read data from the specified buffered
   * reader and parses the LDIF records asynchronously using the specified
   * number of threads.  The encoding of the underlying Reader must be set to
   * "UTF-8" as required by RFC 2849.
   *
   * @param reader The buffered reader that will be used to read the LDIF data.
   *               It must not be {@code null}.
   * @param  numParseThreads  If this value is greater than zero, then the
   *                          specified number of threads will be used to
   *                          asynchronously read and parse the LDIF file.
   *
   * @see #LDIFReader(BufferedReader, int, LDIFReaderEntryTranslator)
   *      constructor for more details about asynchronous processing.
   */
  public LDIFReader(@NotNull final BufferedReader reader,
                    final int numParseThreads)
  {
    this(reader, numParseThreads, null);
  }



  /**
   * Creates a new LDIF reader that will read data from the specified buffered
   * reader and parses the LDIF records asynchronously using the specified
   * number of threads.  The encoding of the underlying Reader must be set to
   * "UTF-8" as required by RFC 2849.
   *
   * @param reader The buffered reader that will be used to read the LDIF data.
   *               It must not be {@code null}.
   * @param  numParseThreads  If this value is greater than zero, then the
   *                          specified number of threads will be used to
   *                          asynchronously read and parse the LDIF file.
   *                          This should only be set to greater than zero when
   *                          performance analysis has demonstrated that reading
   *                          and parsing the LDIF is a bottleneck.  The default
   *                          synchronous processing is normally fast enough.
   *                          There is little benefit in passing in a value
   *                          greater than four (unless there is an
   *                          LDIFReaderEntryTranslator that does time-consuming
   *                          processing).  A value of zero implies the
   *                          default behavior of reading and parsing LDIF
   *                          records synchronously when one of the read
   *                          methods is called.
   * @param entryTranslator  The LDIFReaderEntryTranslator to apply to read
   *                         entries before they are returned.  This is normally
   *                         {@code null}, which causes entries to be returned
   *                         unaltered. This is particularly useful when parsing
   *                         the input file in parallel because the entry
   *                         translation is also done in parallel.
   */
  public LDIFReader(@NotNull final BufferedReader reader,
                    final int numParseThreads,
                    @Nullable final LDIFReaderEntryTranslator entryTranslator)
  {
    this(reader, numParseThreads, entryTranslator, null);
  }



  /**
   * Creates a new LDIF reader that will read data from the specified buffered
   * reader and parses the LDIF records asynchronously using the specified
   * number of threads.  The encoding of the underlying Reader must be set to
   * "UTF-8" as required by RFC 2849.
   *
   * @param reader                   The buffered reader that will be used to
   *                                 read the LDIF data.  It must not be
   *                                 {@code null}.
   * @param  numParseThreads         If this value is greater than zero, then
   *                                 the specified number of threads will be
   *                                 used to asynchronously read and parse the
   *                                 LDIF file.
   * @param  entryTranslator         The LDIFReaderEntryTranslator to apply to
   *                                 entries before they are returned.  This is
   *                                 normally {@code null}, which causes entries
   *                                 to be returned unaltered.  This is
   *                                 particularly useful when parsing the input
   *                                 file in parallel because the entry
   *                                 translation is also done in parallel.
   * @param  changeRecordTranslator  The LDIFReaderChangeRecordTranslator to
   *                                 apply to change records before they are
   *                                 returned.  This is normally {@code null},
   *                                 which causes change records to be returned
   *                                 unaltered.  This is particularly useful
   *                                 when parsing the input file in parallel
   *                                 because the change record translation is
   *                                 also done in parallel.
   */
  public LDIFReader(@NotNull final BufferedReader reader,
       final int numParseThreads,
       @Nullable final LDIFReaderEntryTranslator entryTranslator,
       @Nullable final LDIFReaderChangeRecordTranslator changeRecordTranslator)
  {
    Validator.ensureNotNull(reader);
    Validator.ensureTrue(numParseThreads >= 0,
               "LDIFReader.numParseThreads must not be negative.");

    this.reader = reader;
    this.entryTranslator = entryTranslator;
    this.changeRecordTranslator = changeRecordTranslator;

    duplicateValueBehavior = DuplicateValueBehavior.STRIP;
    trailingSpaceBehavior  = TrailingSpaceBehavior.REJECT;

    relativeBasePath = DEFAULT_RELATIVE_BASE_PATH;

    if (numParseThreads == 0)
    {
      isAsync = false;
      asyncParser = null;
      asyncParsingComplete = null;
      asyncParsedRecords = null;
    }
    else
    {
      isAsync = true;
      asyncParsingComplete = new AtomicBoolean(false);

      // Decodes entries in parallel.
      final LDAPSDKThreadFactory threadFactory =
           new LDAPSDKThreadFactory("LDIFReader Worker", true, null);
      final ParallelProcessor<UnparsedLDIFRecord, LDIFRecord> parallelParser =
           new ParallelProcessor<>(
                new RecordParser(), threadFactory, numParseThreads,
                ASYNC_MIN_PER_PARSING_THREAD);

      final BlockingQueue<UnparsedLDIFRecord> pendingQueue = new
           ArrayBlockingQueue<>(ASYNC_QUEUE_SIZE);

      // The output queue must be a little more than twice as big as the input
      // queue to more easily handle being shutdown in the middle of processing
      // when the queues are full and threads are blocked.
      asyncParsedRecords = new ArrayBlockingQueue<>(2 * ASYNC_QUEUE_SIZE + 100);

      asyncParser = new AsynchronousParallelProcessor<>(pendingQueue,
           parallelParser, asyncParsedRecords);

      final LineReaderThread lineReaderThread = new LineReaderThread();
      lineReaderThread.start();
    }
  }



  /**
   * Reads entries from the LDIF file with the specified path and returns them
   * as a {@code List}.  This is a convenience method that should only be used
   * for data sets that are small enough so that running out of memory isn't a
   * concern.
   *
   * @param  path  The path to the LDIF file containing the entries to be read.
   *
   * @return  A list of the entries read from the given LDIF file.
   *
   * @throws  IOException  If a problem occurs while attempting to read data
   *                       from the specified file.
   *
   * @throws  LDIFException  If a problem is encountered while attempting to
   *                         decode data read as LDIF.
   */
  @NotNull()
  public static List<Entry> readEntries(@NotNull final String path)
         throws IOException, LDIFException
  {
    return readEntries(new LDIFReader(path));
  }



  /**
   * Reads entries from the specified LDIF file and returns them as a
   * {@code List}.  This is a convenience method that should only be used for
   * data sets that are small enough so that running out of memory isn't a
   * concern.
   *
   * @param  file  A reference to the LDIF file containing the entries to be
   *               read.
   *
   * @return  A list of the entries read from the given LDIF file.
   *
   * @throws  IOException  If a problem occurs while attempting to read data
   *                       from the specified file.
   *
   * @throws  LDIFException  If a problem is encountered while attempting to
   *                         decode data read as LDIF.
   */
  @NotNull()
  public static List<Entry> readEntries(@NotNull final File file)
         throws IOException, LDIFException
  {
    return readEntries(new LDIFReader(file));
  }



  /**
   * Reads and decodes LDIF entries from the provided input stream and
   * returns them as a {@code List}.  This is a convenience method that should
   * only be used for data sets that are small enough so that running out of
   * memory isn't a concern.
   *
   * @param  inputStream  The input stream from which the entries should be
   *                      read.  The input stream will be closed before
   *                      returning.
   *
   * @return  A list of the entries read from the given input stream.
   *
   * @throws  IOException  If a problem occurs while attempting to read data
   *                       from the input stream.
   *
   * @throws  LDIFException  If a problem is encountered while attempting to
   *                         decode data read as LDIF.
   */
  @NotNull()
  public static List<Entry> readEntries(@NotNull final InputStream inputStream)
         throws IOException, LDIFException
  {
    return readEntries(new LDIFReader(inputStream));
  }



  /**
   * Reads entries from the provided LDIF reader and returns them as a list.
   *
   * @param  reader  The reader from which the entries should be read.  It will
   *                 be closed before returning.
   *
   * @return  A list of the entries read from the provided reader.
   *
   * @throws  IOException  If a problem was encountered while attempting to read
   *                       data from the LDIF data source.
   *
   * @throws  LDIFException  If a problem is encountered while attempting to
   *                         decode data read as LDIF.
   */
  @NotNull()
  private static List<Entry> readEntries(@NotNull final LDIFReader reader)
          throws IOException, LDIFException
  {
    try
    {
      final ArrayList<Entry> entries = new ArrayList<>(10);
      while (true)
      {
        final Entry e = reader.readEntry();
        if (e == null)
        {
          break;
        }

        entries.add(e);
      }

      return entries;
    }
    finally
    {
      reader.close();
    }
  }



  /**
   * Closes this LDIF reader and the underlying LDIF source.
   *
   * @throws  IOException  If a problem occurs while closing the underlying LDIF
   *                       source.
   */
  @Override()
  public void close()
         throws IOException
  {
    reader.close();

    if (isAsync())
    {
      // Closing the reader will trigger the LineReaderThread to complete, but
      // not if it's blocked submitting the next UnparsedLDIFRecord.  To avoid
      // this, we clear out the completed output queue, which is larger than
      // the input queue, so the LineReaderThread will stop reading and
      // shutdown the asyncParser.
      asyncParsedRecords.clear();
    }
  }



  /**
   * Indicates whether to ignore any duplicate values encountered while reading
   * LDIF records.
   *
   * @return  {@code true} if duplicate values should be ignored, or
   *          {@code false} if any LDIF records containing duplicate values
   *          should be rejected.
   *
   * @deprecated  Use the {@link #getDuplicateValueBehavior} method instead.
   */
  @Deprecated()
  public boolean ignoreDuplicateValues()
  {
    return (duplicateValueBehavior == DuplicateValueBehavior.STRIP);
  }



  /**
   * Specifies whether to ignore any duplicate values encountered while reading
   * LDIF records.
   *
   * @param  ignoreDuplicateValues  Indicates whether to ignore duplicate
   *                                attribute values encountered while reading
   *                                LDIF records.
   *
   * @deprecated  Use the {@link #setDuplicateValueBehavior} method instead.
   */
  @Deprecated()
  public void setIgnoreDuplicateValues(final boolean ignoreDuplicateValues)
  {
    if (ignoreDuplicateValues)
    {
      duplicateValueBehavior = DuplicateValueBehavior.STRIP;
    }
    else
    {
      duplicateValueBehavior = DuplicateValueBehavior.REJECT;
    }
  }



  /**
   * Retrieves the behavior that should be exhibited if the LDIF reader
   * encounters an entry with duplicate values.
   *
   * @return  The behavior that should be exhibited if the LDIF reader
   *          encounters an entry with duplicate values.
   */
  @NotNull()
  public DuplicateValueBehavior getDuplicateValueBehavior()
  {
    return duplicateValueBehavior;
  }



  /**
   * Specifies the behavior that should be exhibited if the LDIF reader
   * encounters an entry with duplicate values.
   *
   * @param  duplicateValueBehavior  The behavior that should be exhibited if
   *                                 the LDIF reader encounters an entry with
   *                                 duplicate values.
   */
  public void setDuplicateValueBehavior(
                   @NotNull final DuplicateValueBehavior duplicateValueBehavior)
  {
    this.duplicateValueBehavior = duplicateValueBehavior;
  }



  /**
   * Indicates whether to strip off any illegal trailing spaces that may appear
   * in LDIF records (e.g., after an entry DN or attribute value).  The LDIF
   * specification strongly recommends that any value which legitimately
   * contains trailing spaces be base64-encoded, and any spaces which appear
   * after the end of non-base64-encoded values may therefore be considered
   * invalid.  If any such trailing spaces are encountered in an LDIF record and
   * they are not to be stripped, then an {@link LDIFException} will be thrown
   * for that record.
   * <BR><BR>
   * Note that this applies only to spaces after the end of a value, and not to
   * spaces which may appear at the end of a line for a value that is wrapped
   * and continued on the next line.
   *
   * @return  {@code true} if illegal trailing spaces should be stripped off, or
   *          {@code false} if LDIF records containing illegal trailing spaces
   *          should be rejected.
   *
   * @deprecated  Use the {@link #getTrailingSpaceBehavior} method instead.
   */
  @Deprecated()
  public boolean stripTrailingSpaces()
  {
    return (trailingSpaceBehavior == TrailingSpaceBehavior.STRIP);
  }



  /**
   * Specifies whether to strip off any illegal trailing spaces that may appear
   * in LDIF records (e.g., after an entry DN or attribute value).  The LDIF
   * specification strongly recommends that any value which legitimately
   * contains trailing spaces be base64-encoded, and any spaces which appear
   * after the end of non-base64-encoded values may therefore be considered
   * invalid.  If any such trailing spaces are encountered in an LDIF record and
   * they are not to be stripped, then an {@link LDIFException} will be thrown
   * for that record.
   * <BR><BR>
   * Note that this applies only to spaces after the end of a value, and not to
   * spaces which may appear at the end of a line for a value that is wrapped
   * and continued on the next line.
   *
   * @param  stripTrailingSpaces  Indicates whether to strip off any illegal
   *                              trailing spaces, or {@code false} if LDIF
   *                              records containing them should be rejected.
   *
   * @deprecated  Use the {@link #setTrailingSpaceBehavior} method instead.
   */
  @Deprecated()
  public void setStripTrailingSpaces(final boolean stripTrailingSpaces)
  {
    trailingSpaceBehavior = stripTrailingSpaces
         ? TrailingSpaceBehavior.STRIP
         : TrailingSpaceBehavior.REJECT;
  }



  /**
   * Retrieves the behavior that should be exhibited when encountering attribute
   * values which are not base64-encoded but contain trailing spaces.  The LDIF
   * specification strongly recommends that any value which legitimately
   * contains trailing spaces be base64-encoded, but the LDAP SDK LDIF parser
   * may be configured to automatically strip these spaces, to preserve them, or
   * to reject any entry or change record containing them.
   *
   * @return  The behavior that should be exhibited when encountering attribute
   *          values which are not base64-encoded but contain trailing spaces.
   */
  @NotNull()
  public TrailingSpaceBehavior getTrailingSpaceBehavior()
  {
    return trailingSpaceBehavior;
  }



  /**
   * Specifies the behavior that should be exhibited when encountering attribute
   * values which are not base64-encoded but contain trailing spaces.  The LDIF
   * specification strongly recommends that any value which legitimately
   * contains trailing spaces be base64-encoded, but the LDAP SDK LDIF parser
   * may be configured to automatically strip these spaces, to preserve them, or
   * to reject any entry or change record containing them.
   *
   * @param  trailingSpaceBehavior  The behavior that should be exhibited when
   *                                encountering attribute values which are not
   *                                base64-encoded but contain trailing spaces.
   */
  public void setTrailingSpaceBehavior(
                   @NotNull final TrailingSpaceBehavior trailingSpaceBehavior)
  {
    this.trailingSpaceBehavior = trailingSpaceBehavior;
  }



  /**
   * Retrieves the base path that will be prepended to relative paths in order
   * to obtain an absolute path.  This will only be used for "file:" URLs that
   * have paths which do not begin with a slash.
   *
   * @return  The base path that will be prepended to relative paths in order to
   *          obtain an absolute path.
   */
  @NotNull()
  public String getRelativeBasePath()
  {
    return relativeBasePath;
  }



  /**
   * Specifies the base path that will be prepended to relative paths in order
   * to obtain an absolute path.  This will only be used for "file:" URLs that
   * have paths which do not begin with a space.
   *
   * @param  relativeBasePath  The base path that will be prepended to relative
   *                           paths in order to obtain an absolute path.
   */
  public void setRelativeBasePath(@NotNull final String relativeBasePath)
  {
    setRelativeBasePath(new File(relativeBasePath));
  }



  /**
   * Specifies the base path that will be prepended to relative paths in order
   * to obtain an absolute path.  This will only be used for "file:" URLs that
   * have paths which do not begin with a space.
   *
   * @param  relativeBasePath  The base path that will be prepended to relative
   *                           paths in order to obtain an absolute path.
   */
  public void setRelativeBasePath(@NotNull final File relativeBasePath)
  {
    final String path = relativeBasePath.getAbsolutePath();
    if (path.endsWith(File.separator))
    {
      this.relativeBasePath = path;
    }
    else
    {
      this.relativeBasePath = path + File.separator;
    }
  }



  /**
   * Retrieves the schema that will be used when reading LDIF records, if
   * defined.
   *
   * @return  The schema that will be used when reading LDIF records, or
   *          {@code null} if no schema should be used and all attributes should
   *          be treated as case-insensitive strings.
   */
  @Nullable()
  public Schema getSchema()
  {
    return schema;
  }



  /**
   * Specifies the schema that should be used when reading LDIF records.
   *
   * @param  schema  The schema that should be used when reading LDIF records,
   *                 or {@code null} if no schema should be used and all
   *                 attributes should be treated as case-insensitive strings.
   */
  public void setSchema(@Nullable final Schema schema)
  {
    this.schema = schema;
  }



  /**
   * Reads a record from the LDIF source.  It may be either an entry or an LDIF
   * change record.
   *
   * @return  The record read from the LDIF source, or {@code null} if there are
   *          no more entries to be read.
   *
   * @throws  IOException  If a problem occurs while trying to read from the
   *                       LDIF source.
   *
   * @throws  LDIFException  If the data read could not be parsed as an entry or
   *                         an LDIF change record.
   */
  @Nullable()
  public LDIFRecord readLDIFRecord()
         throws IOException, LDIFException
  {
    if (isAsync())
    {
      return readLDIFRecordAsync();
    }
    else
    {
      return readLDIFRecordInternal();
    }
  }



  /**
   * Reads an entry from the LDIF source.
   *
   * @return  The entry read from the LDIF source, or {@code null} if there are
   *          no more entries to be read.
   *
   * @throws  IOException  If a problem occurs while attempting to read from the
   *                       LDIF source.
   *
   * @throws  LDIFException  If the data read could not be parsed as an entry.
   */
  @Nullable()
  public Entry readEntry()
         throws IOException, LDIFException
  {
    if (isAsync())
    {
      return readEntryAsync();
    }
    else
    {
      return readEntryInternal();
    }
  }



  /**
   * Reads an LDIF change record from the LDIF source.  The LDIF record must
   * have a changetype.
   *
   * @return  The change record read from the LDIF source, or {@code null} if
   *          there are no more records to be read.
   *
   * @throws  IOException  If a problem occurs while attempting to read from the
   *                       LDIF source.
   *
   * @throws  LDIFException  If the data read could not be parsed as an LDIF
   *                         change record.
   */
  @Nullable()
  public LDIFChangeRecord readChangeRecord()
         throws IOException, LDIFException
  {
    return readChangeRecord(false);
  }



  /**
   * Reads an LDIF change record from the LDIF source.  Optionally, if the LDIF
   * record does not have a changetype, then it may be assumed to be an add
   * change record.
   *
   * @param  defaultAdd  Indicates whether an LDIF record not containing a
   *                     changetype should be retrieved as an add change record.
   *                     If this is {@code false} and the record read does not
   *                     include a changetype, then an {@link LDIFException}
   *                     will be thrown.
   *
   * @return  The change record read from the LDIF source, or {@code null} if
   *          there are no more records to be read.
   *
   * @throws  IOException  If a problem occurs while attempting to read from the
   *                       LDIF source.
   *
   * @throws  LDIFException  If the data read could not be parsed as an LDIF
   *                         change record.
   */
  @Nullable()
  public LDIFChangeRecord readChangeRecord(final boolean defaultAdd)
         throws IOException, LDIFException
  {
    if (isAsync())
    {
      return readChangeRecordAsync(defaultAdd);
    }
    else
    {
      return readChangeRecordInternal(defaultAdd);
    }
  }



  /**
   * Reads the next {@code LDIFRecord}, which was read and parsed by a different
   * thread.
   *
   * @return  The next parsed record or {@code null} if there are no more
   *          records to read.
   *
   * @throws IOException  If IOException was thrown when reading or parsing
   *                      the record.
   *
   * @throws LDIFException If LDIFException was thrown parsing the record.
   */
  @Nullable()
  private LDIFRecord readLDIFRecordAsync()
          throws IOException, LDIFException
  {
    Result<UnparsedLDIFRecord, LDIFRecord> result;
    LDIFRecord record = null;
    while (record == null)
    {
      result = readLDIFRecordResultAsync();
      if (result == null)
      {
        return null;
      }

      record = result.getOutput();

      // This is a special value that means we should skip this Entry.  We have
      // to use something different than null because null means EOF.
      if (record == SKIP_ENTRY)
      {
        record = null;
      }
    }
    return record;
  }



  /**
   * Reads an entry asynchronously from the LDIF source.
   *
   * @return The entry read from the LDIF source, or {@code null} if there are
   *         no more entries to be read.
   *
   * @throws IOException   If a problem occurs while attempting to read from the
   *                       LDIF source.
   * @throws LDIFException If the data read could not be parsed as an entry.
   */
  @Nullable()
  private Entry readEntryAsync()
          throws IOException, LDIFException
  {
    Result<UnparsedLDIFRecord, LDIFRecord> result = null;
    LDIFRecord record = null;
    while (record == null)
    {
      result = readLDIFRecordResultAsync();
      if (result == null)
      {
        return null;
      }

      record = result.getOutput();

      // This is a special value that means we should skip this Entry.  We have
      // to use something different than null because null means EOF.
      if (record == SKIP_ENTRY)
      {
        record = null;
      }
    }

    if (record instanceof Entry)
    {
      return (Entry) record;
    }
    else if (record instanceof LDIFChangeRecord)
    {
      try
      {
        // Some LDIFChangeRecord can be converted to an Entry.  This is really
        // an edge case though.
        return ((LDIFChangeRecord)record).toEntry();
      }
      catch (final LDIFException e)
      {
        Debug.debugException(e);
        final long firstLineNumber = result.getInput().getFirstLineNumber();
        throw new LDIFException(e.getExceptionMessage(),
                                firstLineNumber, true, e);
      }
    }

    throw new AssertionError("LDIFRecords must either be an Entry or an " +
                             "LDIFChangeRecord");
  }



  /**
   * Reads an LDIF change record from the LDIF source asynchronously.
   * Optionally, if the LDIF record does not have a changetype, then it may be
   * assumed to be an add change record.
   *
   * @param defaultAdd Indicates whether an LDIF record not containing a
   *                   changetype should be retrieved as an add change record.
   *                   If this is {@code false} and the record read does not
   *                   include a changetype, then an {@link LDIFException} will
   *                   be thrown.
   *
   * @return The change record read from the LDIF source, or {@code null} if
   *         there are no more records to be read.
   *
   * @throws IOException   If a problem occurs while attempting to read from the
   *                       LDIF source.
   * @throws LDIFException If the data read could not be parsed as an LDIF
   *                       change record.
   */
  @Nullable()
  private LDIFChangeRecord readChangeRecordAsync(final boolean defaultAdd)
          throws IOException, LDIFException
  {
    Result<UnparsedLDIFRecord, LDIFRecord> result = null;
    LDIFRecord record = null;
    while (record == null)
    {
      result = readLDIFRecordResultAsync();
      if (result == null)
      {
        return null;
      }

      record = result.getOutput();

      // This is a special value that means we should skip this Entry.  We have
      // to use something different than null because null means EOF.
      if (record == SKIP_ENTRY)
      {
        record = null;
      }
    }

    if (record instanceof LDIFChangeRecord)
    {
      return (LDIFChangeRecord) record;
    }
    else if (record instanceof Entry)
    {
      if (defaultAdd)
      {
        return new LDIFAddChangeRecord((Entry) record);
      }
      else
      {
        final long firstLineNumber = result.getInput().getFirstLineNumber();
        throw new LDIFException(
             ERR_READ_NOT_CHANGE_RECORD.get(firstLineNumber), firstLineNumber,
             true);
      }
    }

    throw new AssertionError("LDIFRecords must either be an Entry or an " +
                             "LDIFChangeRecord");
  }



  /**
   * Reads the next LDIF record, which was read and parsed asynchronously by
   * separate threads.
   *
   * @return  The next LDIF record or {@code null} if there are no more records.
   *
   * @throws  IOException  If a problem occurs while attempting to read from the
   *                       LDIF source.
   *
   * @throws  LDIFException  If the data read could not be parsed as an entry.
   */
  @Nullable()
  private Result<UnparsedLDIFRecord, LDIFRecord> readLDIFRecordResultAsync()
          throws IOException, LDIFException
  {
    Result<UnparsedLDIFRecord, LDIFRecord> result = null;

    // If the asynchronous reading and parsing is complete, then we don't have
    // to block waiting for the next record to show up on the queue.  If there
    // isn't a record there, then return null (EOF) right away.
    if (asyncParsingComplete.get())
    {
      result = asyncParsedRecords.poll();
    }
    else
    {
      try
      {
        // We probably could just do a asyncParsedRecords.take() here, but
        // there are some edge case error scenarios where
        // asyncParsingComplete might be set without a special EOF sentinel
        // Result enqueued.  So to guard against this, we have a very cautious
        // polling interval of 1 second.  During normal processing, we never
        // have to wait for this to expire, when there is something to do
        // (like shutdown).
        while ((result == null) && (!asyncParsingComplete.get()))
        {
          result = asyncParsedRecords.poll(1, TimeUnit.SECONDS);
        }

        // There's a very small chance that we missed the value, so double-check
        if (result == null)
        {
          result = asyncParsedRecords.poll();
        }
      }
      catch (final InterruptedException e)
      {
        Debug.debugException(e);
        Thread.currentThread().interrupt();
        throw new IOException(e);
      }
    }
    if (result == null)
    {
      return null;
    }

    rethrow(result.getFailureCause());

    // Check if we reached the end of the input
    final UnparsedLDIFRecord unparsedRecord = result.getInput();
    if (unparsedRecord.isEOF())
    {
      // This might have been set already by the LineReaderThread, but
      // just in case it hasn't gotten to it yet, do so here.
      asyncParsingComplete.set(true);

      // Enqueue this EOF result again for any other thread that might be
      // blocked in asyncParsedRecords.take() even though having multiple
      // threads call this method concurrently breaks the contract of this
      // class.
      try
      {
        asyncParsedRecords.put(result);
      }
      catch (final InterruptedException e)
      {
        // We shouldn't ever get interrupted because the put won't ever block.
        // Once we are done reading, this is the only item left in the queue,
        // so we should always be able to re-enqueue it.
        Debug.debugException(e);
        Thread.currentThread().interrupt();
      }
      return null;
    }

    return result;
  }



  /**
   * Indicates whether this LDIF reader was constructed to perform asynchronous
   * processing.
   *
   * @return  {@code true} if this LDIFReader was constructed to perform
   *          asynchronous processing, or {@code false} if not.
   */
  private boolean isAsync()
  {
    return isAsync;
  }



  /**
   * If not {@code null}, rethrows the specified Throwable as either an
   * IOException or LDIFException.
   *
   * @param t  The exception to rethrow.  If it's {@code null}, then nothing
   *           is thrown.
   *
   * @throws IOException   If t is an IOException or a checked Exception that
   *                       is not an LDIFException.
   * @throws LDIFException  If t is an LDIFException.
   */
  static void rethrow(@Nullable final Throwable t)
         throws IOException, LDIFException
  {
    if (t == null)
    {
      return;
    }

    if (t instanceof IOException)
    {
      throw (IOException) t;
    }
    else if (t instanceof LDIFException)
    {
      throw (LDIFException) t;
    }
    else if (t instanceof RuntimeException)
    {
      throw (RuntimeException) t;
    }
    else if (t instanceof Error)
    {
      throw (Error) t;
    }
    else
    {
      throw new IOException(t);
    }
  }



  /**
   * Reads a record from the LDIF source.  It may be either an entry or an LDIF
   * change record.
   *
   * @return The record read from the LDIF source, or {@code null} if there are
   *         no more entries to be read.
   *
   * @throws IOException   If a problem occurs while trying to read from the
   *                       LDIF source.
   * @throws LDIFException If the data read could not be parsed as an entry or
   *                       an LDIF change record.
   */
  @Nullable()
  private LDIFRecord readLDIFRecordInternal()
       throws IOException, LDIFException
  {
    final UnparsedLDIFRecord unparsedRecord = readUnparsedRecord();
    return decodeRecord(unparsedRecord, relativeBasePath, schema);
  }



  /**
   * Reads an entry from the LDIF source.
   *
   * @return The entry read from the LDIF source, or {@code null} if there are
   *         no more entries to be read.
   *
   * @throws IOException   If a problem occurs while attempting to read from the
   *                       LDIF source.
   * @throws LDIFException If the data read could not be parsed as an entry.
   */
  @Nullable()
  private Entry readEntryInternal()
       throws IOException, LDIFException
  {
    Entry e = null;
    while (e == null)
    {
      final UnparsedLDIFRecord unparsedRecord = readUnparsedRecord();
      if (unparsedRecord.isEOF())
      {
        return null;
      }

      e = decodeEntry(unparsedRecord, relativeBasePath);
      Debug.debugLDIFRead(e);

      if (entryTranslator != null)
      {
        e = entryTranslator.translate(e, unparsedRecord.getFirstLineNumber());
      }
    }
    return e;
  }



  /**
   * Reads an LDIF change record from the LDIF source.  Optionally, if the LDIF
   * record does not have a changetype, then it may be assumed to be an add
   * change record.
   *
   * @param defaultAdd Indicates whether an LDIF record not containing a
   *                   changetype should be retrieved as an add change record.
   *                   If this is {@code false} and the record read does not
   *                   include a changetype, then an {@link LDIFException} will
   *                   be thrown.
   *
   * @return The change record read from the LDIF source, or {@code null} if
   *         there are no more records to be read.
   *
   * @throws IOException   If a problem occurs while attempting to read from the
   *                       LDIF source.
   * @throws LDIFException If the data read could not be parsed as an LDIF
   *                       change record.
   */
  @Nullable()
  private LDIFChangeRecord readChangeRecordInternal(final boolean defaultAdd)
       throws IOException, LDIFException
  {
    LDIFChangeRecord r = null;
    while (r == null)
    {
      final UnparsedLDIFRecord unparsedRecord = readUnparsedRecord();
      if (unparsedRecord.isEOF())
      {
        return null;
      }

      r = decodeChangeRecord(unparsedRecord, relativeBasePath, defaultAdd,
           schema);
      Debug.debugLDIFRead(r);

      if (changeRecordTranslator != null)
      {
        r = changeRecordTranslator.translate(r,
             unparsedRecord.getFirstLineNumber());
      }
    }
    return r;
  }



  /**
   * Reads a record (either an entry or a change record) from the LDIF source
   * and places it in the line list.
   *
   * @return  The unparsed record that was read.
   *
   * @throws  IOException  If a problem occurs while attempting to read from the
   *                       LDIF source.
   *
   * @throws  LDIFException  If the data read could not be parsed as a valid
   *                         LDIF record.
   */
  @NotNull()
  private UnparsedLDIFRecord readUnparsedRecord()
         throws IOException, LDIFException
  {
    final ArrayList<StringBuilder> lineList = new ArrayList<>(20);
    boolean lastWasComment = false;
    long firstLineNumber = lineNumberCounter + 1;
    while (true)
    {
      final String line = reader.readLine();
      lineNumberCounter++;

      if (line == null)
      {
        // We've hit the end of the LDIF source.  If we haven't read any entry
        // data, then return null.  Otherwise, the last entry wasn't followed by
        // a blank line, which is OK, and we should decode that entry.
        if (lineList.isEmpty())
        {
          return new UnparsedLDIFRecord(new ArrayList<StringBuilder>(0),
               duplicateValueBehavior, trailingSpaceBehavior, schema, -1);
        }
        else
        {
          break;
        }
      }

      if (line.isEmpty())
      {
        // It's a blank line.  If we have read entry data, then this signals the
        // end of the entry.  Otherwise, it's an extra space between entries,
        // which is OK.
        lastWasComment = false;
        if (lineList.isEmpty())
        {
          firstLineNumber++;
          continue;
        }
        else
        {
          break;
        }
      }

      if (line.charAt(0) == ' ')
      {
        // The line starts with a space, which means that it must be a
        // continuation of the previous line.  This is true even if the last
        // line was a comment.
        if (lastWasComment)
        {
          // What we've read is part of a comment, so we don't care about its
          // content.
        }
        else if (lineList.isEmpty())
        {
          throw new LDIFException(
                         ERR_READ_UNEXPECTED_FIRST_SPACE.get(lineNumberCounter),
                         lineNumberCounter, false);
        }
        else
        {
          lineList.get(lineList.size() - 1).append(line.substring(1));
          lastWasComment = false;
        }
      }
      else if (line.charAt(0) == '#')
      {
        lastWasComment = true;
      }
      else
      {
        // We want to make sure that we skip over the "version:" line if it
        // exists, but that should only occur at the beginning of an entry where
        // it can't be confused with a possible "version" attribute.
        if (lineList.isEmpty() && line.startsWith("version:"))
        {
          lastWasComment = true;
        }
        else
        {
          lineList.add(new StringBuilder(line));
          lastWasComment = false;
        }
      }
    }

    return new UnparsedLDIFRecord(lineList, duplicateValueBehavior,
         trailingSpaceBehavior, schema, firstLineNumber);
  }



  /**
   * Decodes the provided set of LDIF lines as an entry.  The provided set of
   * lines must contain exactly one entry.  Long lines may be wrapped as per the
   * LDIF specification, and it is acceptable to have one or more blank lines
   * following the entry. A default trailing space behavior of
   * {@link TrailingSpaceBehavior#REJECT} will be used.
   *
   * @param  ldifLines  The set of lines that comprise the LDIF representation
   *                    of the entry.  It must not be {@code null} or empty.
   *
   * @return  The entry read from LDIF.
   *
   * @throws  LDIFException  If the provided LDIF data cannot be decoded as an
   *                         entry.
   */
  @NotNull()
  public static Entry decodeEntry(@NotNull final String... ldifLines)
         throws LDIFException
  {
    final Entry e = decodeEntry(prepareRecord(DuplicateValueBehavior.STRIP,
         TrailingSpaceBehavior.REJECT, null, ldifLines),
         DEFAULT_RELATIVE_BASE_PATH);
    Debug.debugLDIFRead(e);
    return e;
  }



  /**
   * Decodes the provided set of LDIF lines as an entry.  The provided set of
   * lines must contain exactly one entry.  Long lines may be wrapped as per the
   * LDIF specification, and it is acceptable to have one or more blank lines
   * following the entry. A default trailing space behavior of
   * {@link TrailingSpaceBehavior#REJECT} will be used.
   *
   * @param  ignoreDuplicateValues  Indicates whether to ignore duplicate
   *                                attribute values encountered while parsing.
   * @param  schema                 The schema to use when parsing the record,
   *                                if applicable.
   * @param  ldifLines              The set of lines that comprise the LDIF
   *                                representation of the entry.  It must not be
   *                                {@code null} or empty.
   *
   * @return  The entry read from LDIF.
   *
   * @throws  LDIFException  If the provided LDIF data cannot be decoded as an
   *                         entry.
   */
  @NotNull()
  public static Entry decodeEntry(final boolean ignoreDuplicateValues,
                                  @Nullable final Schema schema,
                                  @NotNull final String... ldifLines)
         throws LDIFException
  {
    return decodeEntry(ignoreDuplicateValues, TrailingSpaceBehavior.REJECT,
         schema, ldifLines);
  }



  /**
   * Decodes the provided set of LDIF lines as an entry.  The provided set of
   * lines must contain exactly one entry.  Long lines may be wrapped as per the
   * LDIF specification, and it is acceptable to have one or more blank lines
   * following the entry.
   *
   * @param  ignoreDuplicateValues  Indicates whether to ignore duplicate
   *                                attribute values encountered while parsing.
   * @param  trailingSpaceBehavior  The behavior that should be exhibited when
   *                                encountering attribute values which are not
   *                                base64-encoded but contain trailing spaces.
   *                                It must not be {@code null}.
   * @param  schema                 The schema to use when parsing the record,
   *                                if applicable.
   * @param  ldifLines              The set of lines that comprise the LDIF
   *                                representation of the entry.  It must not be
   *                                {@code null} or empty.
   *
   * @return  The entry read from LDIF.
   *
   * @throws  LDIFException  If the provided LDIF data cannot be decoded as an
   *                         entry.
   */
  @NotNull()
  public static Entry decodeEntry(
                     final boolean ignoreDuplicateValues,
                     @NotNull final TrailingSpaceBehavior trailingSpaceBehavior,
                     @Nullable final Schema schema,
                     @NotNull final String... ldifLines)
         throws LDIFException
  {
    final Entry e = decodeEntry(prepareRecord(
              (ignoreDuplicateValues
                   ? DuplicateValueBehavior.STRIP
                   : DuplicateValueBehavior.REJECT),
         trailingSpaceBehavior, schema, ldifLines),
         DEFAULT_RELATIVE_BASE_PATH);
    Debug.debugLDIFRead(e);
    return e;
  }



  /**
   * Decodes the provided set of LDIF lines as an LDIF change record.  The
   * provided set of lines must contain exactly one change record and it must
   * include a changetype.  Long lines may be wrapped as per the LDIF
   * specification, and it is acceptable to have one or more blank lines
   * following the entry.
   *
   * @param  ldifLines  The set of lines that comprise the LDIF representation
   *                    of the change record.  It must not be {@code null} or
   *                    empty.
   *
   * @return  The change record read from LDIF.
   *
   * @throws  LDIFException  If the provided LDIF data cannot be decoded as a
   *                         change record.
   */
  @NotNull()
  public static LDIFChangeRecord decodeChangeRecord(
                                      @NotNull final String... ldifLines)
         throws LDIFException
  {
    return decodeChangeRecord(false, ldifLines);
  }



  /**
   * Decodes the provided set of LDIF lines as an LDIF change record.  The
   * provided set of lines must contain exactly one change record.  Long lines
   * may be wrapped as per the LDIF specification, and it is acceptable to have
   * one or more blank lines following the entry.
   *
   * @param  defaultAdd  Indicates whether an LDIF record not containing a
   *                     changetype should be retrieved as an add change record.
   *                     If this is {@code false} and the record read does not
   *                     include a changetype, then an {@link LDIFException}
   *                     will be thrown.
   * @param  ldifLines  The set of lines that comprise the LDIF representation
   *                    of the change record.  It must not be {@code null} or
   *                    empty.
   *
   * @return  The change record read from LDIF.
   *
   * @throws  LDIFException  If the provided LDIF data cannot be decoded as a
   *                         change record.
   */
  @NotNull()
  public static LDIFChangeRecord decodeChangeRecord(final boolean defaultAdd,
                                      @NotNull final String... ldifLines)
         throws LDIFException
  {
    final LDIFChangeRecord r =
         decodeChangeRecord(
              prepareRecord(DuplicateValueBehavior.STRIP,
                   TrailingSpaceBehavior.REJECT, null, ldifLines),
              DEFAULT_RELATIVE_BASE_PATH, defaultAdd, null);
    Debug.debugLDIFRead(r);
    return r;
  }



  /**
   * Decodes the provided set of LDIF lines as an LDIF change record.  The
   * provided set of lines must contain exactly one change record.  Long lines
   * may be wrapped as per the LDIF specification, and it is acceptable to have
   * one or more blank lines following the entry.
   *
   * @param  ignoreDuplicateValues  Indicates whether to ignore duplicate
   *                                attribute values encountered while parsing.
   * @param  schema                 The schema to use when processing the change
   *                                record, or {@code null} if no schema should
   *                                be used and all values should be treated as
   *                                case-insensitive strings.
   * @param  defaultAdd             Indicates whether an LDIF record not
   *                                containing a changetype should be retrieved
   *                                as an add change record.  If this is
   *                                {@code false} and the record read does not
   *                                include a changetype, then an
   *                                {@link LDIFException} will be thrown.
   * @param  ldifLines              The set of lines that comprise the LDIF
   *                                representation of the change record.  It
   *                                must not be {@code null} or empty.
   *
   * @return  The change record read from LDIF.
   *
   * @throws  LDIFException  If the provided LDIF data cannot be decoded as a
   *                         change record.
   */
  @NotNull()
  public static LDIFChangeRecord decodeChangeRecord(
                     final boolean ignoreDuplicateValues,
                     @Nullable final Schema schema,
                     final boolean defaultAdd,
                     @NotNull final String... ldifLines)
         throws LDIFException
  {
    return decodeChangeRecord(ignoreDuplicateValues,
         TrailingSpaceBehavior.REJECT, schema, defaultAdd, ldifLines);
  }



  /**
   * Decodes the provided set of LDIF lines as an LDIF change record.  The
   * provided set of lines must contain exactly one change record.  Long lines
   * may be wrapped as per the LDIF specification, and it is acceptable to have
   * one or more blank lines following the entry.
   *
   * @param  ignoreDuplicateValues  Indicates whether to ignore duplicate
   *                                attribute values encountered while parsing.
   * @param  trailingSpaceBehavior  The behavior that should be exhibited when
   *                                encountering attribute values which are not
   *                                base64-encoded but contain trailing spaces.
   *                                It must not be {@code null}.
   * @param  schema                 The schema to use when processing the change
   *                                record, or {@code null} if no schema should
   *                                be used and all values should be treated as
   *                                case-insensitive strings.
   * @param  defaultAdd             Indicates whether an LDIF record not
   *                                containing a changetype should be retrieved
   *                                as an add change record.  If this is
   *                                {@code false} and the record read does not
   *                                include a changetype, then an
   *                                {@link LDIFException} will be thrown.
   * @param  ldifLines              The set of lines that comprise the LDIF
   *                                representation of the change record.  It
   *                                must not be {@code null} or empty.
   *
   * @return  The change record read from LDIF.
   *
   * @throws  LDIFException  If the provided LDIF data cannot be decoded as a
   *                         change record.
   */
  @NotNull()
  public static LDIFChangeRecord decodeChangeRecord(
                     final boolean ignoreDuplicateValues,
                     @NotNull final TrailingSpaceBehavior trailingSpaceBehavior,
                     @Nullable final Schema schema,
                     final boolean defaultAdd,
                     @NotNull final String... ldifLines)
         throws LDIFException
  {
    final LDIFChangeRecord r = decodeChangeRecord(
         prepareRecord(
              (ignoreDuplicateValues
                   ? DuplicateValueBehavior.STRIP
                   : DuplicateValueBehavior.REJECT),
              trailingSpaceBehavior, schema, ldifLines),
         DEFAULT_RELATIVE_BASE_PATH, defaultAdd, null);
    Debug.debugLDIFRead(r);
    return r;
  }



  /**
   * Parses the provided set of lines into a list of {@code StringBuilder}
   * objects suitable for decoding into an entry or LDIF change record.
   * Comments will be ignored and wrapped lines will be unwrapped.
   *
   * @param  duplicateValueBehavior  The behavior that should be exhibited if
   *                                 the LDIF reader encounters an entry with
   *                                 duplicate values.
   * @param  trailingSpaceBehavior   The behavior that should be exhibited when
   *                                 encountering attribute values which are not
   *                                 base64-encoded but contain trailing spaces.
   * @param  schema                  The schema to use when parsing the record,
   *                                 if applicable.
   * @param  ldifLines               The set of lines that comprise the record
   *                                 to decode.  It must not be {@code null} or
   *                                 empty.
   *
   * @return  The prepared list of {@code StringBuilder} objects ready to be
   *          decoded.
   *
   * @throws  LDIFException  If the provided lines do not contain valid LDIF
   *                         content.
   */
  @NotNull()
  private static UnparsedLDIFRecord prepareRecord(
               @NotNull final DuplicateValueBehavior duplicateValueBehavior,
               @NotNull final TrailingSpaceBehavior trailingSpaceBehavior,
               @Nullable final Schema schema,
               @NotNull final String... ldifLines)
          throws LDIFException
  {
    Validator.ensureNotNull(ldifLines);
    Validator.ensureFalse(ldifLines.length == 0,
         "LDIFReader.prepareRecord.ldifLines must not be empty.");

    boolean lastWasComment = false;
    final ArrayList<StringBuilder> lineList = new ArrayList<>(ldifLines.length);
    for (int i=0; i < ldifLines.length; i++)
    {
      final String line = ldifLines[i];
      if (line.isEmpty())
      {
        // This is only acceptable if there are no more non-empty lines in the
        // array.
        for (int j=i+1; j < ldifLines.length; j++)
        {
          if (! ldifLines[j].isEmpty())
          {
            throw new LDIFException(ERR_READ_UNEXPECTED_BLANK.get(i), i, true,
                                    ldifLines, null);
          }

          // If we've gotten here, then we know that we're at the end of the
          // entry.  If we have read data, then we can decode it as an entry.
          // Otherwise, there was no real data in the provided LDIF lines.
          if (lineList.isEmpty())
          {
            throw new LDIFException(ERR_READ_ONLY_BLANKS.get(), 0, true,
                                    ldifLines, null);
          }
          else
          {
            return new UnparsedLDIFRecord(lineList, duplicateValueBehavior,
                 trailingSpaceBehavior, schema, 0);
          }
        }
      }

      if (line.charAt(0) == ' ')
      {
        if (i > 0)
        {
          if (! lastWasComment)
          {
            lineList.get(lineList.size() - 1).append(line.substring(1));
          }
        }
        else
        {
          throw new LDIFException(
                         ERR_READ_UNEXPECTED_FIRST_SPACE_NO_NUMBER.get(), 0,
                         true, ldifLines, null);
        }
      }
      else if (line.charAt(0) == '#')
      {
        lastWasComment = true;
      }
      else
      {
        lineList.add(new StringBuilder(line));
        lastWasComment = false;
      }
    }

    if (lineList.isEmpty())
    {
      throw new LDIFException(ERR_READ_NO_DATA.get(), 0, true, ldifLines, null);
    }
    else
    {
      return new UnparsedLDIFRecord(lineList, duplicateValueBehavior,
           trailingSpaceBehavior, schema, 0);
    }
  }



  /**
   * Decodes the unparsed record that was read from the LDIF source.  It may be
   * either an entry or an LDIF change record.
   *
   * @param  unparsedRecord    The unparsed LDIF record that was read from the
   *                           input.  It must not be {@code null} or empty.
   * @param  relativeBasePath  The base path that will be prepended to relative
   *                           paths in order to obtain an absolute path.
   * @param  schema            The schema to use when parsing.
   *
   * @return  The parsed record, or {@code null} if there are no more entries to
   *          be read.
   *
   * @throws  LDIFException  If the data read could not be parsed as an entry or
   *                         an LDIF change record.
   */
  @NotNull()
  private static LDIFRecord decodeRecord(
                      @NotNull final UnparsedLDIFRecord unparsedRecord,
                      @NotNull final String relativeBasePath,
                      @Nullable final Schema schema)
       throws LDIFException
  {
    // If there was an error reading from the input, then we rethrow it here.
    final Exception readError = unparsedRecord.getFailureCause();
    if (readError != null)
    {
      if (readError instanceof LDIFException)
      {
        // If the error was an LDIFException, which will normally be the case,
        // then rethrow it with all of the same state.  We could just
        //   throw (LDIFException) readError;
        // but that's considered bad form.
        final LDIFException ldifEx = (LDIFException) readError;
        throw new LDIFException(ldifEx.getMessage(),
                                ldifEx.getLineNumber(),
                                ldifEx.mayContinueReading(),
                                ldifEx.getDataLines(),
                                ldifEx.getCause());
      }
      else
      {
        throw new LDIFException(StaticUtils.getExceptionMessage(readError),
             -1, true, readError);
      }
    }

    if (unparsedRecord.isEOF())
    {
      return null;
    }

    final ArrayList<StringBuilder> lineList = unparsedRecord.getLineList();
    if (unparsedRecord.getLineList() == null)
    {
      return null;  // We can get here if there was an error reading the lines.
    }

    final LDIFRecord r;
    if (lineList.size() == 1)
    {
      r = decodeEntry(unparsedRecord, relativeBasePath);
    }
    else
    {
      final String lowerSecondLine =
           StaticUtils.toLowerCase(lineList.get(1).toString());
      if (lowerSecondLine.startsWith("control:") ||
          lowerSecondLine.startsWith("changetype:"))
      {
        r = decodeChangeRecord(unparsedRecord, relativeBasePath, true, schema);
      }
      else
      {
        r = decodeEntry(unparsedRecord, relativeBasePath);
      }
    }

    Debug.debugLDIFRead(r);
    return r;
  }



  /**
   * Decodes the provided set of LDIF lines as an entry.  The provided list must
   * not contain any blank lines or comments, and lines are not allowed to be
   * wrapped.
   *
   * @param  unparsedRecord   The unparsed LDIF record that was read from the
   *                          input.  It must not be {@code null} or empty.
   * @param  relativeBasePath  The base path that will be prepended to relative
   *                           paths in order to obtain an absolute path.
   *
   * @return  The entry read from LDIF.
   *
   * @throws  LDIFException  If the provided LDIF data cannot be read as an
   *                         entry.
   */
  @NotNull()
  private static Entry decodeEntry(
                            @NotNull final UnparsedLDIFRecord unparsedRecord,
                            @NotNull final String relativeBasePath)
          throws LDIFException
  {
    final ArrayList<StringBuilder> ldifLines = unparsedRecord.getLineList();
    final long firstLineNumber = unparsedRecord.getFirstLineNumber();

    final Iterator<StringBuilder> iterator = ldifLines.iterator();

    // The first line must start with either "version:" or "dn:".  If the first
    // line starts with "version:" then the second must start with "dn:".
    StringBuilder line = iterator.next();
    handleTrailingSpaces(line, null, firstLineNumber,
         unparsedRecord.getTrailingSpaceBehavior());
    int colonPos = line.indexOf(":");
    if ((colonPos > 0) &&
        line.substring(0, colonPos).equalsIgnoreCase("version"))
    {
      // The first line is "version:".  Under most conditions, this will be
      // handled by the LDIF reader, but this can happen if you call
      // decodeEntry with a set of data that includes a version.  At any rate,
      // read the next line, which must specify the DN.
      line = iterator.next();
      handleTrailingSpaces(line, null, firstLineNumber,
           unparsedRecord.getTrailingSpaceBehavior());
    }

    colonPos = line.indexOf(":");
    if ((colonPos < 0) ||
         (! line.substring(0, colonPos).equalsIgnoreCase("dn")))
    {
      throw new LDIFException(
           ERR_READ_DN_LINE_DOESNT_START_WITH_DN.get(firstLineNumber),
           firstLineNumber, true, ldifLines, null);
    }

    final String dn;
    final int length = line.length();
    if (length == (colonPos+1))
    {
      // The colon was the last character on the line.  This is acceptable and
      // indicates that the entry has the null DN.
      dn = "";
    }
    else if (line.charAt(colonPos+1) == ':')
    {
      // Skip over any spaces leading up to the value, and then the rest of the
      // string is the base64-encoded DN.
      int pos = colonPos+2;
      while ((pos < length) && (line.charAt(pos) == ' '))
      {
        pos++;
      }

      try
      {
        final byte[] dnBytes = Base64.decode(line.substring(pos));
        dn = StaticUtils.toUTF8String(dnBytes);
      }
      catch (final ParseException pe)
      {
        Debug.debugException(pe);
        throw new LDIFException(
                       ERR_READ_CANNOT_BASE64_DECODE_DN.get(firstLineNumber,
                                                            pe.getMessage()),
                       firstLineNumber, true, ldifLines, pe);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDIFException(
                       ERR_READ_CANNOT_BASE64_DECODE_DN.get(firstLineNumber, e),
                       firstLineNumber, true, ldifLines, e);
      }
    }
    else
    {
      // Skip over any spaces leading up to the value, and then the rest of the
      // string is the DN.
      int pos = colonPos+1;
      while ((pos < length) && (line.charAt(pos) == ' '))
      {
        pos++;
      }

      dn = line.substring(pos);
    }


    // The remaining lines must be the attributes for the entry.  However, we
    // will allow the case in which an entry does not have any attributes, to be
    // able to support reading search result entries in which no attributes were
    // returned.
    if (! iterator.hasNext())
    {
      return new Entry(dn, unparsedRecord.getSchema());
    }

    return new Entry(dn, unparsedRecord.getSchema(),
         parseAttributes(dn, unparsedRecord.getDuplicateValueBehavior(),
              unparsedRecord.getTrailingSpaceBehavior(),
              unparsedRecord.getSchema(), ldifLines, iterator, relativeBasePath,
              firstLineNumber));
  }



  /**
   * Decodes the provided set of LDIF lines as a change record.  The provided
   * list must not contain any blank lines or comments, and lines are not
   * allowed to be wrapped.
   *
   * @param  unparsedRecord    The unparsed LDIF record that was read from the
   *                           input.  It must not be {@code null} or empty.
   * @param  relativeBasePath  The base path that will be prepended to relative
   *                           paths in order to obtain an absolute path.
   * @param  defaultAdd        Indicates whether an LDIF record not containing a
   *                           changetype should be retrieved as an add change
   *                           record.  If this is {@code false} and the record
   *                           read does not include a changetype, then an
   *                           {@link LDIFException} will be thrown.
   * @param  schema            The schema to use in parsing.
   *
   * @return  The change record read from LDIF.
   *
   * @throws  LDIFException  If the provided LDIF data cannot be decoded as a
   *                         change record.
   */
  @NotNull()
  private static LDIFChangeRecord decodeChangeRecord(
                      @NotNull final UnparsedLDIFRecord unparsedRecord,
                      @NotNull final String relativeBasePath,
                      final boolean defaultAdd,
                      @Nullable final Schema schema)
          throws LDIFException
  {
    final ArrayList<StringBuilder> ldifLines = unparsedRecord.getLineList();
    final long firstLineNumber = unparsedRecord.getFirstLineNumber();

    Iterator<StringBuilder> iterator = ldifLines.iterator();

    // The first line must start with either "version:" or "dn:".  If the first
    // line starts with "version:" then the second must start with "dn:".
    StringBuilder line = iterator.next();
    handleTrailingSpaces(line, null, firstLineNumber,
         unparsedRecord.getTrailingSpaceBehavior());
    int colonPos = line.indexOf(":");
    int linesRead = 1;
    if ((colonPos > 0) &&
        line.substring(0, colonPos).equalsIgnoreCase("version"))
    {
      // The first line is "version:".  Under most conditions, this will be
      // handled by the LDIF reader, but this can happen if you call
      // decodeEntry with a set of data that includes a version.  At any rate,
      // read the next line, which must specify the DN.
      line = iterator.next();
      linesRead++;
      handleTrailingSpaces(line, null, firstLineNumber,
           unparsedRecord.getTrailingSpaceBehavior());
    }

    colonPos = line.indexOf(":");
    if ((colonPos < 0) ||
         (! line.substring(0, colonPos).equalsIgnoreCase("dn")))
    {
      throw new LDIFException(
           ERR_READ_DN_LINE_DOESNT_START_WITH_DN.get(firstLineNumber),
           firstLineNumber, true, ldifLines, null);
    }

    final String dn;
    final int length = line.length();
    if (length == (colonPos+1))
    {
      // The colon was the last character on the line.  This is acceptable and
      // indicates that the entry has the null DN.
      dn = "";
    }
    else if (line.charAt(colonPos+1) == ':')
    {
      // Skip over any spaces leading up to the value, and then the rest of the
      // string is the base64-encoded DN.
      int pos = colonPos+2;
      while ((pos < length) && (line.charAt(pos) == ' '))
      {
        pos++;
      }

      try
      {
        final byte[] dnBytes = Base64.decode(line.substring(pos));
        dn = StaticUtils.toUTF8String(dnBytes);
      }
      catch (final ParseException pe)
      {
        Debug.debugException(pe);
        throw new LDIFException(
                       ERR_READ_CR_CANNOT_BASE64_DECODE_DN.get(firstLineNumber,
                                                               pe.getMessage()),
                       firstLineNumber, true, ldifLines, pe);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDIFException(
                       ERR_READ_CR_CANNOT_BASE64_DECODE_DN.get(firstLineNumber,
                                                               e),
                       firstLineNumber, true, ldifLines, e);
      }
    }
    else
    {
      // Skip over any spaces leading up to the value, and then the rest of the
      // string is the DN.
      int pos = colonPos+1;
      while ((pos < length) && (line.charAt(pos) == ' '))
      {
        pos++;
      }

      dn = line.substring(pos);
    }


    // An LDIF change record may contain zero or more controls, with the end of
    // the controls signified by the changetype.  The changetype element must be
    // present, unless defaultAdd is true in which case the first thing that is
    // neither control or changetype will trigger the start of add attribute
    // parsing.
    if (! iterator.hasNext())
    {
      throw new LDIFException(ERR_READ_CR_TOO_SHORT.get(firstLineNumber),
                              firstLineNumber, true, ldifLines, null);
    }

    String changeType;
    ArrayList<Control> controls = null;
    while (true)
    {
      line = iterator.next();
      handleTrailingSpaces(line, dn, firstLineNumber,
           unparsedRecord.getTrailingSpaceBehavior());
      colonPos = line.indexOf(":");
      if (colonPos < 0)
      {
        throw new LDIFException(
             ERR_READ_CR_SECOND_LINE_MISSING_COLON.get(firstLineNumber),
             firstLineNumber, true, ldifLines, null);
      }

      final String token = StaticUtils.toLowerCase(line.substring(0, colonPos));
      if (token.equals("control"))
      {
        if (controls == null)
        {
          controls = new ArrayList<>(5);
        }

        controls.add(decodeControl(line, colonPos, firstLineNumber, ldifLines,
             relativeBasePath));
      }
      else if (token.equals("changetype"))
      {
        changeType =
             decodeChangeType(line, colonPos, firstLineNumber, ldifLines);
        break;
      }
      else if (defaultAdd)
      {
        // The line we read wasn't a control or changetype declaration, so we'll
        // assume it's an attribute in an add record.  However, we're not ready
        // for that yet, and since we can't rewind an iterator we'll create a
        // new one that hasn't yet gotten to this line.
        changeType = "add";
        iterator = ldifLines.iterator();
        for (int i=0; i < linesRead; i++)
        {
          iterator.next();
        }
        break;
      }
      else
      {
        throw new LDIFException(
             ERR_READ_CR_CT_LINE_DOESNT_START_WITH_CONTROL_OR_CT.get(
                  firstLineNumber),
             firstLineNumber, true, ldifLines, null);
      }

      linesRead++;
    }


    // Make sure that the change type is acceptable and then decode the rest of
    // the change record accordingly.
    final String lowerChangeType = StaticUtils.toLowerCase(changeType);
    if (lowerChangeType.equals("add"))
    {
      // There must be at least one more line.  If not, then that's an error.
      // Otherwise, parse the rest of the data as attribute-value pairs.
      if (iterator.hasNext())
      {
        final Collection<Attribute> attrs =
             parseAttributes(dn, unparsedRecord.getDuplicateValueBehavior(),
                  unparsedRecord.getTrailingSpaceBehavior(),
                  unparsedRecord.getSchema(), ldifLines, iterator,
                  relativeBasePath, firstLineNumber);
        final Attribute[] attributes = new Attribute[attrs.size()];
        final Iterator<Attribute> attrIterator = attrs.iterator();
        for (int i=0; i < attributes.length; i++)
        {
          attributes[i] = attrIterator.next();
        }

        return new LDIFAddChangeRecord(dn, attributes, controls);
      }
      else
      {
        throw new LDIFException(ERR_READ_CR_NO_ATTRIBUTES.get(firstLineNumber),
                                firstLineNumber, true, ldifLines, null);
      }
    }
    else if (lowerChangeType.equals("delete"))
    {
      // There shouldn't be any more data.  If there is, then that's an error.
      // Otherwise, we can just return the delete change record with what we
      // already know.
      if (iterator.hasNext())
      {
        throw new LDIFException(
                       ERR_READ_CR_EXTRA_DELETE_DATA.get(firstLineNumber),
                       firstLineNumber, true, ldifLines, null);
      }
      else
      {
        return new LDIFDeleteChangeRecord(dn, controls);
      }
    }
    else if (lowerChangeType.equals("modify"))
    {
      // There must be at least one more line.  If not, then that's an error.
      // Otherwise, parse the rest of the data as a set of modifications.
      if (iterator.hasNext())
      {
        final Modification[] mods = parseModifications(dn,
             unparsedRecord.getTrailingSpaceBehavior(), ldifLines, iterator,
             firstLineNumber, schema);
        return new LDIFModifyChangeRecord(dn, mods, controls);
      }
      else
      {
        throw new LDIFException(ERR_READ_CR_NO_MODS.get(firstLineNumber),
                                firstLineNumber, true, ldifLines, null);
      }
    }
    else if (lowerChangeType.equals("moddn") ||
             lowerChangeType.equals("modrdn"))
    {
      // There must be at least one more line.  If not, then that's an error.
      // Otherwise, parse the rest of the data as a set of modifications.
      if (iterator.hasNext())
      {
        return parseModifyDNChangeRecord(ldifLines, iterator, dn, controls,
             unparsedRecord.getTrailingSpaceBehavior(), firstLineNumber);
      }
      else
      {
        throw new LDIFException(ERR_READ_CR_NO_NEWRDN.get(firstLineNumber),
                                firstLineNumber, true, ldifLines, null);
      }
    }
    else
    {
      throw new LDIFException(ERR_READ_CR_INVALID_CT.get(changeType,
                                                         firstLineNumber),
                              firstLineNumber, true, ldifLines, null);
    }
  }



  /**
   * Decodes information about a control from the provided line.
   *
   * @param  line              The line to process.
   * @param  colonPos          The position of the colon that separates the
   *                           control token string from tbe encoded control.
   * @param  firstLineNumber   The line number for the start of the record.
   * @param  ldifLines         The lines that comprise the LDIF representation
   *                           of the full record being parsed.
   * @param  relativeBasePath  The base path that will be prepended to relative
   *                           paths in order to obtain an absolute path.
   *
   * @return  The decoded control.
   *
   * @throws  LDIFException  If a problem is encountered while trying to decode
   *                         the changetype.
   */
  @NotNull()
  private static Control decodeControl(@NotNull final StringBuilder line,
                              final int colonPos, final long firstLineNumber,
                              @NotNull final ArrayList<StringBuilder> ldifLines,
                              @NotNull final String relativeBasePath)
          throws LDIFException
  {
    final String controlString;
    int length = line.length();
    if (length == (colonPos+1))
    {
      // The colon was the last character on the line.  This is not
      // acceptable.
      throw new LDIFException(
           ERR_READ_CONTROL_LINE_NO_CONTROL_VALUE.get(firstLineNumber),
           firstLineNumber, true, ldifLines, null);
    }
    else if (line.charAt(colonPos+1) == ':')
    {
      // Skip over any spaces leading up to the value, and then the rest of
      // the string is the base64-encoded control representation.  This is
      // unusual and unnecessary, but is nevertheless acceptable.
      int pos = colonPos+2;
      while ((pos < length) && (line.charAt(pos) == ' '))
      {
        pos++;
      }

      try
      {
        final byte[] controlBytes = Base64.decode(line.substring(pos));
        controlString =  StaticUtils.toUTF8String(controlBytes);
      }
      catch (final ParseException pe)
      {
        Debug.debugException(pe);
        throw new LDIFException(
                       ERR_READ_CANNOT_BASE64_DECODE_CONTROL.get(
                            firstLineNumber, pe.getMessage()),
                       firstLineNumber, true, ldifLines, pe);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDIFException(
             ERR_READ_CANNOT_BASE64_DECODE_CONTROL.get(firstLineNumber, e),
             firstLineNumber, true, ldifLines, e);
      }
    }
    else
    {
      // Skip over any spaces leading up to the value, and then the rest of
      // the string is the encoded control.
      int pos = colonPos+1;
      while ((pos < length) && (line.charAt(pos) == ' '))
      {
        pos++;
      }

      controlString = line.substring(pos);
    }

    // If the resulting control definition is empty, then that's invalid.
    if (controlString.isEmpty())
    {
      throw new LDIFException(
           ERR_READ_CONTROL_LINE_NO_CONTROL_VALUE.get(firstLineNumber),
           firstLineNumber, true, ldifLines, null);
    }


    // The first element of the control must be the OID, and it must be followed
    // by a space (to separate it from the criticality), a colon (to separate it
    // from the value and indicate a default criticality of false), or the end
    // of the line (to indicate a default criticality of false and no value).
    String oid = null;
    boolean hasCriticality = false;
    boolean hasValue = false;
    int pos = 0;
    length = controlString.length();
    while (pos < length)
    {
      final char c = controlString.charAt(pos);
      if (c == ':')
      {
        // This indicates that there is no criticality and that the value
        // immediately follows the OID.
        oid = controlString.substring(0, pos++);
        hasValue = true;
        break;
      }
      else if (c == ' ')
      {
        // This indicates that there is a criticality.  We don't know anything
        // about the presence of a value yet.
        oid = controlString.substring(0, pos++);
        hasCriticality = true;
        break;
      }
      else
      {
        pos++;
      }
    }

    if (oid == null)
    {
      // This indicates that the string representation of the control is only
      // the OID.
      return new Control(controlString, false);
    }


    // See if we need to read the criticality.  If so, then do so now.
    // Otherwise, assume a default criticality of false.
    final boolean isCritical;
    if (hasCriticality)
    {
      // Skip over any spaces before the criticality.
      while (controlString.charAt(pos) == ' ')
      {
        pos++;
      }

      // Read until we find a colon or the end of the string.
      final int criticalityStartPos = pos;
      while (pos < length)
      {
        final char c = controlString.charAt(pos);
        if (c == ':')
        {
          hasValue = true;
          break;
        }
        else
        {
          pos++;
        }
      }

      final String criticalityString =
           StaticUtils.toLowerCase(controlString.substring(criticalityStartPos,
                pos));
      if (criticalityString.equals("true"))
      {
        isCritical = true;
      }
      else if (criticalityString.equals("false"))
      {
        isCritical = false;
      }
      else
      {
        throw new LDIFException(
             ERR_READ_CONTROL_LINE_INVALID_CRITICALITY.get(criticalityString,
                  firstLineNumber),
             firstLineNumber, true, ldifLines, null);
      }

      if (hasValue)
      {
        pos++;
      }
    }
    else
    {
      isCritical = false;
    }

    // See if we need to read the value.  If so, then do so now.  It may be
    // a string, or it may be base64-encoded.  It could conceivably even be read
    // from a URL.
    final ASN1OctetString value;
    if (hasValue)
    {
      // The character immediately after the colon that precedes the value may
      // be one of the following:
      // - A second colon (optionally followed by a single space) to indicate
      //   that the value is base64-encoded.
      // - A less-than symbol to indicate that the value should be read from a
      //   location specified by a URL.
      // - A single space that precedes the non-base64-encoded value.
      // - The first character of the non-base64-encoded value.
      switch (controlString.charAt(pos))
      {
        case ':':
          try
          {
            if (controlString.length() == (pos+1))
            {
              value = new ASN1OctetString();
            }
            else if (controlString.charAt(pos+1) == ' ')
            {
              value = new ASN1OctetString(
                   Base64.decode(controlString.substring(pos+2)));
            }
            else
            {
              value = new ASN1OctetString(
                   Base64.decode(controlString.substring(pos+1)));
            }
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new LDIFException(
                 ERR_READ_CONTROL_LINE_CANNOT_BASE64_DECODE_VALUE.get(
                      firstLineNumber, StaticUtils.getExceptionMessage(e)),
                 firstLineNumber, true, ldifLines, e);
          }
          break;
        case '<':
          try
          {
            final String urlString;
            if (controlString.charAt(pos+1) == ' ')
            {
              urlString = controlString.substring(pos+2);
            }
            else
            {
              urlString = controlString.substring(pos+1);
            }
            value = new ASN1OctetString(retrieveURLBytes(urlString,
                 relativeBasePath, firstLineNumber));
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new LDIFException(
                 ERR_READ_CONTROL_LINE_CANNOT_RETRIEVE_VALUE_FROM_URL.get(
                      firstLineNumber, StaticUtils.getExceptionMessage(e)),
                 firstLineNumber, true, ldifLines, e);
          }
          break;
        case ' ':
          value = new ASN1OctetString(controlString.substring(pos+1));
          break;
        default:
          value = new ASN1OctetString(controlString.substring(pos));
          break;
      }
    }
    else
    {
      value = null;
    }

    return new Control(oid, isCritical, value);
  }



  /**
   * Decodes the changetype element from the provided line.
   *
   * @param  line             The line to process.
   * @param  colonPos         The position of the colon that separates the
   *                          changetype string from its value.
   * @param  firstLineNumber  The line number for the start of the record.
   * @param  ldifLines        The lines that comprise the LDIF representation of
   *                          the full record being parsed.
   *
   * @return  The decoded changetype string.
   *
   * @throws  LDIFException  If a problem is encountered while trying to decode
   *                         the changetype.
   */
  @NotNull()
  private static String decodeChangeType(@NotNull final StringBuilder line,
                             final int colonPos, final long firstLineNumber,
                             @NotNull final ArrayList<StringBuilder> ldifLines)
          throws LDIFException
  {
    final int length = line.length();
    if (length == (colonPos+1))
    {
      // The colon was the last character on the line.  This is not
      // acceptable.
      throw new LDIFException(
           ERR_READ_CT_LINE_NO_CT_VALUE.get(firstLineNumber), firstLineNumber,
           true, ldifLines, null);
    }
    else if (line.charAt(colonPos+1) == ':')
    {
      // Skip over any spaces leading up to the value, and then the rest of
      // the string is the base64-encoded changetype.  This is unusual and
      // unnecessary, but is nevertheless acceptable.
      int pos = colonPos+2;
      while ((pos < length) && (line.charAt(pos) == ' '))
      {
        pos++;
      }

      try
      {
        final byte[] changeTypeBytes = Base64.decode(line.substring(pos));
        return StaticUtils.toUTF8String(changeTypeBytes);
      }
      catch (final ParseException pe)
      {
        Debug.debugException(pe);
        throw new LDIFException(
                       ERR_READ_CANNOT_BASE64_DECODE_CT.get(firstLineNumber,
                                                            pe.getMessage()),
                       firstLineNumber, true, ldifLines, pe);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDIFException(
             ERR_READ_CANNOT_BASE64_DECODE_CT.get(firstLineNumber, e),
             firstLineNumber, true, ldifLines, e);
      }
    }
    else
    {
      // Skip over any spaces leading up to the value, and then the rest of
      // the string is the changetype.
      int pos = colonPos+1;
      while ((pos < length) && (line.charAt(pos) == ' '))
      {
        pos++;
      }

      return line.substring(pos);
    }
  }



  /**
   * Parses the data available through the provided iterator as a collection of
   * attributes suitable for use in an entry or an add change record.
   *
   * @param  dn                      The DN of the record being read.
   * @param  duplicateValueBehavior  The behavior that should be exhibited if
   *                                 the LDIF reader encounters an entry with
   *                                 duplicate values.
   * @param  trailingSpaceBehavior   The behavior that should be exhibited when
   *                                 encountering attribute values which are not
   *                                 base64-encoded but contain trailing spaces.
   * @param  schema                  The schema to use when parsing the
   *                                 attributes, or {@code null} if none is
   *                                 needed.
   * @param  ldifLines               The lines that comprise the LDIF
   *                                 representation of the full record being
   *                                 parsed.
   * @param  iterator                The iterator to use to access the attribute
   *                                 lines.
   * @param  relativeBasePath        The base path that will be prepended to
   *                                 relative paths in order to obtain an
   *                                 absolute path.
   * @param  firstLineNumber         The line number for the start of the
   *                                 record.
   *
   * @return  The collection of attributes that were read.
   *
   * @throws  LDIFException  If the provided LDIF data cannot be decoded as a
   *                         set of attributes.
   */
  @NotNull()
  private static ArrayList<Attribute> parseAttributes(@NotNull final String dn,
               @NotNull final DuplicateValueBehavior duplicateValueBehavior,
               @NotNull final TrailingSpaceBehavior trailingSpaceBehavior,
               @Nullable final Schema schema,
               @NotNull final ArrayList<StringBuilder> ldifLines,
               @NotNull final Iterator<StringBuilder> iterator,
               @NotNull final String relativeBasePath,
               final long firstLineNumber)
          throws LDIFException
  {
    final LinkedHashMap<String,Object> attributes =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(ldifLines.size()));
    while (iterator.hasNext())
    {
      final StringBuilder line = iterator.next();
      handleTrailingSpaces(line, dn, firstLineNumber, trailingSpaceBehavior);
      final int colonPos = line.indexOf(":");
      if (colonPos <= 0)
      {
        throw new LDIFException(ERR_READ_NO_ATTR_COLON.get(firstLineNumber),
                                firstLineNumber, true, ldifLines, null);
      }

      final String attributeName = line.substring(0, colonPos);
      final String lowerName     = StaticUtils.toLowerCase(attributeName);

      final MatchingRule matchingRule;
      if (schema == null)
      {
        matchingRule = CaseIgnoreStringMatchingRule.getInstance();
      }
      else
      {
        matchingRule =
             MatchingRule.selectEqualityMatchingRule(attributeName, schema);
      }

      Attribute attr;
      final LDIFAttribute ldifAttr;
      final Object attrObject = attributes.get(lowerName);
      if (attrObject == null)
      {
        attr     = null;
        ldifAttr = null;
      }
      else
      {
        if (attrObject instanceof Attribute)
        {
          attr     = (Attribute) attrObject;
          ldifAttr = new LDIFAttribute(attr.getName(), matchingRule,
                                       attr.getRawValues()[0]);
          attributes.put(lowerName, ldifAttr);
        }
        else
        {
          attr     = null;
          ldifAttr = (LDIFAttribute) attrObject;
        }
      }

      final int length = line.length();
      if (length == (colonPos+1))
      {
        // This means that the attribute has a zero-length value, which is
        // acceptable.
        if (attrObject == null)
        {
          attr = new Attribute(attributeName, matchingRule, "");
          attributes.put(lowerName, attr);
        }
        else
        {
          try
          {
            if (! ldifAttr.addValue(new ASN1OctetString(),
                       duplicateValueBehavior))
            {
              if (duplicateValueBehavior != DuplicateValueBehavior.STRIP)
              {
                throw new LDIFException(ERR_READ_DUPLICATE_VALUE.get(dn,
                     firstLineNumber, attributeName), firstLineNumber, true,
                     ldifLines, null);
              }
            }
          }
          catch (final LDAPException le)
          {
            throw new LDIFException(
                 ERR_READ_VALUE_SYNTAX_VIOLATION.get(dn, firstLineNumber,
                      attributeName, StaticUtils.getExceptionMessage(le)),
                 firstLineNumber, true, ldifLines, le);
          }
        }
      }
      else if (line.charAt(colonPos+1) == ':')
      {
        // Skip over any spaces leading up to the value, and then the rest of
        // the string is the base64-encoded attribute value.
        int pos = colonPos+2;
        while ((pos < length) && (line.charAt(pos) == ' '))
        {
          pos++;
        }

        try
        {
          final byte[] valueBytes = Base64.decode(line.substring(pos));
          if (attrObject == null)
          {
            attr = new Attribute(attributeName, matchingRule, valueBytes);
            attributes.put(lowerName, attr);
          }
          else
          {
            try
            {
              if (! ldifAttr.addValue(new ASN1OctetString(valueBytes),
                         duplicateValueBehavior))
              {
                if (duplicateValueBehavior != DuplicateValueBehavior.STRIP)
                {
                  throw new LDIFException(ERR_READ_DUPLICATE_VALUE.get(dn,
                       firstLineNumber, attributeName), firstLineNumber, true,
                       ldifLines, null);
                }
              }
            }
            catch (final LDAPException le)
            {
              throw new LDIFException(
                   ERR_READ_VALUE_SYNTAX_VIOLATION.get(dn, firstLineNumber,
                        attributeName, StaticUtils.getExceptionMessage(le)),
                   firstLineNumber, true, ldifLines, le);
            }
          }
        }
        catch (final ParseException pe)
        {
          Debug.debugException(pe);
          throw new LDIFException(
               ERR_READ_CANNOT_BASE64_DECODE_ATTR.get(attributeName,
                    firstLineNumber, pe.getMessage()),
               firstLineNumber, true, ldifLines, pe);
        }
      }
      else if (line.charAt(colonPos+1) == '<')
      {
        // Skip over any spaces leading up to the value, and then the rest of
        // the string is a URL that indicates where to get the real content.
        // At the present time, we'll only support the file URLs.
        int pos = colonPos+2;
        while ((pos < length) && (line.charAt(pos) == ' '))
        {
          pos++;
        }

        final byte[] urlBytes;
        final String urlString = line.substring(pos);
        try
        {
          urlBytes =
               retrieveURLBytes(urlString, relativeBasePath, firstLineNumber);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new LDIFException(
               ERR_READ_URL_EXCEPTION.get(attributeName, urlString,
                    firstLineNumber, e),
               firstLineNumber, true, ldifLines, e);
        }

        if (attrObject == null)
        {
          attr = new Attribute(attributeName, matchingRule, urlBytes);
          attributes.put(lowerName, attr);
        }
        else
        {
          try
          {
            if (! ldifAttr.addValue(new ASN1OctetString(urlBytes),
                 duplicateValueBehavior))
            {
              if (duplicateValueBehavior != DuplicateValueBehavior.STRIP)
              {
                throw new LDIFException(ERR_READ_DUPLICATE_VALUE.get(dn,
                     firstLineNumber, attributeName), firstLineNumber, true,
                     ldifLines, null);
              }
            }
          }
          catch (final LDIFException le)
          {
            Debug.debugException(le);
            throw le;
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new LDIFException(
                 ERR_READ_URL_EXCEPTION.get(attributeName, urlString,
                      firstLineNumber, e),
                 firstLineNumber, true, ldifLines, e);
          }
        }
      }
      else
      {
        // Skip over any spaces leading up to the value, and then the rest of
        // the string is the value.
        int pos = colonPos+1;
        while ((pos < length) && (line.charAt(pos) == ' '))
        {
          pos++;
        }

        final String valueString = line.substring(pos);
        if (attrObject == null)
        {
          attr = new Attribute(attributeName, matchingRule, valueString);
          attributes.put(lowerName, attr);
        }
        else
        {
          try
          {
            if (! ldifAttr.addValue(new ASN1OctetString(valueString),
                       duplicateValueBehavior))
            {
              if (duplicateValueBehavior != DuplicateValueBehavior.STRIP)
              {
                throw new LDIFException(ERR_READ_DUPLICATE_VALUE.get(dn,
                     firstLineNumber, attributeName), firstLineNumber, true,
                     ldifLines, null);
              }
            }
          }
          catch (final LDAPException le)
          {
            throw new LDIFException(
                 ERR_READ_VALUE_SYNTAX_VIOLATION.get(dn, firstLineNumber,
                      attributeName, StaticUtils.getExceptionMessage(le)),
                 firstLineNumber, true, ldifLines, le);
          }
        }
      }
    }

    final ArrayList<Attribute> attrList = new ArrayList<>(attributes.size());
    for (final Object o : attributes.values())
    {
      if (o instanceof Attribute)
      {
        attrList.add((Attribute) o);
      }
      else
      {
        attrList.add(((LDIFAttribute) o).toAttribute());
      }
    }

    return attrList;
  }



  /**
   * Retrieves the bytes that make up the file referenced by the given URL.
   *
   * @param  urlString         The string representation of the URL to retrieve.
   * @param  relativeBasePath  The base path that will be prepended to relative
   *                           paths in order to obtain an absolute path.
   * @param  firstLineNumber   The line number for the start of the record.
   *
   * @return  The bytes contained in the specified file, or an empty array if
   *          the specified file is empty.
   *
   * @throws  LDIFException  If the provided URL is malformed or references a
   *                         nonexistent file.
   *
   * @throws  IOException  If a problem is encountered while attempting to read
   *                       from the target file.
   */
  @NotNull()
  private static byte[] retrieveURLBytes(@NotNull final String urlString,
                                         @NotNull final String relativeBasePath,
                                         final long firstLineNumber)
          throws LDIFException, IOException
  {
    int pos;
    final String path;
    final String lowerURLString = StaticUtils.toLowerCase(urlString);
    if (lowerURLString.startsWith("file:/"))
    {
      pos = 6;
      while ((pos < urlString.length()) && (urlString.charAt(pos) == '/'))
      {
        pos++;
      }

      path = urlString.substring(pos-1);
    }
    else if (lowerURLString.startsWith("file:"))
    {
      // A file: URL that doesn't include a slash will be interpreted as a
      // relative path.
      path = relativeBasePath + urlString.substring(5);
    }
    else
    {
      throw new LDIFException(ERR_READ_URL_INVALID_SCHEME.get(urlString),
           firstLineNumber, true);
    }

    final File f = new File(path);
    if (! f.exists())
    {
      throw new LDIFException(
           ERR_READ_URL_NO_SUCH_FILE.get(urlString, f.getAbsolutePath()),
           firstLineNumber, true);
    }

    // In order to conserve memory, we'll only allow values to be read from
    // files no larger than 10 megabytes.
    final long fileSize = f.length();
    if (fileSize > (10 * 1024 * 1024))
    {
      throw new LDIFException(
           ERR_READ_URL_FILE_TOO_LARGE.get(urlString, f.getAbsolutePath(),
                (10*1024*1024)),
           firstLineNumber, true);
    }

    int fileBytesRemaining = (int) fileSize;
    final byte[] fileData = new byte[(int) fileSize];
    final FileInputStream fis = new FileInputStream(f);
    try
    {
      int fileBytesRead = 0;
      while (fileBytesRead < fileSize)
      {
        final int bytesRead =
             fis.read(fileData, fileBytesRead, fileBytesRemaining);
        if (bytesRead < 0)
        {
          // We hit the end of the file before we expected to.  This shouldn't
          // happen unless the file size changed since we first looked at it,
          // which we won't allow.
          throw new LDIFException(
               ERR_READ_URL_FILE_SIZE_CHANGED.get(urlString,
                    f.getAbsolutePath()),
               firstLineNumber, true);
        }

        fileBytesRead      += bytesRead;
        fileBytesRemaining -= bytesRead;
      }

      if (fis.read() != -1)
      {
        // There is still more data to read.  This shouldn't happen unless the
        // file size changed since we first looked at it, which we won't allow.
        throw new LDIFException(
             ERR_READ_URL_FILE_SIZE_CHANGED.get(urlString, f.getAbsolutePath()),
             firstLineNumber, true);
      }
    }
    finally
    {
      fis.close();
    }

    return fileData;
  }



  /**
   * Parses the data available through the provided iterator into an array of
   * modifications suitable for use in a modify change record.
   *
   * @param  dn                     The DN of the entry being parsed.
   * @param  trailingSpaceBehavior  The behavior that should be exhibited when
   *                                encountering attribute values which are not
   *                                base64-encoded but contain trailing spaces.
   * @param  ldifLines              The lines that comprise the LDIF
   *                                representation of the full record being
   *                                parsed.
   * @param  iterator               The iterator to use to access the
   *                                modification data.
   * @param  firstLineNumber        The line number for the start of the record.
   * @param  schema                 The schema to use in processing.
   *
   * @return  An array containing the modifications that were read.
   *
   * @throws  LDIFException  If the provided LDIF data cannot be decoded as a
   *                         set of modifications.
   */
  @NotNull()
  private static Modification[] parseModifications(@NotNull final String dn,
               @NotNull final TrailingSpaceBehavior trailingSpaceBehavior,
               @NotNull final ArrayList<StringBuilder> ldifLines,
               @NotNull final Iterator<StringBuilder> iterator,
               final long firstLineNumber, @Nullable final Schema schema)
          throws LDIFException
  {
    final ArrayList<Modification> modList = new ArrayList<>(ldifLines.size());

    while (iterator.hasNext())
    {
      // The first line must start with "add:", "delete:", "replace:", or
      // "increment:" followed by an attribute name.
      StringBuilder line = iterator.next();
      handleTrailingSpaces(line, dn, firstLineNumber, trailingSpaceBehavior);
      int colonPos = line.indexOf(":");
      if (colonPos < 0)
      {
        throw new LDIFException(ERR_READ_MOD_CR_NO_MODTYPE.get(firstLineNumber),
                                firstLineNumber, true, ldifLines, null);
      }

      final ModificationType modType;
      final String modTypeStr =
           StaticUtils.toLowerCase(line.substring(0, colonPos));
      if (modTypeStr.equals("add"))
      {
        modType = ModificationType.ADD;
      }
      else if (modTypeStr.equals("delete"))
      {
        modType = ModificationType.DELETE;
      }
      else if (modTypeStr.equals("replace"))
      {
        modType = ModificationType.REPLACE;
      }
      else if (modTypeStr.equals("increment"))
      {
        modType = ModificationType.INCREMENT;
      }
      else
      {
        throw new LDIFException(ERR_READ_MOD_CR_INVALID_MODTYPE.get(modTypeStr,
                                     firstLineNumber),
                                firstLineNumber, true, ldifLines, null);
      }

      String attributeName;
      int length = line.length();
      if (length == (colonPos+1))
      {
        // The colon was the last character on the line.  This is not
        // acceptable.
        throw new LDIFException(ERR_READ_MOD_CR_MODTYPE_NO_ATTR.get(
                                     firstLineNumber),
                                firstLineNumber, true, ldifLines, null);
      }
      else if (line.charAt(colonPos+1) == ':')
      {
        // Skip over any spaces leading up to the value, and then the rest of
        // the string is the base64-encoded attribute name.
        int pos = colonPos+2;
        while ((pos < length) && (line.charAt(pos) == ' '))
        {
          pos++;
        }

        try
        {
          final byte[] dnBytes = Base64.decode(line.substring(pos));
          attributeName = StaticUtils.toUTF8String(dnBytes);
        }
        catch (final ParseException pe)
        {
          Debug.debugException(pe);
          throw new LDIFException(
               ERR_READ_MOD_CR_MODTYPE_CANNOT_BASE64_DECODE_ATTR.get(
                    firstLineNumber, pe.getMessage()),
               firstLineNumber, true, ldifLines, pe);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new LDIFException(
               ERR_READ_MOD_CR_MODTYPE_CANNOT_BASE64_DECODE_ATTR.get(
                    firstLineNumber, e),
               firstLineNumber, true, ldifLines, e);
        }
      }
      else
      {
        // Skip over any spaces leading up to the value, and then the rest of
        // the string is the attribute name.
        int pos = colonPos+1;
        while ((pos < length) && (line.charAt(pos) == ' '))
        {
          pos++;
        }

        attributeName = line.substring(pos);
      }

      if (attributeName.isEmpty())
      {
        throw new LDIFException(ERR_READ_MOD_CR_MODTYPE_NO_ATTR.get(
                                     firstLineNumber),
                                firstLineNumber, true, ldifLines, null);
      }


      // The next zero or more lines may be the set of attribute values.  Keep
      // reading until we reach the end of the iterator or until we find a line
      // with just a "-".
      final ArrayList<ASN1OctetString> valueList =
           new ArrayList<>(ldifLines.size());
      while (iterator.hasNext())
      {
        line = iterator.next();
        handleTrailingSpaces(line, dn, firstLineNumber, trailingSpaceBehavior);
        if (line.toString().equals("-"))
        {
          break;
        }

        colonPos = line.indexOf(":");
        if (colonPos < 0)
        {
          throw new LDIFException(ERR_READ_NO_ATTR_COLON.get(firstLineNumber),
                                  firstLineNumber, true, ldifLines, null);
        }
        else if (! line.substring(0, colonPos).equalsIgnoreCase(attributeName))
        {
          // There are a couple of cases in which this might be acceptable:
          // - If the two names are logically equivalent, but have an alternate
          //   name (or OID) for the target attribute type, or if there are
          //   attribute options and the options are just in a different order.
          // - If this is the first value for the target attribute and the
          //   alternate name includes a "binary" option that the original
          //   attribute name did not have.  In this case, all subsequent values
          //   will also be required to have the binary option.
          final String alternateName = line.substring(0, colonPos);


          // Check to see if the base names are equivalent.
          boolean baseNameEquivalent = false;
          final String expectedBaseName = Attribute.getBaseName(attributeName);
          final String alternateBaseName = Attribute.getBaseName(alternateName);
          if (alternateBaseName.equalsIgnoreCase(expectedBaseName))
          {
            baseNameEquivalent = true;
          }
          else
          {
            if (schema != null)
            {
              final AttributeTypeDefinition expectedAT =
                   schema.getAttributeType(expectedBaseName);
              final AttributeTypeDefinition alternateAT =
                   schema.getAttributeType(alternateBaseName);
              if ((expectedAT != null) && (alternateAT != null) &&
                  expectedAT.equals(alternateAT))
              {
                baseNameEquivalent = true;
              }
            }
          }


          // Check to see if the attribute options are equivalent.
          final Set<String> expectedOptions =
               Attribute.getOptions(attributeName);
          final Set<String> lowerExpectedOptions = new HashSet<>(
               StaticUtils.computeMapCapacity(expectedOptions.size()));
          for (final String s : expectedOptions)
          {
            lowerExpectedOptions.add(StaticUtils.toLowerCase(s));
          }

          final Set<String> alternateOptions =
               Attribute.getOptions(alternateName);
          final Set<String> lowerAlternateOptions = new HashSet<>(
               StaticUtils.computeMapCapacity(alternateOptions.size()));
          for (final String s : alternateOptions)
          {
            lowerAlternateOptions.add(StaticUtils.toLowerCase(s));
          }

          final boolean optionsEquivalent =
               lowerAlternateOptions.equals(lowerExpectedOptions);


          if (baseNameEquivalent && optionsEquivalent)
          {
            // This is fine.  The two attribute descriptions are logically
            // equivalent.  We'll continue using the attribute description that
            // was provided first.
          }
          else if (valueList.isEmpty() && baseNameEquivalent &&
                   lowerAlternateOptions.remove("binary") &&
                   lowerAlternateOptions.equals(lowerExpectedOptions))
          {
            // This means that the provided value is the first value for the
            // attribute, and that the only significant difference is that the
            // provided attribute description included an unexpected "binary"
            // option.  We'll accept this, but will require any additional
            // values for this modification to also include the binary option,
            // and we'll use the binary option in the attribute that is
            // eventually created.
            attributeName = alternateName;
          }
          else
          {
            // This means that either the base names are different or the sets
            // of options are incompatible.  This is not acceptable.
            throw new LDIFException(ERR_READ_MOD_CR_ATTR_MISMATCH.get(
                                         firstLineNumber,
                                         line.substring(0, colonPos),
                                         attributeName),
                                    firstLineNumber, true, ldifLines, null);
          }
        }

        length = line.length();
        final ASN1OctetString value;
        if (length == (colonPos+1))
        {
          // The colon was the last character on the line.  This is fine.
          value = new ASN1OctetString();
        }
        else if (line.charAt(colonPos+1) == ':')
        {
          // Skip over any spaces leading up to the value, and then the rest of
          // the string is the base64-encoded value.  This is unusual and
          // unnecessary, but is nevertheless acceptable.
          int pos = colonPos+2;
          while ((pos < length) && (line.charAt(pos) == ' '))
          {
            pos++;
          }

          try
          {
            value = new ASN1OctetString(Base64.decode(line.substring(pos)));
          }
          catch (final ParseException pe)
          {
            Debug.debugException(pe);
            throw new LDIFException(ERR_READ_CANNOT_BASE64_DECODE_ATTR.get(
                 attributeName, firstLineNumber, pe.getMessage()),
                 firstLineNumber, true, ldifLines, pe);
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new LDIFException(ERR_READ_CANNOT_BASE64_DECODE_ATTR.get(
                                         firstLineNumber, e),
                                    firstLineNumber, true, ldifLines, e);
          }
        }
        else
        {
          // Skip over any spaces leading up to the value, and then the rest of
          // the string is the value.
          int pos = colonPos+1;
          while ((pos < length) && (line.charAt(pos) == ' '))
          {
            pos++;
          }

          value = new ASN1OctetString(line.substring(pos));
        }

        valueList.add(value);
      }

      final ASN1OctetString[] values = new ASN1OctetString[valueList.size()];
      valueList.toArray(values);

      // If it's an add modification type, then there must be at least one
      // value.
      if ((modType.intValue() == ModificationType.ADD.intValue()) &&
          (values.length == 0))
      {
        throw new LDIFException(ERR_READ_MOD_CR_NO_ADD_VALUES.get(attributeName,
                                     firstLineNumber),
                                firstLineNumber, true, ldifLines, null);
      }

      // If it's an increment modification type, then there must be exactly one
      // value.
      if ((modType.intValue() == ModificationType.INCREMENT.intValue()) &&
          (values.length != 1))
      {
        throw new LDIFException(ERR_READ_MOD_CR_INVALID_INCR_VALUE_COUNT.get(
                                     firstLineNumber, attributeName),
                                firstLineNumber, true, ldifLines, null);
      }

      modList.add(new Modification(modType, attributeName, values));
    }

    final Modification[] mods = new Modification[modList.size()];
    modList.toArray(mods);
    return mods;
  }



  /**
   * Parses the data available through the provided iterator as the body of a
   * modify DN change record (i.e., the newrdn, deleteoldrdn, and optional
   * newsuperior lines).
   *
   * @param  ldifLines              The lines that comprise the LDIF
   *                                representation of the full record being
   *                                parsed.
   * @param  iterator               The iterator to use to access the modify DN
   *                                data.
   * @param  dn                     The current DN of the entry.
   * @param  controls               The set of controls to include in the change
   *                                record.
   * @param  trailingSpaceBehavior  The behavior that should be exhibited when
   *                                encountering attribute values which are not
   *                                base64-encoded but contain trailing spaces.
   * @param  firstLineNumber        The line number for the start of the record.
   *
   * @return  The decoded modify DN change record.
   *
   * @throws  LDIFException  If the provided LDIF data cannot be decoded as a
   *                         modify DN change record.
   */
  @NotNull()
  private static LDIFModifyDNChangeRecord parseModifyDNChangeRecord(
               @NotNull final ArrayList<StringBuilder> ldifLines,
               @NotNull final Iterator<StringBuilder> iterator,
               @NotNull final String dn,
               @Nullable final List<Control> controls,
               @NotNull final TrailingSpaceBehavior trailingSpaceBehavior,
               final long firstLineNumber)
          throws LDIFException
  {
    // The next line must be the new RDN, and it must start with "newrdn:".
    StringBuilder line = iterator.next();
    handleTrailingSpaces(line, dn, firstLineNumber, trailingSpaceBehavior);
    int colonPos = line.indexOf(":");
    if ((colonPos < 0) ||
        (! line.substring(0, colonPos).equalsIgnoreCase("newrdn")))
    {
      throw new LDIFException(ERR_READ_MODDN_CR_NO_NEWRDN_COLON.get(
                                   firstLineNumber),
                              firstLineNumber, true, ldifLines, null);
    }

    final String newRDN;
    int length = line.length();
    if (length == (colonPos+1))
    {
      // The colon was the last character on the line.  This is not acceptable.
      throw new LDIFException(ERR_READ_MODDN_CR_NO_NEWRDN_VALUE.get(
                                   firstLineNumber),
                              firstLineNumber, true, ldifLines, null);
    }
    else if (line.charAt(colonPos+1) == ':')
    {
      // Skip over any spaces leading up to the value, and then the rest of the
      // string is the base64-encoded new RDN.
      int pos = colonPos+2;
      while ((pos < length) && (line.charAt(pos) == ' '))
      {
        pos++;
      }

      try
      {
        final byte[] dnBytes = Base64.decode(line.substring(pos));
        newRDN = StaticUtils.toUTF8String(dnBytes);
      }
      catch (final ParseException pe)
      {
        Debug.debugException(pe);
        throw new LDIFException(
             ERR_READ_MODDN_CR_CANNOT_BASE64_DECODE_NEWRDN.get(firstLineNumber,
                                                               pe.getMessage()),
             firstLineNumber, true, ldifLines, pe);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDIFException(
             ERR_READ_MODDN_CR_CANNOT_BASE64_DECODE_NEWRDN.get(firstLineNumber,
                                                               e),
             firstLineNumber, true, ldifLines, e);
      }
    }
    else
    {
      // Skip over any spaces leading up to the value, and then the rest of the
      // string is the new RDN.
      int pos = colonPos+1;
      while ((pos < length) && (line.charAt(pos) == ' '))
      {
        pos++;
      }

      newRDN = line.substring(pos);
    }

    if (newRDN.isEmpty())
    {
      throw new LDIFException(ERR_READ_MODDN_CR_NO_NEWRDN_VALUE.get(
                                   firstLineNumber),
                              firstLineNumber, true, ldifLines, null);
    }


    // The next line must be the deleteOldRDN flag, and it must start with
    // 'deleteoldrdn:'.
    if (! iterator.hasNext())
    {
      throw new LDIFException(ERR_READ_MODDN_CR_NO_DELOLDRDN_COLON.get(
                                   firstLineNumber),
                              firstLineNumber, true, ldifLines, null);
    }

    line = iterator.next();
    handleTrailingSpaces(line, dn, firstLineNumber, trailingSpaceBehavior);
    colonPos = line.indexOf(":");
    if ((colonPos < 0) ||
        (! line.substring(0, colonPos).equalsIgnoreCase("deleteoldrdn")))
    {
      throw new LDIFException(ERR_READ_MODDN_CR_NO_DELOLDRDN_COLON.get(
                                   firstLineNumber),
                              firstLineNumber, true, ldifLines, null);
    }

    final String deleteOldRDNStr;
    length = line.length();
    if (length == (colonPos+1))
    {
      // The colon was the last character on the line.  This is not acceptable.
      throw new LDIFException(ERR_READ_MODDN_CR_NO_DELOLDRDN_VALUE.get(
                                   firstLineNumber),
                              firstLineNumber, true, ldifLines, null);
    }
    else if (line.charAt(colonPos+1) == ':')
    {
      // Skip over any spaces leading up to the value, and then the rest of the
      // string is the base64-encoded value.  This is unusual and
      // unnecessary, but is nevertheless acceptable.
      int pos = colonPos+2;
      while ((pos < length) && (line.charAt(pos) == ' '))
      {
        pos++;
      }

      try
      {
        final byte[] changeTypeBytes = Base64.decode(line.substring(pos));
        deleteOldRDNStr = StaticUtils.toUTF8String(changeTypeBytes);
      }
      catch (final ParseException pe)
      {
        Debug.debugException(pe);
        throw new LDIFException(
             ERR_READ_MODDN_CR_CANNOT_BASE64_DECODE_DELOLDRDN.get(
                  firstLineNumber, pe.getMessage()),
             firstLineNumber, true, ldifLines, pe);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDIFException(
             ERR_READ_MODDN_CR_CANNOT_BASE64_DECODE_DELOLDRDN.get(
                  firstLineNumber, e),
             firstLineNumber, true, ldifLines, e);
      }
    }
    else
    {
      // Skip over any spaces leading up to the value, and then the rest of the
      // string is the value.
      int pos = colonPos+1;
      while ((pos < length) && (line.charAt(pos) == ' '))
      {
        pos++;
      }

      deleteOldRDNStr = line.substring(pos);
    }

    final boolean deleteOldRDN;
    if (deleteOldRDNStr.equals("0"))
    {
      deleteOldRDN = false;
    }
    else if (deleteOldRDNStr.equals("1"))
    {
      deleteOldRDN = true;
    }
    else if (deleteOldRDNStr.equalsIgnoreCase("false") ||
             deleteOldRDNStr.equalsIgnoreCase("no"))
    {
      // This is technically illegal, but we'll allow it.
      deleteOldRDN = false;
    }
    else if (deleteOldRDNStr.equalsIgnoreCase("true") ||
             deleteOldRDNStr.equalsIgnoreCase("yes"))
    {
      // This is also technically illegal, but we'll allow it.
      deleteOldRDN = false;
    }
    else
    {
      throw new LDIFException(ERR_READ_MODDN_CR_INVALID_DELOLDRDN.get(
                                   deleteOldRDNStr, firstLineNumber),
                              firstLineNumber, true, ldifLines, null);
    }


    // If there is another line, then it must be the new superior DN and it must
    // start with "newsuperior:".  If this is absent, then it's fine.
    final String newSuperiorDN;
    if (iterator.hasNext())
    {
      line = iterator.next();
      handleTrailingSpaces(line, dn, firstLineNumber, trailingSpaceBehavior);
      colonPos = line.indexOf(":");
      if ((colonPos < 0) ||
          (! line.substring(0, colonPos).equalsIgnoreCase("newsuperior")))
      {
        throw new LDIFException(ERR_READ_MODDN_CR_NO_NEWSUPERIOR_COLON.get(
                                     firstLineNumber),
                                firstLineNumber, true, ldifLines, null);
      }

      length = line.length();
      if (length == (colonPos+1))
      {
        // The colon was the last character on the line.  This is fine.
        newSuperiorDN = "";
      }
      else if (line.charAt(colonPos+1) == ':')
      {
        // Skip over any spaces leading up to the value, and then the rest of
        // the string is the base64-encoded new superior DN.
        int pos = colonPos+2;
        while ((pos < length) && (line.charAt(pos) == ' '))
        {
          pos++;
        }

        try
        {
          final byte[] dnBytes = Base64.decode(line.substring(pos));
          newSuperiorDN = StaticUtils.toUTF8String(dnBytes);
        }
        catch (final ParseException pe)
        {
          Debug.debugException(pe);
          throw new LDIFException(
               ERR_READ_MODDN_CR_CANNOT_BASE64_DECODE_NEWSUPERIOR.get(
                    firstLineNumber, pe.getMessage()),
               firstLineNumber, true, ldifLines, pe);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new LDIFException(
               ERR_READ_MODDN_CR_CANNOT_BASE64_DECODE_NEWSUPERIOR.get(
                    firstLineNumber, e),
               firstLineNumber, true, ldifLines, e);
        }
      }
      else
      {
        // Skip over any spaces leading up to the value, and then the rest of
        // the string is the new superior DN.
        int pos = colonPos+1;
        while ((pos < length) && (line.charAt(pos) == ' '))
        {
          pos++;
        }

        newSuperiorDN = line.substring(pos);
      }
    }
    else
    {
      newSuperiorDN = null;
    }


    // There must not be any more lines.
    if (iterator.hasNext())
    {
      throw new LDIFException(ERR_READ_CR_EXTRA_MODDN_DATA.get(firstLineNumber),
                              firstLineNumber, true, ldifLines, null);
    }

    return new LDIFModifyDNChangeRecord(dn, newRDN, deleteOldRDN,
         newSuperiorDN, controls);
  }



  /**
   * Examines the line contained in the provided buffer to determine whether it
   * may contain one or more illegal trailing spaces.  If it does, then those
   * spaces will either be stripped out or an exception will be thrown to
   * indicate that they are illegal.
   *
   * @param  buffer                 The buffer to be examined.
   * @param  dn                     The DN of the LDIF record being parsed.  It
   *                                may be {@code null} if the DN is not yet
   *                                known (e.g., because the provided line is
   *                                expected to contain that DN).
   * @param  firstLineNumber        The approximate line number in the LDIF
   *                                source on which the LDIF record begins.
   * @param  trailingSpaceBehavior  The behavior that should be exhibited when
   *                                encountering attribute values which are not
   *                                base64-encoded but contain trailing spaces.
   *
   * @throws  LDIFException  If the line contained in the provided buffer ends
   *                         with one or more illegal trailing spaces and
   *                         {@code stripTrailingSpaces} was provided with a
   *                         value of {@code false}.
   */
  private static void handleTrailingSpaces(@NotNull final StringBuilder buffer,
               @Nullable final String dn, final long firstLineNumber,
               @NotNull final TrailingSpaceBehavior trailingSpaceBehavior)
          throws LDIFException
  {
    int pos = buffer.length() - 1;
    boolean trailingFound = false;
    while ((pos >= 0) && (buffer.charAt(pos) == ' '))
    {
      trailingFound = true;
      pos--;
    }

    if (trailingFound && (buffer.charAt(pos) != ':'))
    {
      switch (trailingSpaceBehavior)
      {
        case STRIP:
          buffer.setLength(pos+1);
          break;

        case REJECT:
          if (dn == null)
          {
            throw new LDIFException(
                 ERR_READ_ILLEGAL_TRAILING_SPACE_WITHOUT_DN.get(firstLineNumber,
                      buffer.toString()),
                 firstLineNumber, true);
          }
          else
          {
            throw new LDIFException(
                 ERR_READ_ILLEGAL_TRAILING_SPACE_WITH_DN.get(dn,
                      firstLineNumber, buffer.toString()),
                 firstLineNumber, true);
          }

        case RETAIN:
        default:
          // No action will be taken.
          break;
      }
    }
  }



  /**
   * This represents an unparsed LDIFRecord.  It stores the line number of the
   * first line of the record and each line of the record.
   */
  private static final class UnparsedLDIFRecord
  {
    @Nullable private final ArrayList<StringBuilder> lineList;
    private final long firstLineNumber;
    @Nullable private final Exception failureCause;
    private final boolean isEOF;
    @NotNull private final DuplicateValueBehavior duplicateValueBehavior;
    @Nullable private final Schema schema;
    @NotNull private final TrailingSpaceBehavior trailingSpaceBehavior;



    /**
     * Creates a new instance of this record.
     *
     * @param  lineList                The lines that comprise the LDIF record.
     * @param  duplicateValueBehavior  The behavior to exhibit if the entry
     *                                 contains duplicate attribute values.
     * @param  trailingSpaceBehavior   Specifies the behavior to exhibit when
     *                                 encountering trailing spaces in
     *                                 non-base64-encoded attribute values.
     * @param  schema                  The schema to use when parsing, if
     *                                 applicable.
     * @param  firstLineNumber         The first line number of the LDIF record.
     */
    private UnparsedLDIFRecord(@NotNull final ArrayList<StringBuilder> lineList,
                 @NotNull final DuplicateValueBehavior duplicateValueBehavior,
                 @NotNull final TrailingSpaceBehavior trailingSpaceBehavior,
                 @Nullable final Schema schema, final long firstLineNumber)
    {
      this.lineList               = lineList;
      this.firstLineNumber        = firstLineNumber;
      this.duplicateValueBehavior = duplicateValueBehavior;
      this.trailingSpaceBehavior  = trailingSpaceBehavior;
      this.schema                 = schema;

      failureCause = null;
      isEOF =
           (firstLineNumber < 0) || ((lineList != null) && lineList.isEmpty());
    }



    /**
     * Creates a new instance of this record.
     *
     * @param failureCause  The Exception thrown when reading from the input.
     */
    private UnparsedLDIFRecord(@NotNull final Exception failureCause)
    {
      this.failureCause = failureCause;

      lineList               = null;
      firstLineNumber        = 0;
      duplicateValueBehavior = DuplicateValueBehavior.REJECT;
      trailingSpaceBehavior  = TrailingSpaceBehavior.REJECT;
      schema                 = null;
      isEOF                  = false;
    }



    /**
     * Return the lines that comprise the LDIF record.
     *
     * @return  The lines that comprise the LDIF record, or {@code null} if this
     *          is a failure record.
     */
    @Nullable()
    private ArrayList<StringBuilder> getLineList()
    {
      return lineList;
    }



    /**
     * Retrieves the behavior to exhibit when encountering duplicate attribute
     * values.
     *
     * @return  The behavior to exhibit when encountering duplicate attribute
     *          values.
     */
    @NotNull()
    private DuplicateValueBehavior getDuplicateValueBehavior()
    {
      return duplicateValueBehavior;
    }



    /**
     * Retrieves the behavior that should be exhibited when encountering
     * attribute values which are not base64-encoded but contain trailing
     * spaces.  The LDIF specification strongly recommends that any value which
     * legitimately contains trailing spaces be base64-encoded, but the LDAP SDK
     * LDIF parser may be configured to automatically strip these spaces, to
     * preserve them, or to reject any entry or change record containing them.
     *
     * @return  The behavior that should be exhibited when encountering
     *          attribute values which are not base64-encoded but contain
     *          trailing spaces.
     */
    @NotNull()
    private TrailingSpaceBehavior getTrailingSpaceBehavior()
    {
      return trailingSpaceBehavior;
    }



    /**
     * Retrieves the schema that should be used when parsing the record, if
     * applicable.
     *
     * @return  The schema that should be used when parsing the record, or
     *          {@code null} if none should be used.
     */
    @Nullable()
    private Schema getSchema()
    {
      return schema;
    }



    /**
     * Return the first line number of the LDIF record.
     *
     * @return  The first line number of the LDIF record.
     */
    private long getFirstLineNumber()
    {
      return firstLineNumber;
    }



    /**
     * Return {@code true} iff the end of the input was reached.
     *
     * @return  {@code true} iff the end of the input was reached.
     */
    private boolean isEOF()
    {
      return isEOF;
    }



    /**
     * Returns the reason that reading the record lines failed.  This normally
     * is only non-null if something bad happened to the input stream (like
     * a disk read error).
     *
     * @return  The reason that reading the record lines failed.
     */
    @Nullable()
    private Exception getFailureCause()
    {
      return failureCause;
    }
  }


  /**
   * When processing in asynchronous mode, this thread is responsible for
   * reading the raw unparsed records from the input and submitting them for
   * processing.
   */
  private final class LineReaderThread
       extends Thread
  {
    /**
     * Creates a new instance o fthis thread.
     */
    private LineReaderThread()
    {
      super("Asynchronous LDIF line reader");
      setDaemon(true);
    }



    /**
     * Reads raw, unparsed records from the input and submits them for
     * processing until the input is finished or closed.
     */
    @Override()
    public void run()
    {
      try
      {
        boolean stopProcessing = false;
        while (!stopProcessing)
        {
          UnparsedLDIFRecord unparsedRecord;
          try
          {
            unparsedRecord = readUnparsedRecord();
          }
          catch (final IOException e)
          {
            Debug.debugException(e);
            unparsedRecord = new UnparsedLDIFRecord(e);
            stopProcessing = true;
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            unparsedRecord = new UnparsedLDIFRecord(e);
          }

          try
          {
            asyncParser.submit(unparsedRecord);
          }
          catch (final InterruptedException e)
          {
            Debug.debugException(e);
            // If this thread is interrupted, then someone wants us to stop
            // processing, so that's what we'll do.
            Thread.currentThread().interrupt();
            stopProcessing = true;
          }

          if ((unparsedRecord == null) || unparsedRecord.isEOF())
          {
            stopProcessing = true;
          }
        }
      }
      finally
      {
        try
        {
          asyncParser.shutdown();
        }
        catch (final InterruptedException e)
        {
          Debug.debugException(e);
          Thread.currentThread().interrupt();
        }
        finally
        {
          asyncParsingComplete.set(true);
        }
      }
    }
  }



  /**
   * Used to parse Records asynchronously.
   */
  private final class RecordParser implements Processor<UnparsedLDIFRecord,
                                                        LDIFRecord>
  {
    /**
     * {@inheritDoc}
     */
    @Override()
    public LDIFRecord process(@NotNull final UnparsedLDIFRecord input)
           throws LDIFException
    {
      LDIFRecord record = decodeRecord(input, relativeBasePath, schema);

      if ((record instanceof Entry) && (entryTranslator != null))
      {
        record = entryTranslator.translate((Entry) record,
             input.getFirstLineNumber());

        if (record == null)
        {
          record = SKIP_ENTRY;
        }
      }
      if ((record instanceof LDIFChangeRecord) &&
          (changeRecordTranslator != null))
      {
        record = changeRecordTranslator.translate((LDIFChangeRecord) record,
             input.getFirstLineNumber());

        if (record == null)
        {
          record = SKIP_ENTRY;
        }
      }
      return record;
    }
  }
}
