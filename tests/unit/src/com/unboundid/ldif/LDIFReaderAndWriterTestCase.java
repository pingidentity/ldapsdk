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



import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.Base64;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.TestReader;



/**
 * This class provides a set of test cases for the LDIFReader and LDIFWriter
 * classes.
 */
public class LDIFReaderAndWriterTestCase
       extends LDIFTestCase
       implements LDIFReaderChangeRecordTranslator, LDIFReaderEntryTranslator,
                  LDIFWriterChangeRecordTranslator, LDIFWriterEntryTranslator
{
  /**
   * The end-of-line marker.
   */
  private static final String EOL = System.getProperty("line.separator");



  // Indicates whether the LDIF writer is configured to comment about
  // base64-encoded values.
  private boolean origCommentAboutBase64EncodedValues = false;

  // The schema to use, if available.
  private Schema schema = null;



  /**
   * Reads the schema from the Directory Server, if available.  Also, configures
   * the LDIF writer to include comments with the unencoded representation of
   * base64-encoded values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      schema = Schema.getDefaultStandardSchema();
    }
    else
    {
      LDAPConnection conn = getAdminConnection();
      schema =  conn.getSchema();
      conn.close();
    }

    origCommentAboutBase64EncodedValues =
         LDIFWriter.commentAboutBase64EncodedValues();
    LDIFWriter.setCommentAboutBase64EncodedValues(true);
    assertTrue(LDIFWriter.commentAboutBase64EncodedValues());
  }



  /**
   * Cleans up after testing is complete.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @AfterClass()
  public void cleanUp()
         throws Exception
  {
    LDIFWriter.setCommentAboutBase64EncodedValues(
         origCommentAboutBase64EncodedValues);
    assertEquals(LDIFWriter.commentAboutBase64EncodedValues(),
         origCommentAboutBase64EncodedValues);
  }



  /**
   * Tests the ability to read and write LDIF entries using files (including
   * String, File, and FileInputStream variants).
   *
   * @param  wrapColumn  The column at which long lines should be wrapped.
   * @param  numThreads  The number of threads to use when reading the LDIF.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testWrapColumnsAndThreads")
  public void testReadAndWriteEntries(int wrapColumn, int numThreads)
         throws Exception
  {
    File ldifFile = File.createTempFile("ldapsdk-test-", ".ldif");
    ldifFile.deleteOnExit();

    BufferedWriter bw = new BufferedWriter(new FileWriter(ldifFile));
    for (String line : getValidLDIFEntries())
    {
      bw.write(line);
      bw.newLine();
    }
    bw.close();

    // First, read and write using string paths.
    LDIFReader ldifReader;
    if (numThreads == 0)
    {
      ldifReader = new LDIFReader(ldifFile.getAbsolutePath());
    }
    else
    {
      ldifReader = new LDIFReader(ldifFile.getAbsolutePath(),
                                  numThreads);
    }

    File outputFile1 = File.createTempFile("ldapsdk-output-test-1-", ".ldif");
    outputFile1.deleteOnExit();
    LDIFWriter ldifWriter;
    if (numThreads == 0)
    {
      ldifWriter = new LDIFWriter(outputFile1.getAbsolutePath());
    }
    else
    {
      ldifWriter = new LDIFWriter(
           new FileOutputStream(outputFile1), numThreads);
    }
    ldifWriter.setWrapColumn(wrapColumn);
    assertEquals(ldifWriter.getWrapColumn(), wrapColumn);

    ldifWriter.writeVersionHeader();
    while (true)
    {
      Entry e = ldifReader.readEntry();
      if (e == null)
      {
        break;
      }

      ldifWriter.writeEntry(e);
    }

    ldifReader.close();
    ldifWriter.flush();
    ldifWriter.close();


    // Next, read and write using File arguments.
    if (numThreads == 0)
    {
      ldifReader = new LDIFReader(ldifFile);
    }
    else
    {
      ldifReader = new LDIFReader(ldifFile, numThreads);
    }

    File outputFile2 = File.createTempFile("ldapsdk-output-test-2-", ".ldif");
    outputFile2.deleteOnExit();
    ldifWriter = new LDIFWriter(outputFile2);
    ldifWriter.setWrapColumn(wrapColumn);
    assertEquals(ldifWriter.getWrapColumn(), wrapColumn);

    ldifWriter.writeVersionHeader();
    while (true)
    {
      Entry e = ldifReader.readEntry();
      if (e == null)
      {
        break;
      }

      ldifWriter.writeEntry(e);
    }

    ldifReader.close();
    ldifWriter.flush();
    ldifWriter.close();


    // Next, read and write using streams.
    if (numThreads == 0)
    {
      ldifReader = new LDIFReader(new FileInputStream(ldifFile));
    }
    else
    {
      ldifReader = new LDIFReader(new FileInputStream(ldifFile), numThreads);
    }

    File outputFile3 = File.createTempFile("ldapsdk-output-test-3-", ".ldif");
    outputFile3.deleteOnExit();
    ldifWriter = new LDIFWriter(new BufferedOutputStream(
         new FileOutputStream(outputFile3)));
    ldifWriter.setWrapColumn(wrapColumn);
    assertEquals(ldifWriter.getWrapColumn(), wrapColumn);

    ldifWriter.writeVersionHeader();
    while (true)
    {
      Entry e = ldifReader.readEntry();
      if (e == null)
      {
        break;
      }

      ldifWriter.writeEntry(e);
    }

    ldifReader.close();
    ldifWriter.flush();
    ldifWriter.close();


    // Next, read and write using buffered readers and writers.
    if (numThreads == 0)
    {
      ldifReader = new LDIFReader(
           new BufferedReader(new FileReader((ldifFile))));
    }
    else
    {
      ldifReader = new LDIFReader(
           new BufferedReader(new FileReader((ldifFile))),
           numThreads);
    }

    File outputFile4 = File.createTempFile("ldapsdk-output-test-4-", ".ldif");
    outputFile4.deleteOnExit();
    ldifWriter = new LDIFWriter(outputFile4);
    ldifWriter.setWrapColumn(wrapColumn);
    assertEquals(ldifWriter.getWrapColumn(), wrapColumn);

    ldifWriter.writeVersionHeader();
    while (true)
    {
      Entry e = ldifReader.readEntry();
      if (e == null)
      {
        break;
      }

      ldifWriter.writeEntry(e);
    }

    ldifReader.close();
    ldifWriter.flush();
    ldifWriter.close();


    // Make sure that we can read back the LDIF that we wrote, and write it out
    // again.
    ldifReader = new LDIFReader(outputFile1, numThreads);

    File outputFile5 = File.createTempFile("ldapsdk-output-test-5-", ".ldif");
    outputFile5.deleteOnExit();
    ldifWriter = new LDIFWriter(new FileOutputStream(outputFile5), numThreads);
    ldifWriter.setWrapColumn(wrapColumn);
    assertEquals(ldifWriter.getWrapColumn(), wrapColumn);

    ldifWriter.writeVersionHeader();

    List<Entry> entries = new ArrayList<Entry>();
    while (true)
    {
      Entry e = ldifReader.readEntry();
      if (e == null)
      {
        break;
      }
      entries.add(e);
    }
    // Test writing as a batch.
    ldifWriter.writeLDIFRecords(entries);

    ldifReader.close();
    ldifWriter.flush();
    ldifWriter.close();


    // Make sure that all of the LDIF files that we wrote are identical.
    byte[] output1MD5 = getMD5Digest(outputFile1);
    byte[] output2MD5 = getMD5Digest(outputFile2);
    byte[] output3MD5 = getMD5Digest(outputFile3);
    byte[] output4MD5 = getMD5Digest(outputFile5);
    assertTrue(Arrays.equals(output1MD5, output2MD5));
    assertTrue(Arrays.equals(output1MD5, output3MD5));
    assertTrue(Arrays.equals(output1MD5, output4MD5));


    // Read the entry one more time and write it out again, this time prefixing
    // each entry with a comment.
    ldifReader = new LDIFReader(ldifFile, numThreads);

    File outputFile6 = File.createTempFile("ldapsdk-output-test-5-", ".ldif");
    outputFile6.deleteOnExit();
    ldifWriter = new LDIFWriter(outputFile6);
    ldifWriter.setWrapColumn(wrapColumn);
    assertEquals(ldifWriter.getWrapColumn(), wrapColumn);

    ldifWriter.writeVersionHeader();

    int commentWrapColumn = wrapColumn;
    if (wrapColumn <= 0)
    {
      commentWrapColumn = 79;
    }
    char[] longWordHalf          = new char[commentWrapColumn / 2];
    char[] longWordEqualMinusTwo = new char[commentWrapColumn - 2];
    char[] longWordEqualMinusOne = new char[commentWrapColumn - 1];
    char[] longWordEqual         = new char[commentWrapColumn];
    char[] longWordEqualPlusOne  = new char[commentWrapColumn + 1];
    char[] longWordEqualPlusTwo  = new char[commentWrapColumn + 2];
    char[] longWordDouble        = new char[commentWrapColumn * 2];

    Arrays.fill(longWordHalf, 'a');
    Arrays.fill(longWordEqualMinusTwo, 'a');
    Arrays.fill(longWordEqualMinusOne, 'a');
    Arrays.fill(longWordEqual, 'a');
    Arrays.fill(longWordEqualPlusOne, 'a');
    Arrays.fill(longWordEqualPlusTwo, 'a');
    Arrays.fill(longWordDouble, 'a');

    String comment = "This is a comment that will be written before every " +
                     "entry.  Hopefully it's long enough that in most cases " +
                     "it will be necessary to wrap it when wrapping is " +
                     "enabled.  Here are a series of some long 'words' that " +
                     "will should cause problems wrapping on the desired " +
                     "boundary:  " + new String(longWordHalf) + ", " +
                     new String(longWordEqualMinusTwo) + ", " +
                     new String(longWordEqualMinusOne) + ", " +
                     new String(longWordEqual) + ", " +
                     new String(longWordEqualPlusOne) + ", " +
                     new String(longWordEqualPlusTwo) + ", " +
                     new String(longWordDouble) + ".";

    boolean lastWasLong = false;
    while (true)
    {
      Entry e = ldifReader.readEntry();
      if (e == null)
      {
        break;
      }

      if (lastWasLong)
      {
        ldifWriter.writeEntry(e, "a");
        lastWasLong = false;
      }
      else
      {
        ldifWriter.writeEntry(e, comment);
        lastWasLong = true;
      }
    }

    ldifReader.close();
    ldifWriter.flush();
    ldifWriter.close();


    // Make sure that we can read back the LDIF file with comments.  We don't
    // need to write it out anywhere.
    ldifReader = new LDIFReader(ldifFile, numThreads);
    while (true)
    {
      Entry e = ldifReader.readEntry();
      if (e == null)
      {
        // Make sure that multiple reads at the end of the file will still be
        // null.
        assertNull(ldifReader.readEntry());
        break;
      }
    }
    ldifReader.close();
  }



  /**
   * Tests the ability to read and write LDIF entries using files (including
   * String, File, and FileInputStream variants).
   *
   * @param  wrapColumn  The column at which long lines should be wrapped.
   * @param  numThreads  The number of threads to use when reading the LDIF.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @SuppressWarnings("deprecation")
  @Test(dataProvider = "testWrapColumnsAndThreads")
  public void testReadAndWriteEntriesWithSchema(int wrapColumn, int numThreads)
         throws Exception
  {
    File ldifFile = File.createTempFile("ldapsdk-test-", ".ldif");
    ldifFile.deleteOnExit();

    BufferedWriter bw = new BufferedWriter(new FileWriter(ldifFile));
    for (String line : getValidLDIFEntries())
    {
      bw.write(line);
      bw.newLine();
    }
    bw.close();

    // First, read and write using string paths.
    LDIFReader ldifReader;
    if (numThreads == 0)
    {
      ldifReader = new LDIFReader(ldifFile.getAbsolutePath());
    }
    else
    {
      ldifReader = new LDIFReader(ldifFile.getAbsolutePath(),
                                  numThreads);
    }

    assertNull(ldifReader.getSchema());
    ldifReader.setSchema(schema);
    assertEquals(ldifReader.getSchema(), schema);

    assertTrue(ldifReader.ignoreDuplicateValues());
    ldifReader.setIgnoreDuplicateValues(false);
    assertFalse(ldifReader.ignoreDuplicateValues());

    File outputFile1 = File.createTempFile("ldapsdk-output-test-1-", ".ldif");
    outputFile1.deleteOnExit();
    LDIFWriter ldifWriter;
    if (numThreads == 0)
    {
      ldifWriter = new LDIFWriter(outputFile1.getAbsolutePath());
    }
    else
    {
      ldifWriter = new LDIFWriter(
           new FileOutputStream(outputFile1), numThreads);
    }
    ldifWriter.setWrapColumn(wrapColumn);
    assertEquals(ldifWriter.getWrapColumn(), wrapColumn);

    ldifWriter.writeVersionHeader();
    while (true)
    {
      Entry e = ldifReader.readEntry();
      if (e == null)
      {
        break;
      }

      ldifWriter.writeEntry(e);
    }

    ldifReader.close();
    ldifWriter.flush();
    ldifWriter.close();


    // Next, read and write using File arguments.
    if (numThreads == 0)
    {
      ldifReader = new LDIFReader(ldifFile);
    }
    else
    {
      ldifReader = new LDIFReader(ldifFile, numThreads);
    }

    assertNull(ldifReader.getSchema());
    ldifReader.setSchema(schema);
    assertEquals(ldifReader.getSchema(), schema);

    assertTrue(ldifReader.ignoreDuplicateValues());
    ldifReader.setIgnoreDuplicateValues(false);
    assertFalse(ldifReader.ignoreDuplicateValues());

    File outputFile2 = File.createTempFile("ldapsdk-output-test-2-", ".ldif");
    outputFile2.deleteOnExit();
    ldifWriter = new LDIFWriter(outputFile2);
    ldifWriter.setWrapColumn(wrapColumn);
    assertEquals(ldifWriter.getWrapColumn(), wrapColumn);

    ldifWriter.writeVersionHeader();
    while (true)
    {
      Entry e = ldifReader.readEntry();
      if (e == null)
      {
        break;
      }

      ldifWriter.writeEntry(e);
    }

    ldifReader.close();
    ldifWriter.flush();
    ldifWriter.close();


    // Next, read and write using streams.
    if (numThreads == 0)
    {
      ldifReader = new LDIFReader(new FileInputStream(ldifFile));
    }
    else
    {
      ldifReader = new LDIFReader(new FileInputStream(ldifFile), numThreads);
    }

    assertNull(ldifReader.getSchema());
    ldifReader.setSchema(schema);
    assertEquals(ldifReader.getSchema(), schema);

    assertTrue(ldifReader.ignoreDuplicateValues());
    ldifReader.setIgnoreDuplicateValues(false);
    assertFalse(ldifReader.ignoreDuplicateValues());

    File outputFile3 = File.createTempFile("ldapsdk-output-test-3-", ".ldif");
    outputFile3.deleteOnExit();
    ldifWriter = new LDIFWriter(new BufferedOutputStream(
         new FileOutputStream(outputFile3)));
    ldifWriter.setWrapColumn(wrapColumn);
    assertEquals(ldifWriter.getWrapColumn(), wrapColumn);

    ldifWriter.writeVersionHeader();
    while (true)
    {
      Entry e = ldifReader.readEntry();
      if (e == null)
      {
        break;
      }

      ldifWriter.writeEntry(e);
    }

    ldifReader.close();
    ldifWriter.flush();
    ldifWriter.close();


    // Next, read and write using buffered readers and writers.
    if (numThreads == 0)
    {
      ldifReader = new LDIFReader(
           new BufferedReader(new FileReader((ldifFile))));
    }
    else
    {
      ldifReader = new LDIFReader(
           new BufferedReader(new FileReader((ldifFile))),
           numThreads);
    }

    assertNull(ldifReader.getSchema());
    ldifReader.setSchema(schema);
    assertEquals(ldifReader.getSchema(), schema);

    assertTrue(ldifReader.ignoreDuplicateValues());
    ldifReader.setIgnoreDuplicateValues(false);
    assertFalse(ldifReader.ignoreDuplicateValues());

    File outputFile4 = File.createTempFile("ldapsdk-output-test-4-", ".ldif");
    outputFile4.deleteOnExit();
    ldifWriter = new LDIFWriter(outputFile4);
    ldifWriter.setWrapColumn(wrapColumn);
    assertEquals(ldifWriter.getWrapColumn(), wrapColumn);

    ldifWriter.writeVersionHeader();
    while (true)
    {
      Entry e = ldifReader.readEntry();
      if (e == null)
      {
        break;
      }

      ldifWriter.writeEntry(e);
    }

    ldifReader.close();
    ldifWriter.flush();
    ldifWriter.close();


    // Make sure that we can read back the LDIF that we wrote, and write it out
    // again.
    ldifReader = new LDIFReader(outputFile1, numThreads);

    assertNull(ldifReader.getSchema());
    ldifReader.setSchema(schema);
    assertEquals(ldifReader.getSchema(), schema);

    assertTrue(ldifReader.ignoreDuplicateValues());
    ldifReader.setIgnoreDuplicateValues(false);
    assertFalse(ldifReader.ignoreDuplicateValues());

    File outputFile5 = File.createTempFile("ldapsdk-output-test-5-", ".ldif");
    outputFile5.deleteOnExit();
    ldifWriter = new LDIFWriter(new FileOutputStream(outputFile5), numThreads);
    ldifWriter.setWrapColumn(wrapColumn);
    assertEquals(ldifWriter.getWrapColumn(), wrapColumn);

    ldifWriter.writeVersionHeader();

    List<Entry> entries = new ArrayList<Entry>();
    while (true)
    {
      Entry e = ldifReader.readEntry();
      if (e == null)
      {
        break;
      }
      entries.add(e);
    }
    // Test writing as a batch.
    ldifWriter.writeLDIFRecords(entries);

    ldifReader.close();
    ldifWriter.flush();
    ldifWriter.close();


    // Make sure that all of the LDIF files that we wrote are identical.
    byte[] output1MD5 = getMD5Digest(outputFile1);
    byte[] output2MD5 = getMD5Digest(outputFile2);
    byte[] output3MD5 = getMD5Digest(outputFile3);
    byte[] output4MD5 = getMD5Digest(outputFile5);
    assertTrue(Arrays.equals(output1MD5, output2MD5));
    assertTrue(Arrays.equals(output1MD5, output3MD5));
    assertTrue(Arrays.equals(output1MD5, output4MD5));


    // Read the entry one more time and write it out again, this time prefixing
    // each entry with a comment.
    ldifReader = new LDIFReader(ldifFile, numThreads);

    assertNull(ldifReader.getSchema());
    ldifReader.setSchema(schema);
    assertEquals(ldifReader.getSchema(), schema);

    assertTrue(ldifReader.ignoreDuplicateValues());
    ldifReader.setIgnoreDuplicateValues(false);
    assertFalse(ldifReader.ignoreDuplicateValues());

    File outputFile6 = File.createTempFile("ldapsdk-output-test-5-", ".ldif");
    outputFile6.deleteOnExit();
    ldifWriter = new LDIFWriter(outputFile6);
    ldifWriter.setWrapColumn(wrapColumn);
    assertEquals(ldifWriter.getWrapColumn(), wrapColumn);

    ldifWriter.writeVersionHeader();

    int commentWrapColumn = wrapColumn;
    if (wrapColumn <= 0)
    {
      commentWrapColumn = 79;
    }
    char[] longWordHalf          = new char[commentWrapColumn / 2];
    char[] longWordEqualMinusTwo = new char[commentWrapColumn - 2];
    char[] longWordEqualMinusOne = new char[commentWrapColumn - 1];
    char[] longWordEqual         = new char[commentWrapColumn];
    char[] longWordEqualPlusOne  = new char[commentWrapColumn + 1];
    char[] longWordEqualPlusTwo  = new char[commentWrapColumn + 2];
    char[] longWordDouble        = new char[commentWrapColumn * 2];

    Arrays.fill(longWordHalf, 'a');
    Arrays.fill(longWordEqualMinusTwo, 'a');
    Arrays.fill(longWordEqualMinusOne, 'a');
    Arrays.fill(longWordEqual, 'a');
    Arrays.fill(longWordEqualPlusOne, 'a');
    Arrays.fill(longWordEqualPlusTwo, 'a');
    Arrays.fill(longWordDouble, 'a');

    String comment = "This is a comment that will be written before every " +
                     "entry.  Hopefully it's long enough that in most cases " +
                     "it will be necessary to wrap it when wrapping is " +
                     "enabled.  Here are a series of some long 'words' that " +
                     "will should cause problems wrapping on the desired " +
                     "boundary:  " + new String(longWordHalf) + ", " +
                     new String(longWordEqualMinusTwo) + ", " +
                     new String(longWordEqualMinusOne) + ", " +
                     new String(longWordEqual) + ", " +
                     new String(longWordEqualPlusOne) + ", " +
                     new String(longWordEqualPlusTwo) + ", " +
                     new String(longWordDouble) + ".";

    boolean lastWasLong = false;
    while (true)
    {
      Entry e = ldifReader.readEntry();
      if (e == null)
      {
        break;
      }

      if (lastWasLong)
      {
        ldifWriter.writeEntry(e, "a");
        lastWasLong = false;
      }
      else
      {
        ldifWriter.writeEntry(e, comment);
        lastWasLong = true;
      }
    }

    ldifReader.close();
    ldifWriter.flush();
    ldifWriter.close();


    // Make sure that we can read back the LDIF file with comments.  We don't
    // need to write it out anywhere.
    ldifReader = new LDIFReader(ldifFile, numThreads);

    assertNull(ldifReader.getSchema());
    ldifReader.setSchema(schema);
    assertEquals(ldifReader.getSchema(), schema);

    assertTrue(ldifReader.ignoreDuplicateValues());
    ldifReader.setIgnoreDuplicateValues(false);
    assertFalse(ldifReader.ignoreDuplicateValues());

    while (true)
    {
      Entry e = ldifReader.readEntry();
      if (e == null)
      {
        // Make sure that multiple reads at the end of the file will still be
        // null.
        assertNull(ldifReader.readEntry());
        break;
      }
    }
    ldifReader.close();
  }



  /**
   * Tests the ability to read and write LDIF change records.
   *
   * @param  wrapColumn  The column at which long lines should be wrapped.
   * @param  numThreads  The number of threads to use when reading the LDIF.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testWrapColumnsAndThreads")
  public void testReadAndWriteChangeRecords(int wrapColumn, int numThreads)
         throws Exception
  {
    File ldifFile = File.createTempFile("ldapsdk-test-", ".ldif");
    ldifFile.deleteOnExit();

    BufferedWriter bw = new BufferedWriter(new FileWriter(ldifFile));
    for (String line : getLDIFChangeRecords())
    {
      bw.write(line);
      bw.newLine();
    }
    bw.close();


    // First, read and write using string paths.
    LDIFReader ldifReader = new LDIFReader(ldifFile.getAbsolutePath(),
                                           numThreads);

    File outputFile1 = File.createTempFile("ldapsdk-output-test-1-", ".ldif");
    outputFile1.deleteOnExit();
    LDIFWriter ldifWriter = new LDIFWriter(outputFile1.getAbsolutePath());
    ldifWriter.setWrapColumn(wrapColumn);
    assertEquals(ldifWriter.getWrapColumn(), wrapColumn);

    ldifWriter.writeVersionHeader();
    while (true)
    {
      LDIFChangeRecord changeRecord = ldifReader.readChangeRecord();
      if (changeRecord == null)
      {
        break;
      }

      ldifWriter.writeChangeRecord(changeRecord);
    }

    ldifReader.close();
    ldifWriter.flush();
    ldifWriter.close();


    // Next, read and write using File arguments.
    ldifReader = new LDIFReader(ldifFile, numThreads);

    File outputFile2 = File.createTempFile("ldapsdk-output-test-2-", ".ldif");
    outputFile2.deleteOnExit();
    ldifWriter = new LDIFWriter(outputFile2);
    ldifWriter.setWrapColumn(wrapColumn);
    assertEquals(ldifWriter.getWrapColumn(), wrapColumn);

    ldifWriter.writeVersionHeader();
    while (true)
    {
      LDIFChangeRecord changeRecord = ldifReader.readChangeRecord();
      if (changeRecord == null)
      {
        break;
      }

      ldifWriter.writeChangeRecord(changeRecord);
    }

    ldifReader.close();
    ldifWriter.flush();
    ldifWriter.close();


    // Finally, read and write using streams.
    ldifReader = new LDIFReader(new FileInputStream(ldifFile), numThreads);

    File outputFile3 = File.createTempFile("ldapsdk-output-test-3-", ".ldif");
    outputFile3.deleteOnExit();
    ldifWriter = new LDIFWriter(new FileOutputStream(outputFile3));
    ldifWriter.setWrapColumn(wrapColumn);
    assertEquals(ldifWriter.getWrapColumn(), wrapColumn);

    ldifWriter.writeVersionHeader();
    while (true)
    {
      LDIFChangeRecord changeRecord = ldifReader.readChangeRecord();
      if (changeRecord == null)
      {
        break;
      }

      ldifWriter.writeChangeRecord(changeRecord);
    }

    ldifReader.close();
    ldifWriter.flush();
    ldifWriter.close();


    // Make sure that we can read back the LDIF that we wrote, and write it out
    // again.
    ldifReader = new LDIFReader(outputFile1, numThreads);

    File outputFile4 = File.createTempFile("ldapsdk-output-test-4-", ".ldif");
    outputFile4.deleteOnExit();
    ldifWriter = new LDIFWriter(outputFile4);
    ldifWriter.setWrapColumn(wrapColumn);
    assertEquals(ldifWriter.getWrapColumn(), wrapColumn);

    ldifWriter.writeVersionHeader();
    while (true)
    {
      LDIFChangeRecord changeRecord = ldifReader.readChangeRecord();
      if (changeRecord == null)
      {
        break;
      }

      ldifWriter.writeChangeRecord(changeRecord);
    }

    ldifReader.close();
    ldifWriter.flush();
    ldifWriter.close();


    // Make sure that all of the LDIF files that we wrote are identical.
    byte[] output1MD5 = getMD5Digest(outputFile1);
    byte[] output2MD5 = getMD5Digest(outputFile2);
    byte[] output3MD5 = getMD5Digest(outputFile3);
    byte[] output4MD5 = getMD5Digest(outputFile4);
    assertTrue(Arrays.equals(output1MD5, output2MD5));
    assertTrue(Arrays.equals(output1MD5, output3MD5));
    assertTrue(Arrays.equals(output1MD5, output4MD5));


    // Read the entry one more time and write it out again, this time prefixing
    // each entry with a comment.
    ldifReader = new LDIFReader(ldifFile, numThreads);

    File outputFile5 = File.createTempFile("ldapsdk-output-test-5-", ".ldif");
    outputFile5.deleteOnExit();
    ldifWriter = new LDIFWriter(outputFile5);
    ldifWriter.setWrapColumn(wrapColumn);
    assertEquals(ldifWriter.getWrapColumn(), wrapColumn);

    ldifWriter.writeVersionHeader();

    int commentWrapColumn = wrapColumn;
    if (wrapColumn <= 0)
    {
      commentWrapColumn = 79;
    }
    char[] longWordHalf          = new char[commentWrapColumn / 2];
    char[] longWordEqualMinusTwo = new char[commentWrapColumn - 2];
    char[] longWordEqualMinusOne = new char[commentWrapColumn - 1];
    char[] longWordEqual         = new char[commentWrapColumn];
    char[] longWordEqualPlusOne  = new char[commentWrapColumn + 1];
    char[] longWordEqualPlusTwo  = new char[commentWrapColumn + 2];
    char[] longWordDouble        = new char[commentWrapColumn * 2];

    Arrays.fill(longWordHalf, 'a');
    Arrays.fill(longWordEqualMinusTwo, 'a');
    Arrays.fill(longWordEqualMinusOne, 'a');
    Arrays.fill(longWordEqual, 'a');
    Arrays.fill(longWordEqualPlusOne, 'a');
    Arrays.fill(longWordEqualPlusTwo, 'a');
    Arrays.fill(longWordDouble, 'a');

    String comment = "This is a comment that will be written before every " +
                     "entry.  Hopefully it's long enough that in most cases " +
                     "it will be necessary to wrap it when wrapping is " +
                     "enabled.  Here are a series of some long 'words' that " +
                     "will should cause problems wrapping on the desired " +
                     "boundary:  " + new String(longWordHalf) + ", " +
                     new String(longWordEqualMinusTwo) + ", " +
                     new String(longWordEqualMinusOne) + ", " +
                     new String(longWordEqual) + ", " +
                     new String(longWordEqualPlusOne) + ", " +
                     new String(longWordEqualPlusTwo) + ", " +
                     new String(longWordDouble) + ".";

    boolean lastWasLong = false;
    while (true)
    {
      LDIFChangeRecord changeRecord = ldifReader.readChangeRecord();
      if (changeRecord == null)
      {
        break;
      }

      if (lastWasLong)
      {
        ldifWriter.writeChangeRecord(changeRecord, "a");
        lastWasLong = false;
      }
      else
      {
        ldifWriter.writeChangeRecord(changeRecord, comment);
        lastWasLong = true;
      }
    }

    ldifReader.close();
    ldifWriter.flush();
    ldifWriter.close();


    // Make sure that we can read back the LDIF file with comments.  We don't
    // need to write it out anywhere.
    ldifReader = new LDIFReader(ldifFile, numThreads);
    while (true)
    {
      LDIFChangeRecord changeRecord = ldifReader.readChangeRecord();
      if (changeRecord == null)
      {
        // Make sure that multiple reads at the end of the file will still be
        // null.
        assertNull(ldifReader.readChangeRecord());
        break;
      }
    }
    ldifReader.close();
  }



  /**
   * Tests the ability to read and write LDIF records using files (including
   * String, File, and FileInputStream variants).
   *
   * @param  wrapColumn  The column at which long lines should be wrapped.
   * @param  numThreads  The number of threads to use when reading the LDIF.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testWrapColumnsAndThreads")
  public void testReadAndWriteEntriesAsRecords(int wrapColumn, int numThreads)
         throws Exception
  {
    File ldifFile = File.createTempFile("ldapsdk-test-", ".ldif");
    ldifFile.deleteOnExit();

    BufferedWriter bw = new BufferedWriter(new FileWriter(ldifFile));
    for (String line : getValidLDIFEntries())
    {
      bw.write(line);
      bw.newLine();
    }
    bw.close();


    // First, read and write using string paths.
    LDIFReader ldifReader = new LDIFReader(ldifFile.getAbsolutePath(),
                                           numThreads);

    File outputFile1 = File.createTempFile("ldapsdk-output-test-1-", ".ldif");
    outputFile1.deleteOnExit();
    LDIFWriter ldifWriter = new LDIFWriter(outputFile1.getAbsolutePath());
    ldifWriter.setWrapColumn(wrapColumn);
    assertEquals(ldifWriter.getWrapColumn(), wrapColumn);

    ldifWriter.writeVersionHeader();
    while (true)
    {
      LDIFRecord r = ldifReader.readLDIFRecord();
      if (r == null)
      {
        break;
      }

      assertTrue(r instanceof Entry);
      ldifWriter.writeLDIFRecord(r);
    }

    ldifReader.close();
    ldifWriter.flush();
    ldifWriter.close();


    // Next, read and write using File arguments.
    ldifReader = new LDIFReader(ldifFile, numThreads);

    File outputFile2 = File.createTempFile("ldapsdk-output-test-2-", ".ldif");
    outputFile2.deleteOnExit();
    ldifWriter = new LDIFWriter(outputFile2);
    ldifWriter.setWrapColumn(wrapColumn);
    assertEquals(ldifWriter.getWrapColumn(), wrapColumn);

    ldifWriter.writeVersionHeader();
    while (true)
    {
      LDIFRecord r = ldifReader.readLDIFRecord();
      if (r == null)
      {
        break;
      }

      assertTrue(r instanceof Entry);
      ldifWriter.writeLDIFRecord(r);
    }

    ldifReader.close();
    ldifWriter.flush();
    ldifWriter.close();


    // Finally, read and write using streams.
    ldifReader = new LDIFReader(new FileInputStream(ldifFile), numThreads);

    File outputFile3 = File.createTempFile("ldapsdk-output-test-3-", ".ldif");
    outputFile3.deleteOnExit();
    ldifWriter = new LDIFWriter(new FileOutputStream(outputFile3));
    ldifWriter.setWrapColumn(wrapColumn);
    assertEquals(ldifWriter.getWrapColumn(), wrapColumn);

    ldifWriter.writeVersionHeader();
    while (true)
    {
      LDIFRecord r = ldifReader.readLDIFRecord();
      if (r == null)
      {
        break;
      }

      assertTrue(r instanceof Entry);
      ldifWriter.writeLDIFRecord(r);
    }

    ldifReader.close();
    ldifWriter.flush();
    ldifWriter.close();


    // Make sure that we can read back the LDIF that we wrote, and write it out
    // again.
    ldifReader = new LDIFReader(outputFile1, numThreads);

    File outputFile4 = File.createTempFile("ldapsdk-output-test-4-", ".ldif");
    outputFile4.deleteOnExit();
    ldifWriter = new LDIFWriter(outputFile4);
    ldifWriter.setWrapColumn(wrapColumn);
    assertEquals(ldifWriter.getWrapColumn(), wrapColumn);

    ldifWriter.writeVersionHeader();
    while (true)
    {
      LDIFRecord r = ldifReader.readLDIFRecord();
      if (r == null)
      {
        break;
      }

      assertTrue(r instanceof Entry);
      ldifWriter.writeLDIFRecord(r);
    }

    ldifReader.close();
    ldifWriter.flush();
    ldifWriter.close();


    // Make sure that all of the LDIF files that we wrote are identical.
    byte[] output1MD5 = getMD5Digest(outputFile1);
    byte[] output2MD5 = getMD5Digest(outputFile2);
    byte[] output3MD5 = getMD5Digest(outputFile3);
    byte[] output4MD5 = getMD5Digest(outputFile4);
    if (!Arrays.equals(output1MD5, output2MD5))
    {
      System.err.println(outputFile1 +  "and " + outputFile2 + " differ");
      Thread.sleep(10 * 60 * 1000);
    }
    assertTrue(Arrays.equals(output1MD5, output2MD5));
    assertTrue(Arrays.equals(output1MD5, output3MD5));
    assertTrue(Arrays.equals(output1MD5, output4MD5));


    // Read the entry one more time and write it out again, this time prefixing
    // each entry with a comment.
    ldifReader = new LDIFReader(ldifFile, numThreads);

    File outputFile5 = File.createTempFile("ldapsdk-output-test-5-", ".ldif");
    outputFile5.deleteOnExit();
    ldifWriter = new LDIFWriter(outputFile5);
    ldifWriter.setWrapColumn(wrapColumn);
    assertEquals(ldifWriter.getWrapColumn(), wrapColumn);

    ldifWriter.writeVersionHeader();

    int commentWrapColumn = wrapColumn;
    if (wrapColumn <= 0)
    {
      commentWrapColumn = 79;
    }
    char[] longWordHalf          = new char[commentWrapColumn / 2];
    char[] longWordEqualMinusTwo = new char[commentWrapColumn - 2];
    char[] longWordEqualMinusOne = new char[commentWrapColumn - 1];
    char[] longWordEqual         = new char[commentWrapColumn];
    char[] longWordEqualPlusOne  = new char[commentWrapColumn + 1];
    char[] longWordEqualPlusTwo  = new char[commentWrapColumn + 2];
    char[] longWordDouble        = new char[commentWrapColumn * 2];

    Arrays.fill(longWordHalf, 'a');
    Arrays.fill(longWordEqualMinusTwo, 'a');
    Arrays.fill(longWordEqualMinusOne, 'a');
    Arrays.fill(longWordEqual, 'a');
    Arrays.fill(longWordEqualPlusOne, 'a');
    Arrays.fill(longWordEqualPlusTwo, 'a');
    Arrays.fill(longWordDouble, 'a');

    String comment = "This is a comment that will be written before every " +
                     "entry.  Hopefully it's long enough that in most cases " +
                     "it will be necessary to wrap it when wrapping is " +
                     "enabled.  Here are a series of some long 'words' that " +
                     "will should cause problems wrapping on the desired " +
                     "boundary:  " + new String(longWordHalf) + ", " +
                     new String(longWordEqualMinusTwo) + ", " +
                     new String(longWordEqualMinusOne) + ", " +
                     new String(longWordEqual) + ", " +
                     new String(longWordEqualPlusOne) + ", " +
                     new String(longWordEqualPlusTwo) + ", " +
                     new String(longWordDouble) + ".";

    boolean lastWasLong = false;
    while (true)
    {
      LDIFRecord r = ldifReader.readLDIFRecord();
      if (r == null)
      {
        break;
      }

      assertTrue(r instanceof Entry);

      if (lastWasLong)
      {
        ldifWriter.writeLDIFRecord(r, "a");
        lastWasLong = false;
      }
      else
      {
        ldifWriter.writeLDIFRecord(r, comment);
        lastWasLong = true;
      }
    }

    ldifReader.close();
    ldifWriter.flush();
    ldifWriter.close();


    // Make sure that we can read back the LDIF file with comments.  We don't
    // need to write it out anywhere.
    ldifReader = new LDIFReader(ldifFile, numThreads);
    while (true)
    {
      LDIFRecord r = ldifReader.readLDIFRecord();
      if (r == null)
      {
        // Make sure that multiple reads at the end of the file will still be
        // null.
        assertNull(ldifReader.readLDIFRecord());
        break;
      }

      assertTrue(r instanceof Entry);
    }
    ldifReader.close();
  }



  /**
   * Tests the ability to read and write LDIF change records as LDIF records.
   *
   * @param  wrapColumn  The column at which long lines should be wrapped.
   * @param  numThreads  The number of threads to use when reading the LDIF.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testWrapColumnsAndThreads")
  public void testReadAndWriteChangeRecordsAsRecords(int wrapColumn,
                                                     int numThreads)
         throws Exception
  {
    File ldifFile = File.createTempFile("ldapsdk-test-", ".ldif");
    ldifFile.deleteOnExit();

    BufferedWriter bw = new BufferedWriter(new FileWriter(ldifFile));
    for (String line : getLDIFChangeRecords())
    {
      bw.write(line);
      bw.newLine();
    }
    bw.close();


    // First, read and write using string paths.
    LDIFReader ldifReader = new LDIFReader(ldifFile.getAbsolutePath(),
                                           numThreads);

    File outputFile1 = File.createTempFile("ldapsdk-output-test-1-", ".ldif");
    outputFile1.deleteOnExit();
    LDIFWriter ldifWriter = new LDIFWriter(outputFile1.getAbsolutePath());
    ldifWriter.setWrapColumn(wrapColumn);
    assertEquals(ldifWriter.getWrapColumn(), wrapColumn);

    ldifWriter.writeVersionHeader();
    while (true)
    {
      LDIFRecord record = ldifReader.readLDIFRecord();
      if (record == null)
      {
        break;
      }

      assertTrue(record instanceof LDIFChangeRecord);
      ldifWriter.writeLDIFRecord(record);
    }

    ldifReader.close();
    ldifWriter.flush();
    ldifWriter.close();


    // Next, read and write using File arguments.
    ldifReader = new LDIFReader(ldifFile, numThreads);

    File outputFile2 = File.createTempFile("ldapsdk-output-test-2-", ".ldif");
    outputFile2.deleteOnExit();
    ldifWriter = new LDIFWriter(outputFile2);
    ldifWriter.setWrapColumn(wrapColumn);
    assertEquals(ldifWriter.getWrapColumn(), wrapColumn);

    ldifWriter.writeVersionHeader();
    while (true)
    {
      LDIFRecord record = ldifReader.readLDIFRecord();
      if (record == null)
      {
        break;
      }

      assertTrue(record instanceof LDIFChangeRecord);
      ldifWriter.writeLDIFRecord(record);
    }

    ldifReader.close();
    ldifWriter.flush();
    ldifWriter.close();


    // Finally, read and write using streams.
    ldifReader = new LDIFReader(new FileInputStream(ldifFile), numThreads);

    File outputFile3 = File.createTempFile("ldapsdk-output-test-3-", ".ldif");
    outputFile3.deleteOnExit();
    ldifWriter = new LDIFWriter(new FileOutputStream(outputFile3));
    ldifWriter.setWrapColumn(wrapColumn);
    assertEquals(ldifWriter.getWrapColumn(), wrapColumn);

    ldifWriter.writeVersionHeader();
    while (true)
    {
      LDIFRecord record = ldifReader.readLDIFRecord();
      if (record == null)
      {
        break;
      }

      assertTrue(record instanceof LDIFChangeRecord);
      ldifWriter.writeLDIFRecord(record);
    }

    ldifReader.close();
    ldifWriter.flush();
    ldifWriter.close();


    // Make sure that we can read back the LDIF that we wrote, and write it out
    // again.
    ldifReader = new LDIFReader(outputFile1, numThreads);

    File outputFile4 = File.createTempFile("ldapsdk-output-test-4-", ".ldif");
    outputFile4.deleteOnExit();
    ldifWriter = new LDIFWriter(outputFile4);
    ldifWriter.setWrapColumn(wrapColumn);
    assertEquals(ldifWriter.getWrapColumn(), wrapColumn);

    ldifWriter.writeVersionHeader();
    while (true)
    {
      LDIFRecord record = ldifReader.readLDIFRecord();
      if (record == null)
      {
        break;
      }

      assertTrue(record instanceof LDIFChangeRecord);
      ldifWriter.writeLDIFRecord(record);
    }

    ldifReader.close();
    ldifWriter.flush();
    ldifWriter.close();


    // Make sure that all of the LDIF files that we wrote are identical.
    byte[] output1MD5 = getMD5Digest(outputFile1);
    byte[] output2MD5 = getMD5Digest(outputFile2);
    byte[] output3MD5 = getMD5Digest(outputFile3);
    byte[] output4MD5 = getMD5Digest(outputFile4);
    assertTrue(Arrays.equals(output1MD5, output2MD5));
    assertTrue(Arrays.equals(output1MD5, output3MD5));
    assertTrue(Arrays.equals(output1MD5, output4MD5));


    // Read the entry one more time and write it out again, this time prefixing
    // each entry with a comment.
    ldifReader = new LDIFReader(ldifFile, numThreads);

    File outputFile5 = File.createTempFile("ldapsdk-output-test-5-", ".ldif");
    outputFile5.deleteOnExit();
    ldifWriter = new LDIFWriter(outputFile5);
    ldifWriter.setWrapColumn(wrapColumn);
    assertEquals(ldifWriter.getWrapColumn(), wrapColumn);

    ldifWriter.writeVersionHeader();

    int commentWrapColumn = wrapColumn;
    if (wrapColumn <= 0)
    {
      commentWrapColumn = 79;
    }
    char[] longWordHalf          = new char[commentWrapColumn / 2];
    char[] longWordEqualMinusTwo = new char[commentWrapColumn - 2];
    char[] longWordEqualMinusOne = new char[commentWrapColumn - 1];
    char[] longWordEqual         = new char[commentWrapColumn];
    char[] longWordEqualPlusOne  = new char[commentWrapColumn + 1];
    char[] longWordEqualPlusTwo  = new char[commentWrapColumn + 2];
    char[] longWordDouble        = new char[commentWrapColumn * 2];

    Arrays.fill(longWordHalf, 'a');
    Arrays.fill(longWordEqualMinusTwo, 'a');
    Arrays.fill(longWordEqualMinusOne, 'a');
    Arrays.fill(longWordEqual, 'a');
    Arrays.fill(longWordEqualPlusOne, 'a');
    Arrays.fill(longWordEqualPlusTwo, 'a');
    Arrays.fill(longWordDouble, 'a');

    String comment = "This is a comment that will be written before every " +
                     "entry.  Hopefully it's long enough that in most cases " +
                     "it will be necessary to wrap it when wrapping is " +
                     "enabled.  Here are a series of some long 'words' that " +
                     "will should cause problems wrapping on the desired " +
                     "boundary:  " + new String(longWordHalf) + ", " +
                     new String(longWordEqualMinusTwo) + ", " +
                     new String(longWordEqualMinusOne) + ", " +
                     new String(longWordEqual) + ", " +
                     new String(longWordEqualPlusOne) + ", " +
                     new String(longWordEqualPlusTwo) + ", " +
                     new String(longWordDouble) + ".";

    boolean lastWasLong = false;
    while (true)
    {
      LDIFRecord record = ldifReader.readLDIFRecord();
      if (record == null)
      {
        break;
      }

      assertTrue(record instanceof LDIFChangeRecord);
      if (lastWasLong)
      {
        ldifWriter.writeLDIFRecord(record, "a");
        lastWasLong = false;
      }
      else
      {
        ldifWriter.writeLDIFRecord(record, comment);
        lastWasLong = true;
      }
    }

    ldifReader.close();
    ldifWriter.flush();
    ldifWriter.close();


    // Make sure that we can read back the LDIF file with comments.  We don't
    // need to write it out anywhere.
    ldifReader = new LDIFReader(ldifFile, numThreads);
    while (true)
    {
      LDIFRecord record = ldifReader.readLDIFRecord();
      if (record == null)
      {
        // Make sure that multiple reads at the end of the file will still be
        // null.
        LDIFRecord readRecord = ldifReader.readLDIFRecord();
        if (readRecord != null)
        {
          fail("Expected null, but got " + readRecord);
        }
        break;
      }

      assertTrue(record instanceof LDIFChangeRecord);
    }
    ldifReader.close();
  }



  /**
   * Tests the first constructor for the {@code LDIFWriter} class with a
   * {@code null} argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class,
                               NullPointerException.class })
  public void testLDIFWriterConstructor1Null()
         throws Exception
  {
    new LDIFWriter((String) null);
  }



  /**
   * Tests the second constructor for the {@code LDIFWriter} class with a
   * {@code null} argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class,
                               NullPointerException.class })
  public void testLDIFWriterConstructor2Null()
         throws Exception
  {
    new LDIFWriter((File) null);
  }



  /**
   * Tests the third constructor for the {@code LDIFWriter} class with a
   * {@code null} argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class,
                               NullPointerException.class })
  public void testLDIFWriterConstructor3Null()
         throws Exception
  {
    new LDIFWriter((FileOutputStream) null);
  }



  /**
   * Tests the first constructor for the {@code LDIFReader} class with a
   * {@code null} argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class,
                               NullPointerException.class })
  public void testLDIFReaderConstructor1Null()
         throws Exception
  {
    new LDIFReader((String) null);
  }



  /**
   * Tests the second constructor for the {@code LDIFReader} class with a
   * {@code null} argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class,
                               NullPointerException.class })
  public void testLDIFReaderConstructor2Null()
         throws Exception
  {
    new LDIFReader((File) null);
  }



  /**
   * Tests the third constructor for the {@code LDIFReader} class with a
   * {@code null} argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class,
                               NullPointerException.class })
  public void testLDIFReaderConstructor3Null()
         throws Exception
  {
    new LDIFReader((FileInputStream) null);
  }



  /**
   * Tests the fourth constructor for the {@code LDIFReader} class with a
   * {@code null} argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class,
                               NullPointerException.class })
  public void testLDIFReaderConstructor4Null()
         throws Exception
  {
    new LDIFReader((BufferedReader) null);
  }



  /**
   * Tests the behavior of the LDIF reader when reading from an empty LDIF
   * source.
   *
   * @param  numThreads  The number of threads to use when reading the LDIF.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testNumThreads")
  public void testReadEmptySource(int numThreads)
         throws Exception
  {
    ByteArrayInputStream inputStream = new ByteArrayInputStream(new byte[0]);

    LDIFReader ldifReader = new LDIFReader(inputStream, numThreads);
    assertNull(ldifReader.readEntry());
    assertNull(ldifReader.readEntry());
    assertNull(ldifReader.readEntry());
    assertNull(ldifReader.readEntry());
    assertNull(ldifReader.readEntry());
  }



  /**
   * Tests the behavior of the LDIF reader when reading from an LDIF source that
   * contains only blank lines and comments.
   *
   * @param  numThreads  The number of threads to use when reading the LDIF.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testNumThreads")
  public void testReadOnlyBlanksAndComments(int numThreads)
         throws Exception
  {
    String ldif =
         EOL + EOL + EOL +
         "# This is the first comment" + EOL +
         "# This is the second comment" + EOL +
         EOL;

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(ldif.getBytes("UTF-8"));

    LDIFReader ldifReader = new LDIFReader(inputStream, numThreads);
    assertNull(ldifReader.readEntry());
  }



  /**
   * Tests the behavior of the LDIF reader when reading from an LDIF source that
   * contains only blank lines and comments and the version identifier.
   *
   * @param  numThreads  The number of threads to use when reading the LDIF.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testNumThreads")
  public void testReadOnlyBlanksAndCommentsAndVersion(int numThreads)
         throws Exception
  {
    String ldif =
         EOL +
         "version: 1" + EOL +
         EOL + EOL + EOL +
         "# This is the first comment" + EOL +
         "# This is the second comment" + EOL +
         EOL;

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(ldif.getBytes("UTF-8"));

    LDIFReader ldifReader = new LDIFReader(inputStream, numThreads);
    assertNull(ldifReader.readEntry());
  }



  /**
   * Tests the behavior of the LDIF reader when encountering a space at the
   * beginning of the first line.
   *
   * @param  numThreads  The number of threads to use when reading the LDIF.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class },
        dataProvider = "testNumThreads")
  public void testReadSpaceAtBeginning(int numThreads)
         throws Exception
  {
    String ldif =
         " dn: dc=example,dc=com" + EOL +
         "objectClass: top" + EOL +
         "objectClass: domain" + EOL +
         "dc: example" + EOL;

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(ldif.getBytes("UTF-8"));

    LDIFReader ldifReader = null;
    try
    {
      ldifReader = new LDIFReader(inputStream, numThreads);
      ldifReader.readEntry();
    }
    finally
    {
      if (ldifReader != null)
      {
        ldifReader.close();
      }
    }
  }



  /**
   * Tests using an Entry translator with the LDIFReader using a buffered reader
   * as the source.
   *
   * @param numThreads The number of threads to use when parsing the LDIF.
   *
   * @throws Exception If the test fails.
   */
  @Test(dataProvider = "testNumThreads")
  public void testEntryTranslatorReader(int numThreads)
       throws Exception
  {
    final Entry entryOne = new Entry(
         "dn: dc=one,dc=com",
         "objectClass: domain",
         "dc: one");

    final Entry entryTwo = new Entry(
         "dn: dc=two,dc=com",
         "objectClass: domain",
         "dc: two");

    final Entry entryThree = new Entry(
         "dn: dc=three,dc=com",
         "objectClass: domain",
         "dc: three");

    final Entry entryFour = new Entry(
         "dn: dc=four,dc=com",
         "objectClass: domain",
         "dc: four");

    StringReader reader = new StringReader(
         entryOne.toLDIFString() + EOL +
         entryTwo.toLDIFString() + EOL +
         entryThree.toLDIFString() + EOL +
         entryFour.toLDIFString());

    final LDIFException entryOneException = new LDIFException("some msg", 0,
                                                              true);

    final AtomicInteger entryNum = new AtomicInteger(0);

    LDIFReader ldifReader = new LDIFReader(
         new BufferedReader(reader),
         numThreads,
         new LDIFReaderEntryTranslator()
         {
           @Override()
           public Entry translate(Entry original, long lineNumber)
                throws LDIFException
           {
             entryNum.incrementAndGet();

             switch (entryNum.get())
             {
               case 1:
                 throw entryOneException;
               case 2:
                 return original;
               case 3:
                 return null;  // This will cause it to be skipped
               case 4:
                 return entryFour;
               default:
                 return null;
             }
           }
         });

    try
    {
      ldifReader.readEntry();
    }
    catch (LDIFException e)
    {
      assertEquals(e, entryOneException);
    }

    Entry readTwo = ldifReader.readEntry();
    assertEquals(readTwo, entryTwo);
    assertTrue(readTwo != entryTwo);  // It should be parsed.

    assertTrue(ldifReader.readEntry() == entryFour);
    assertTrue(ldifReader.readEntry() == null);
  }



  /**
   * Tests using a change record translator with the LDIFReader using a buffered
   * reader as the source.
   *
   * @param numThreads The number of threads to use when parsing the LDIF.
   *
   * @throws Exception If the test fails.
   */
  @Test(dataProvider = "testNumThreads")
  public void testChangeRecordTranslatorReader(int numThreads)
         throws Exception
  {
    final LDIFChangeRecord cr1 = new LDIFAddChangeRecord(new Entry(
         "dn: dc=one,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: one"));

    final LDIFChangeRecord cr2 = new LDIFAddChangeRecord(new Entry(
         "dn: dc=two,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: two",
         "description: should be replaced"));

    final LDIFChangeRecord cr3 =
         new LDIFDeleteChangeRecord("dc=three,dc=com");

    final LDIFChangeRecord cr4 =
         new LDIFDeleteChangeRecord("dc=suppress,dc=com");

    final LDIFChangeRecord cr5 =
         new LDIFDeleteChangeRecord("dc=throw,dc=com");

    final LDIFChangeRecord cr6 = new LDIFModifyChangeRecord(new ModifyRequest(
         "dn: dc=four,dc=com",
         "changetype: modify",
         "add: objectClass",
         "objectClass: extensibleObject"));

    final LDIFChangeRecord cr7 = new LDIFModifyChangeRecord(new ModifyRequest(
         "dn: dc=five,dc=com",
         "changetype: modify",
         "add: description",
         "description: foo"));

    final LDIFChangeRecord cr8 = new LDIFModifyChangeRecord(new ModifyRequest(
         "dn: dc=six,dc=com",
         "changetype: modify",
         "replace: description",
         "description: bar"));

    final LDIFChangeRecord cr9 = new LDIFModifyChangeRecord(new ModifyRequest(
         "dn: dc=seven,dc=com",
         "changetype: modify",
         "delete: description",
         "description: baz"));

    final LDIFChangeRecord cr10 = new LDIFModifyDNChangeRecord(
         "dc=eight,dc=com", "dc=8", true, null);

    final StringReader stringReader = new StringReader(
         cr1.toLDIFString() + EOL +
         cr2.toLDIFString() + EOL +
         cr3.toLDIFString() + EOL +
         cr4.toLDIFString() + EOL +
         cr5.toLDIFString() + EOL +
         cr6.toLDIFString() + EOL +
         cr7.toLDIFString() + EOL +
         cr8.toLDIFString() + EOL +
         cr9.toLDIFString() + EOL +
         cr10.toLDIFString() + EOL);

    final LDIFReader reader = new LDIFReader(new BufferedReader(stringReader),
         numThreads, this, this);

    assertEquals(reader.readChangeRecord(),
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=one,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: one",
              "description: replacedOnRead")));

    assertEquals(reader.readChangeRecord(),
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=two,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: two",
              "description: replacedOnRead")));

    assertEquals(reader.readChangeRecord(),
         new LDIFDeleteChangeRecord("dc=three,dc=com"));

    try
    {
      reader.readChangeRecord();
      fail("Expected an exception from the LDIFReaderChangeRecordTranslator");
    }
    catch (final LDIFException le)
    {
      // This was expected.
    }

    assertEquals(reader.readChangeRecord(),
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=four,dc=com",
              "changetype: modify",
              "add: objectClass",
              "objectClass: extensibleObject",
              "-",
              "replace: description",
              "description: replacedOnRead")));

    assertEquals(reader.readChangeRecord(),
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=five,dc=com",
              "changetype: modify",
              "add: description",
              "description: replacedOnRead")));

    assertEquals(reader.readChangeRecord(),
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=six,dc=com",
              "changetype: modify",
              "replace: description",
              "description: replacedOnRead")));

    assertEquals(reader.readChangeRecord(),
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=seven,dc=com",
              "changetype: modify",
              "delete: description",
              "description: baz",
              "-",
              "replace: description",
              "description: replacedOnRead")));

    assertEquals(reader.readChangeRecord(),
         new LDIFModifyDNChangeRecord("dc=eight,dc=com", "dc=8", true, null));

    assertNull(reader.readChangeRecord());

    reader.close();
  }



  /**
   * Tests using an Entry translator with the LDIFReader using an input stream
   * as the source.
   *
   * @param numThreads The number of threads to use when parsing the LDIF.
   *
   * @throws Exception If the test fails.
   */
  @Test(dataProvider = "testNumThreads")
  public void testEntryTranslatorInputStream(int numThreads)
       throws Exception
  {
    final Entry entryOne = new Entry(
         "dn: dc=one,dc=com",
         "objectClass: domain",
         "dc: one");

    final Entry entryTwo = new Entry(
         "dn: dc=two,dc=com",
         "objectClass: domain",
         "dc: two");

    final Entry entryThree = new Entry(
         "dn: dc=three,dc=com",
         "objectClass: domain",
         "dc: three");

    final Entry entryFour = new Entry(
         "dn: dc=four,dc=com",
         "objectClass: domain",
         "dc: four");

    ArrayList<String> lineList = new ArrayList<String>();
    lineList.addAll(Arrays.asList(entryOne.toLDIF()));
    lineList.add("");
    lineList.addAll(Arrays.asList(entryTwo.toLDIF()));
    lineList.add("");
    lineList.addAll(Arrays.asList(entryThree.toLDIF()));
    lineList.add("");
    lineList.addAll(Arrays.asList(entryFour.toLDIF()));

    String[] lines = new String[lineList.size()];
    lineList.toArray(lines);

    File tempFile = createTempFile(lines);

    final LDIFException entryOneException = new LDIFException("some msg", 0,
                                                              true);

    final AtomicInteger entryNum = new AtomicInteger(0);

    LDIFReader ldifReader = new LDIFReader(
         new FileInputStream(tempFile),
         numThreads,
         new LDIFReaderEntryTranslator()
         {
           @Override()
           public Entry translate(Entry original, long lineNumber)
                throws LDIFException
           {
             entryNum.incrementAndGet();

             switch (entryNum.get())
             {
               case 1:
                 throw entryOneException;
               case 2:
                 return original;
               case 3:
                 return null;  // This will cause it to be skipped
               case 4:
                 return entryFour;
               default:
                 return null;
             }
           }
         });

    try
    {
      ldifReader.readEntry();
    }
    catch (LDIFException e)
    {
      assertEquals(e, entryOneException);
    }

    Entry readTwo = ldifReader.readEntry();
    assertEquals(readTwo, entryTwo);
    assertTrue(readTwo != entryTwo);  // It should be parsed.

    assertTrue(ldifReader.readEntry() == entryFour);
    assertTrue(ldifReader.readEntry() == null);
    tempFile.delete();
  }



  /**
   * Provides test parameters for testCloseAsync.
   *
   * @return  Parameters for testCloseAsync.
   */
  @DataProvider
  public Object[][] closeAsyncParams()
  {
    return new Object[][]{
         new Object[]{ 0, 0, 0 },
         new Object[]{ 10, 2, 0 },
         new Object[]{ 400, 0, 0 },
         new Object[]{ 400, 2, 0 },
         new Object[]{ 2000, 0, 0 },
         new Object[]{ 2000, 2, 0 },
         new Object[]{ 10, 2, 10 },
         new Object[]{ 400, 0, 10 },
         new Object[]{ 400, 2, 10 },
         new Object[]{ 2000, 0, 10 },
         new Object[]{ 2000, 2, 10 },
    };
  }



  /**
   * Tests that closing the LDIFReader closes all threads.
   *
   * @param numInputEntries The number of entries in the LDIF input.
   * @param numThreads      The number of threads to use for parsing.
   * @param numToRead       The number of entries to read before closing.
   *
   * @throws Exception If the test fails.
   */
  @Test(dataProvider = "closeAsyncParams")
  public void testCloseAync(int numInputEntries, int numThreads, int numToRead)
       throws Exception
  {
    StringBuilder buffer = new StringBuilder();
    for (int i = 0; i < numInputEntries; i++)
    {
      buffer.append("dn: dc=com" + EOL +
                    "objectClass: domain" + EOL +
                    "dc: com" + EOL + EOL);
    }

    StringReader reader = new StringReader(buffer.toString());

    Set<Thread> threadsBefore = Thread.getAllStackTraces().keySet();

    LDIFReader ldifReader = new LDIFReader(
         new BufferedReader(reader),
         numThreads);

    for (int i = 0; i < numToRead; i++)
    {
      ldifReader.readEntry();
    }

    ldifReader.close();

    try
    {
      reader.ready();
      fail("Expected 'Stream closed' IOException");
    }
    catch (IOException e)
    {
      // This is expected since the stream should be closed.
    }

    //
    // All of the threads allocated by the reader might not be shutdown when
    // close() returns, but they should shutdown eventually.
    //

    long failAtMs = System.currentTimeMillis() + 10 * 1000;
    while (System.currentTimeMillis() < failAtMs)
    {
      Set<Thread> threadsAfter = Thread.getAllStackTraces().keySet();
      if (threadsBefore.containsAll(threadsAfter))
      {
        return; // Success
      }
      Thread.sleep(10);
    }

    Map<Thread, StackTraceElement[]> stacks = Thread.getAllStackTraces();
    Set<Thread> extraThreads = new HashSet<Thread>(stacks.keySet());
    extraThreads.removeAll(threadsBefore);

    if (!extraThreads.isEmpty())
    {
      StringBuilder failureInfo = new StringBuilder();
      for (Thread thread: extraThreads)
      {
        failureInfo.append(EOL);
        failureInfo.append("Thread " + thread + " : ");
        failureInfo.append(StaticUtils.getStackTrace(stacks.get(thread)));
      }
      fail("LDIFReader#close() should have stopped all new Threads, but some " +
           "are still running: " + failureInfo);
    }
  }



  /**
   * Tests that getting a read error from the underlying input eventually
   * gets propagated up to readEntry().
   *
   * @param numThreads      The number of threads to use for parsing.
   *
   * @throws Exception If the test fails.
   */
  @Test(dataProvider = "testNumThreads")
  public void testAsyncReadError(int numThreads)
       throws Exception
  {
    StringBuilder buffer = new StringBuilder();
    for (int i = 0; i < 2000; i++)
    {
      buffer.append("dn: dc=com" + EOL +
                    "objectClass: domain" + EOL +
                    "dc: com" + EOL + EOL);
    }

    TestReader r = new TestReader(new StringReader(buffer.toString()),
                                  new IOException(), 10000, true);
    BufferedReader reader = new BufferedReader(r);

    LDIFReader ldifReader = new LDIFReader(reader, numThreads);

    int numRead = 0;
    boolean exceptionCaught = false;
    try
    {
      // Read through the file until we get null (i.e. EOF) or an Exception.
      while (ldifReader.readEntry() != null)
      {
        numRead++;
      }
    }
    catch (Exception e)
    {
      exceptionCaught = true;
    }

    assertTrue(exceptionCaught, "Expected readEntry() to throw, but it didn't" +
         "  Read " + numRead + " entries instead.");
  }



  /**
   * Test reading records that are not the right type.
   *
   * @param numThreads The number of threads to use when parsing the LDIF.
   *
   * @throws Exception If the test fails.
   */
  @Test(dataProvider = "testNumThreads")
  public void testReadWrongType(int numThreads)
       throws Exception
  {
    String ldif = "dn: dc=com0"          + EOL +
                  "changetype: modify"   + EOL +
                  "replace: description" + EOL +
                  "description: test"    + EOL +
                  "--"                   + EOL +
                  "delete: seeAlso"      + EOL +
                                           EOL +
                  "dn: dc=com1"          + EOL +
                  "changetype: add"      + EOL +
                  "objectclass: domain"  + EOL +
                  "dc: com1"             + EOL +
                                           EOL +
                  "dn: dc=com2"          + EOL +
                  "objectclass: domain"  + EOL +
                  "dc: com2"             + EOL +
                                           EOL +
                  "dn: dc=com3"          + EOL +
                  "objectclass: domain"  + EOL +
                  "dc: com3"             + EOL +
                                           EOL;

    LDIFReader reader = new LDIFReader(
         new BufferedReader(new StringReader(ldif)), numThreads);

    try
    {
      Entry entry = reader.readEntry();
      fail("Expected readEntry to fail since it's not an Entry. " +
           "But read: " + entry);
    }
    catch (LDIFException e)
    {
      // This is expected.
    }

    // This will succeed.  It will just have an attribute that's 'changetype'.
    Entry entry = reader.readEntry();
    assertEquals(entry.getAttributeValue("changetype"), "add");

    try
    {
      reader.readChangeRecord();
      fail("Expected readChangeRecord to fail since it's an Entry.");
    }
    catch (LDIFException e)
    {
      // This is expected.
    }

    // This should succeed because we'll convert the entry to a change record.
    LDIFChangeRecord changeRecord = reader.readChangeRecord(true);
    assertEquals(changeRecord.getDN(), "dc=com3");

    assertTrue(reader.readEntry() == null);
}



  /**
   * Tests the {@code decodeEntry} method with a valid LDIF entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntry()
         throws Exception
  {
    LDIFReader.decodeEntry("dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
  }



  /**
   * Tests the {@code decodeEntry} method with a valid LDIF entry using schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryWithSchema()
         throws Exception
  {
    LDIFReader.decodeEntry(true, schema,
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
  }



  /**
   * Tests the {@code decodeEntry} method with a valid LDIF entry using schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryWithSchemaAndVersion()
         throws Exception
  {
    LDIFReader.decodeEntry(true, schema,
         "version: 1",
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
  }



  /**
   * Tests the {@code decodeEntry} method with a valid LDIF entry with split
   * lines.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntrySplitLines()
         throws Exception
  {
    LDIFReader.decodeEntry("# This comm",
                           " ent is spl",
                           " it",
                           "dn: dc=exam",
                           " ple,dc=com",
                           "# This comm",
                           " ent is spl",
                           " it, too",
                           "objectClass",
                           " : top",
                           "objectClass",
                           " : domain",
                           "dc: example");
  }



  /**
   * Tests the {@code decodeEntry} method with a valid LDIF entry with split
   * lines using schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntrySplitLinesWithSchema()
         throws Exception
  {
    LDIFReader.decodeEntry(true, schema,
                           "# This comm",
                           " ent is spl",
                           " it",
                           "dn: dc=exam",
                           " ple,dc=com",
                           "# This comm",
                           " ent is spl",
                           " it, too",
                           "objectClass",
                           " : top",
                           "objectClass",
                           " : domain",
                           "dc: example");
  }



  /**
   * Tests the {@code decodeEntry} method with an empty set of content.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeEntryNoContent()
         throws Exception
  {
    LDIFReader.decodeEntry("# This is just a comment");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry where the first line
   * starts with a space.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeEntryStartsWithSpace()
         throws Exception
  {
    LDIFReader.decodeEntry(" dn: dc=example,dc=com",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry where the first line
   * doesn't contain a DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeEntryStartsWithNonDN()
         throws Exception
  {
    LDIFReader.decodeEntry("objectClass: top",
                           "objectClass: domain",
                           "dc: example");
  }



  /**
   * Tests the {@code decodeEntry} method with a valid LDIF entry with trailing
   * blank lines.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryTrailingBlanks()
         throws Exception
  {
    LDIFReader.decodeEntry("dn: dc=example,dc=com",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example",
                           "",
                           "");
  }



  /**
   * Tests the {@code decodeEntry} method with a valid LDIF entry with trailing
   * blank lines with schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryTrailingBlanksWithSchema()
         throws Exception
  {
    LDIFReader.decodeEntry(true, schema,
                           "dn: dc=example,dc=com",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example",
                           "",
                           "");
  }



  /**
   * Tests the {@code decodeEntry} method with only blank lines.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeEntryOnlyBlanks()
         throws Exception
  {
    LDIFReader.decodeEntry("",
                           "",
                           "");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with invalid blank lines
   * in the middle of the entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeEntryInvalidMiddleBlanks()
         throws Exception
  {
    LDIFReader.decodeEntry("dn: dc=example,dc=com",
                           "objectClass: top",
                           "objectClass: domain",
                           "",
                           "dc: example");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry that doesn't have a
   * colon in the DN line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeEntryDNLineNoColon()
         throws Exception
  {
    LDIFReader.decodeEntry("dn dc=example,dc=com",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry that doesn't have a
   * colon in an attribute line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeEntryAttrLineNoColon()
         throws Exception
  {
    LDIFReader.decodeEntry("dn: dc=example,dc=com",
                           "objectClass top",
                           "objectClass: domain",
                           "dc: example");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with an empty DN with
   * no spaces after the single colon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryEmptyDNNoTrailingSpace()
         throws Exception
  {
    LDIFReader.decodeEntry("dn:",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with an empty DN with
   * no spaces after the single colon with schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryEmptyDNNoTrailingSpaceWithSchema()
         throws Exception
  {
    LDIFReader.decodeEntry(true, schema,
                           "dn:",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with an empty DN with a
   * trailing space after the single colon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryEmptyDNWithTrailingSpace()
         throws Exception
  {
    LDIFReader.decodeEntry("dn: ",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with an empty DN with a
   * trailing space after the single colon with schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryEmptyDNWithTrailingSpaceWithSchema()
         throws Exception
  {
    LDIFReader.decodeEntry(true, schema,
                           "dn: ",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with an empty DN with
   * multiple trailing spaces after the single colon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryEmptyDNMultipleTrailingSpaces()
         throws Exception
  {
    LDIFReader.decodeEntry("dn:     ",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with an empty DN with
   * multiple trailing spaces after the single colon with schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryEmptyDNMultipleTrailingSpacesWithSchema()
         throws Exception
  {
    LDIFReader.decodeEntry(true, schema,
                           "dn:     ",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with a base64-encoded
   * empty DN with no spaces after the double colon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryEmptyBase64DNNoTrailingSpace()
         throws Exception
  {
    LDIFReader.decodeEntry("dn::",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with a base64-encoded
   * empty DN with no spaces after the double colon with schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryEmptyBase64DNNoTrailingSpaceWithSchema()
         throws Exception
  {
    LDIFReader.decodeEntry(true, schema,
                           "dn::",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with a base64-encoded
   * empty DN with a single space after the double colon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryEmptyBase64DNWithTrailingSpace()
         throws Exception
  {
    LDIFReader.decodeEntry("dn:: ",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with a base64-encoded
   * empty DN with a single space after the double colon with schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryEmptyBase64DNWithTrailingSpaceWithSchema()
         throws Exception
  {
    LDIFReader.decodeEntry(true, schema,
                           "dn:: ",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with a base64-encoded
   * empty DN with multiple spaces after the double colon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryEmptyBase64DNMultipleTrailingSpaces()
         throws Exception
  {
    LDIFReader.decodeEntry("dn::     ",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with a base64-encoded
   * empty DN with multiple spaces after the double colon with schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryEmptyBase64DNMultipleTrailingSpacesWithSchema()
         throws Exception
  {
    LDIFReader.decodeEntry(true, schema,
                           "dn::     ",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with a valid
   * base64-encoded DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryValidBase64DN()
         throws Exception
  {
    LDIFReader.decodeEntry("dn:: ZGM9ZXhhbXBsZSxkYz1jb20=",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with a valid
   * base64-encoded DN with schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryValidBase64DNWithSchema()
         throws Exception
  {
    LDIFReader.decodeEntry(true, schema,
                           "dn:: ZGM9ZXhhbXBsZSxkYz1jb20=",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with an invalid
   * base64-encoded DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeEntryInvalidBase64DN()
         throws Exception
  {
    LDIFReader.decodeEntry("dn:: invalid-base-64",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with an empty attribute
   * with no spaces after the single colon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryEmptyAttrNoTrailingSpace()
         throws Exception
  {
    LDIFReader.decodeEntry("dn: dc=example,dc=com",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example",
                           "description:");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with an empty attribute
   * with no spaces after the single colon with schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryEmptyAttrNoTrailingSpaceWithSchema()
         throws Exception
  {
    LDIFReader.decodeEntry(true, schema,
                           "dn: dc=example,dc=com",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example",
                           "description:");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with an empty attribute
   * with a trailing space after the single colon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryEmptyAttrWithTrailingSpace()
         throws Exception
  {
    LDIFReader.decodeEntry("dn: dc=example,dc=com",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example",
                           "description: ");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with an empty attribute
   * with a trailing space after the single colon with schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryEmptyAttrWithTrailingSpaceWithSchema()
         throws Exception
  {
    LDIFReader.decodeEntry(true, schema,
                           "dn: dc=example,dc=com",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example",
                           "description: ");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with an empty attribute
   * with multiple trailing spaces after the single colon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryEmptyAttrMultipleTrailingSpaces()
         throws Exception
  {
    LDIFReader.decodeEntry("dn: dc=example,dc=com",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example",
                           "description:     ");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with an empty attribute
   * with multiple trailing spaces after the single colon with schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryEmptyAttrMultipleTrailingSpacesWithSchema()
         throws Exception
  {
    LDIFReader.decodeEntry(true, schema,
                           "dn: dc=example,dc=com",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example",
                           "description:     ");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with a base64-encoded
   * empty attribute with no spaces after the double colon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryEmptyBase64AttrNoTrailingSpace()
         throws Exception
  {
    LDIFReader.decodeEntry("dn: dc=example,dc=com",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example",
                           "description::");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with a base64-encoded
   * empty attribute with no spaces after the double colon with schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryEmptyBase64AttrNoTrailingSpaceWithSchema()
         throws Exception
  {
    LDIFReader.decodeEntry(true, schema,
                           "dn: dc=example,dc=com",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example",
                           "description::");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with a base64-encoded
   * empty attribute with a single space after the double colon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryEmptyBase64AttrWithTrailingSpace()
         throws Exception
  {
    LDIFReader.decodeEntry("dn: dc=example,dc=com",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example",
                           "description:: ");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with a base64-encoded
   * empty attribute with a single space after the double colon with schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryEmptyBase64AttrWithTrailingSpaceWithSchema()
         throws Exception
  {
    LDIFReader.decodeEntry(true, schema,
                           "dn: dc=example,dc=com",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example",
                           "description:: ");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with a base64-encoded
   * empty attribute with multiple spaces after the double colon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryEmptyBase64AttrMultipleTrailingSpaces()
         throws Exception
  {
    LDIFReader.decodeEntry("dn: dc=example,dc=com",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example",
                           "description::     ");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with a base64-encoded
   * empty attribute with multiple spaces after the double colon with schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryEmptyBase64AttrMultipleTrailingSpacesWithSchema()
         throws Exception
  {
    LDIFReader.decodeEntry(true, schema,
                           "dn: dc=example,dc=com",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example",
                           "description::     ");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with a valid
   * base64-encoded attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryValidBase64Attr()
         throws Exception
  {
    LDIFReader.decodeEntry("dn: dc=example,dc=com",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example",
                           "description:: Zm9v");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with a valid
   * base64-encoded attribute with schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryValidBase64AttrWithSchema()
         throws Exception
  {
    LDIFReader.decodeEntry(true, schema,
                           "dn: dc=example,dc=com",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example",
                           "description:: Zm9v");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with an invalid
   * base64-encoded attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeEntryInvalidBase64Attr()
         throws Exception
  {
    LDIFReader.decodeEntry("dn: dc=example,dc=com",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example",
                           "description:: invalid-base-64");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with an empty value
   * after a non-empty value for the same attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryEmptyValueAfterNonEmptyValue()
         throws Exception
  {
    LDIFReader.decodeEntry("dn: dc=example,dc=com",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example",
                           "description: foo",
                           "description:");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with an empty
   * base64-encoded value after a non-empty value for the same attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryEmptyBase64ValueAfterNonEmptyValue()
         throws Exception
  {
    LDIFReader.decodeEntry("dn: dc=example,dc=com",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example",
                           "description: foo",
                           "description::");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with an attribute line
   * that starts with a colon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeEntryLineStartsWithColon()
         throws Exception
  {
    LDIFReader.decodeEntry("dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         ": foo");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry that doesn't contain any
   * attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryNoAttributes()
         throws Exception
  {
    Entry e = LDIFReader.decodeEntry("dn: dc=example,dc=com");
    assertEquals(new DN(e.getDN()), new DN("dc=example,dc=com"));
  }



  /**
   * Tests the {@code decodeEntry} method with an attribute that references an
   * invalid URL type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeEntryInvalidURLType()
         throws Exception
  {
    LDIFReader.decodeEntry("dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description:< invalid://url/type");
  }



  /**
   * Tests the {@code decodeEntry} method with an attribute that references an
   * file URL for a file that does not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeEntryURLNoSuchFile()
         throws Exception
  {
    LDIFReader.decodeEntry("dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description:< file://this/file/does/not/exist");
  }



  /**
   * Tests the {@code decodeEntry} method with an attribute value that does not
   * conform to the associated syntax when no schema is used.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeInvalidSyntaxWithoutSchema()
         throws Exception
  {
    // Single-valued
    LDIFReader.decodeEntry("dn: cn=Test,ou=Groups,dc=example,dc=com",
                           "objectClass: top",
                           "objectClass: groupOfNames",
                           "cn: Test",
                           "member: invalid");

    // Multi-valued
    LDIFReader.decodeEntry("dn: cn=Test,ou=Groups,dc=example,dc=com",
                           "objectClass: top",
                           "objectClass: groupOfNames",
                           "cn: Test",
                           "member: uid=valid,ou=People,dc=example,dc=com",
                           "member: invalid");

    // Value read from file.
    File f = File.createTempFile("ldapsdk-attr-data-", ".value");
    f.deleteOnExit();

    FileWriter fw = new FileWriter(f);
    fw.write("invalid");
    fw.close();

    StringBuilder fileURL = new StringBuilder();
    fileURL.append("file:/");
    appendPathComponentsToURL(f, fileURL);

    LDIFReader.decodeEntry("dn: cn=Test,ou=Groups,dc=example,dc=com",
                           "objectClass: top",
                           "objectClass: groupOfNames",
                           "cn: Test",
                           "member:< " + fileURL);
  }



  /**
   * Tests the {@code decodeEntry} method with an attribute value that does not
   * conform to the associated syntax when schema is used.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeInvalidSyntaxWithSchema()
         throws Exception
  {
    if (schema == null)
    {
      return;
    }

    try
    {
      // Single-valued
      LDIFReader.decodeEntry(true, schema,
                             "dn: cn=Test,ou=Groups,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: groupOfNames",
                             "cn: Test",
                             "member: invalid");
      // At present, this may not throw an exception because of the optimized
      // way in which we handle single-valued attributes.
    }
    catch (LDIFException le)
    {
      // This was expected.
    }

    try
    {
      // Multi-valued with invalid first.
      LDIFReader.decodeEntry(true, schema,
                             "dn: cn=Test,ou=Groups,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: groupOfNames",
                             "cn: Test",
                             "member: invalid",
                             "member: uid=valid,ou=People,dc=example,dc=com");
      fail("Expected an exception due to an invalid first value");
    }
    catch (LDIFException le)
    {
      // This was expected.
    }

    try
    {
      // Multi-valued with invalid first and second empty.
      LDIFReader.decodeEntry(true, schema,
                             "dn: cn=Test,ou=Groups,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: groupOfNames",
                             "cn: Test",
                             "member: invalid",
                             "member:");
      fail("Expected an exception due to an invalid first value with blank");
    }
    catch (LDIFException le)
    {
      // This was expected.
    }

    try
    {
      // Multi-valued with invalid second.
      LDIFReader.decodeEntry(true, schema,
                             "dn: cn=Test,ou=Groups,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: groupOfNames",
                             "cn: Test",
                             "member: uid=valid,ou=People,dc=example,dc=com",
                             "member: invalid");
      fail("Expected an exception due to an invalid subsequent value");
    }
    catch (LDIFException le)
    {
      // This was expected.
    }

    try
    {
      // Invalid base64-encoded value.
      LDIFReader.decodeEntry(true, schema,
                             "dn: cn=Test,ou=Groups,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: groupOfNames",
                             "cn: Test",
                             "member: uid=valid,ou=People,dc=example,dc=com",
                             "member:: aW52YWxpZA==");
      fail("Expected an exception due to an invalid base64-encoded value");
    }
    catch (LDIFException le)
    {
      // This was expected.
    }

    try
    {
      // Value from file
      File f = File.createTempFile("ldapsdk-attr-data-", ".value");
      f.deleteOnExit();

      FileWriter fw = new FileWriter(f);
      fw.write("invalid");
      fw.close();

      StringBuilder fileURL = new StringBuilder();
      fileURL.append("file:/");
      appendPathComponentsToURL(f, fileURL);

      LDIFReader.decodeEntry(true, schema,
                             "dn: cn=Test,ou=Groups,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: groupOfNames",
                             "cn: Test",
                             "member: uid=valid,ou=People,dc=example,dc=com",
                             "member:< " + fileURL);
      fail("Expected an exception due to an invalid value read from a file");
    }
    catch (LDIFException le)
    {
      // This was expected.
    }
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a DN line that does not
   * contain a colon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeChangeRecordNoDNColon()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn dc=example,dc=com",
         "changetype: delete");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a first line that does not
   * start with "dn".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeChangeRecordFirstLineDoesntStartWithDN()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("changetype: delete");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a DN line that is
   * base64-encoded but can't be decoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeChangeRecordInvalidBase64DN()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn:: invalid-base64",
                                  "changetype: delete");
  }



  /**
   * Tests the {@code decodeChangeRecord} method without a changetype line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeChangeRecordNoChangetype()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: dc=example,dc=com");
  }



  /**
   * Tests the {@code decodeChangeRecord} method without a changetype value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeChangeRecordNoChangetypeValue()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: dc=example,dc=com",
                                  "changetype:");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a changetype line that
   * does not contain a colon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeChangeRecordNoChangetypeColon()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: dc=example,dc=com",
                                  "changetype delete");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a second line that
   * doesn't start with "changetype:" and for which defaultAdd is {@code false}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeChangeRecordSecondLineNotChangeTypeNoDefaultAdd()
         throws Exception
  {
    LDIFReader.decodeChangeRecord(false,
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a second line that
   * doesn't start with "changetype:" and for which defaultAdd is {@code true}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeChangeRecordSecondLineNotChangeTypeWithDefaultAdd()
         throws Exception
  {
    LDIFChangeRecord changeRecord = LDIFReader.decodeChangeRecord(true,
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    assertTrue(changeRecord instanceof LDIFAddChangeRecord);
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a second line that
   * doesn't start with "changetype:" and for which defaultAdd is {@code true}
   * with schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void
       testDecodeChangeRecordSecondLineNotChangeTypeWithDefaultAddWithSchema()
         throws Exception
  {
    LDIFChangeRecord changeRecord =
         LDIFReader.decodeChangeRecord(true, schema, true,
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example");

    assertTrue(changeRecord instanceof LDIFAddChangeRecord);
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a record that contains a
   * changetype and for which defaultAdd is {@code true}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeChangeRecordSecondWithChangeTypeAndDefaultAdd()
         throws Exception
  {
    LDIFChangeRecord changeRecord = LDIFReader.decodeChangeRecord(true,
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    assertTrue(changeRecord instanceof LDIFAddChangeRecord);
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a record that contains a
   * changetype and for which defaultAdd is {@code true} with schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void
       testDecodeChangeRecordSecondWithChangeTypeAndDefaultAddWithSchema()
         throws Exception
  {
    LDIFChangeRecord changeRecord =
         LDIFReader.decodeChangeRecord(true, schema, true,
              "dn: dc=example,dc=com",
              "changetype: add",
              "objectClass: top",
              "objectClass: domain",
              "dc: example");

    assertTrue(changeRecord instanceof LDIFAddChangeRecord);
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a changetype line that has
   * an invalid changetype.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeChangeRecordInvalidChangetype()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: dc=example,dc=com",
         "changetype: invalid");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a changetype line that has
   * an invalid base64-encoded changetype.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeChangeRecordInvalidBase64Changetype()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: dc=example,dc=com",
         "changetype:: invalid-base64");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a valid add change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeAddChangeRecord()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a valid add change record
   * with schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeAddChangeRecordWithSchema()
         throws Exception
  {
    LDIFReader.decodeChangeRecord(true, schema, false,
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with an add change record that
   * does not contain any attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeAddChangeRecordNoAttrs()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: dc=example,dc=com",
         "changetype: add");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a valid delete change
   * record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeDeleteChangeRecord()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: dc=example,dc=com",
                                  "changetype: delete");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a valid delete change
   * record with schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeDeleteChangeRecordWithSchema()
         throws Exception
  {
    LDIFReader.decodeChangeRecord(true, schema, false,
                                  "dn: dc=example,dc=com",
                                  "changetype: delete");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a delete change record
   * that contains extra data after the changetype line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeDeleteChangeRecordExtraData()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: dc=example,dc=com",
                                  "changetype: delete",
                                  "objectClass: top",
                                  "objectClass: domain",
                                  "dc: example");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a valid modify change
   * record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeModifyChangeRecord()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: dc=example,dc=com",
                                  "changetype: modify",
                                  "replace: description",
                                  "description: foo");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a valid modify change
   * record with schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeModifyChangeRecordWithSchema()
         throws Exception
  {
    LDIFReader.decodeChangeRecord(true, schema, false,
                                  "dn: dc=example,dc=com",
                                  "changetype: modify",
                                  "replace: description",
                                  "description: foo");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify change record
   * that does not contain any modifications.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyChangeRecordNoModifications()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: dc=example,dc=com",
                                  "changetype: modify");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify change record
   * that does not have a colon in the modification type line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyChangeRecordNoModificationTypeColon()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: dc=example,dc=com",
                                  "changetype: modify",
                                  "replace description",
                                  "description: foo");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify change record
   * that has an invalid modification type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyChangeRecordInvalidModificationType()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: dc=example,dc=com",
                                  "changetype: modify",
                                  "invalid: description",
                                  "description: foo");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify change record
   * that has a mismatch between the modification attribute type and the value
   * attribute type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyChangeRecordAttrNameMismatch()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: dc=example,dc=com",
                                  "changetype: modify",
                                  "replace: description",
                                  "notdescription: foo");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify change record
   * that has a mismatch between the modification attribute type and the value
   * attribute type, but the mismatch is acceptable because the only difference
   * is that the attribute descriptions have different but logically equivalent
   * base names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeModifyChangeRecordAlternateBaseName()
         throws Exception
  {
    if (schema == null)
    {
      return;
    }

    final AttributeTypeDefinition cnTypeByName = schema.getAttributeType("cn");
    final AttributeTypeDefinition cnTypeByOID =
         schema.getAttributeType("2.5.4.3");
    if ((cnTypeByName == null) || (cnTypeByOID == null) ||
        (! cnTypeByName.equals(cnTypeByOID)))
    {
      return;
    }


    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: cn",
         "2.5.4.3: foo");
    final LDIFReader ldifReader = new LDIFReader(ldifFile);
    ldifReader.setSchema(schema);


    final LDIFModifyChangeRecord changeRecord =
         (LDIFModifyChangeRecord)  ldifReader.readChangeRecord();
    assertNotNull(changeRecord);

    assertEquals(changeRecord.getModifications().length, 1);
    assertEquals(changeRecord.getModifications()[0].getAttribute().getName(),
         "cn");

    ldifReader.close();
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify change record
   * that has a mismatch between the modification attribute type and the value
   * attribute type, but the mismatch is acceptable because the only difference
   * is that the attribute descriptions have different but logically equivalent
   * base names, and also sets of equivalent options but in different orders.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeModifyChangeRecordAlternateBaseNameWithOptions()
         throws Exception
  {
    if (schema == null)
    {
      return;
    }

    final AttributeTypeDefinition cnTypeByName = schema.getAttributeType("cn");
    final AttributeTypeDefinition cnTypeByOID =
         schema.getAttributeType("2.5.4.3");
    if ((cnTypeByName == null) || (cnTypeByOID == null) ||
        (! cnTypeByName.equals(cnTypeByOID)))
    {
      return;
    }

    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: cn;a;b",
         "2.5.4.3;b;a: foo");
    final LDIFReader ldifReader = new LDIFReader(ldifFile);
    ldifReader.setSchema(schema);


    final LDIFModifyChangeRecord changeRecord =
         (LDIFModifyChangeRecord)  ldifReader.readChangeRecord();
    assertNotNull(changeRecord);

    assertEquals(changeRecord.getModifications().length, 1);
    assertEquals(changeRecord.getModifications()[0].getAttribute().getName(),
         "cn;a;b");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify change record
   * that has a mismatch between the modification attribute type and the value
   * attribute type, but the mismatch is acceptable because the only difference
   * is that the attribute descriptions have the options in a different order.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeModifyChangeRecordOptionsInDifferentOrder()
         throws Exception
  {
    final LDIFModifyChangeRecord changeRecord =
         (LDIFModifyChangeRecord)  LDIFReader.decodeChangeRecord(
              "dn: dc=example,dc=com",
              "changetype: modify",
              "replace: description;a;b",
              "description;b;a: foo");
    assertEquals(changeRecord.getModifications().length, 1);
    assertEquals(changeRecord.getModifications()[0].getAttribute().getName(),
         "description;a;b");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify change record
   * that has a mismatch between the modification attribute type and the value
   * attribute type, but the mismatch is acceptable because the only difference
   * is that the new attribute description introduces the binary option.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeModifyChangeRecordIntroducedBinaryOption()
         throws Exception
  {
    final LDIFModifyChangeRecord changeRecord =
         (LDIFModifyChangeRecord)  LDIFReader.decodeChangeRecord(
              "dn: dc=example,dc=com",
              "changetype: modify",
              "replace: description",
              "description;binary:: 1234");
    assertEquals(changeRecord.getModifications().length, 1);
    assertEquals(changeRecord.getModifications()[0].getAttribute().getName(),
         "description;binary");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify change record
   * that has a mismatch between the modification attribute type and the value
   * attribute type, but the mismatch is acceptable because the only difference
   * is that the new attribute description introduces the binary option when
   * there is already another option present.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeModifyChangeRecordWithOptionIntroducedBinaryOption()
         throws Exception
  {
    final LDIFModifyChangeRecord changeRecord =
         (LDIFModifyChangeRecord)  LDIFReader.decodeChangeRecord(
              "dn: dc=example,dc=com",
              "changetype: modify",
              "replace: description;foo",
              "description;foo;binary:: 1234");
    assertEquals(changeRecord.getModifications().length, 1);
    assertEquals(changeRecord.getModifications()[0].getAttribute().getName(),
         "description;foo;binary");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify change record
   * that has a mismatch between the modification attribute type and the value
   * attribute type, but the mismatch is acceptable because the only difference
   * is that the new attribute description introduces the binary option when
   * there is another option present, and then has a second value with the same
   * options.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeModifyChangeRecordWithOptionIntroducedBinaryOption2()
         throws Exception
  {
    final LDIFModifyChangeRecord changeRecord =
         (LDIFModifyChangeRecord)  LDIFReader.decodeChangeRecord(
              "dn: dc=example,dc=com",
              "changetype: modify",
              "replace: description;foo",
              "description;foo;binary:: 1234",
              "description;foo;binary:: 5678");
    assertEquals(changeRecord.getModifications().length, 1);
    assertEquals(changeRecord.getModifications()[0].getAttribute().getName(),
         "description;foo;binary");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify change record
   * that has a mismatch between the modification attribute type and the value
   * attribute type.  The mismatch is in the introduction of the binary option,
   * but it comes after a non-binary value has already been provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyChangeRecordWithBinaryOptionIntroducedTooLate()
         throws Exception
  {
    LDIFReader.decodeChangeRecord(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description;foo",
         "description;foo:: 1234",
         "description;foo;binary:: 5678");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify change record
   * that does not have a value in the modification type line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyChangeRecordNoModificationTypeValue()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: dc=example,dc=com",
                                  "changetype: modify",
                                  "replace:");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify change record
   * that does not have a value in the modification type line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyChangeRecordNoModificationTypeValueWithSpace()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: dc=example,dc=com",
                                  "changetype: modify",
                                  "replace: ");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify change record
   * with an invalid base64-encoded attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyChangeRecordInvalidBase64AttributeName()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: dc=example,dc=com",
                                  "changetype: modify",
                                  "replace:: invalid-base64");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify change record
   * that does not have a colon in a value line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyChangeRecordNoValueColon()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: dc=example,dc=com",
                                  "changetype: modify",
                                  "replace: description",
                                  "description foo");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify change record
   * that has an invalid base64-encoded attribute value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyChangeRecordInvalidBase64Value()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: dc=example,dc=com",
                                  "changetype: modify",
                                  "replace: description",
                                  "description:: invalid-base64");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify change record
   * that attempts to add an attribute with no values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyChangeRecordAddMissingValues()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: dc=example,dc=com",
                                  "changetype: modify",
                                  "add: description");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify change record
   * that attempts to increment an attribute with multiple values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyChangeRecordIncrementMultipleValues()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: dc=example,dc=com",
                                  "changetype: modify",
                                  "increment: intValue",
                                  "intValue: 1",
                                  "intValue: 2");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a valid modify DN change
   * record without a newSuperior DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeModifyDNChangeRecordNoNewSuperior()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: ou=People,dc=example,dc=com",
                                  "changetype: moddn",
                                  "newrdn: ou=Users",
                                  "deleteoldrdn: 1");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a valid modify DN change
   * record without a newSuperior DN with schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeModifyDNChangeRecordNoNewSuperiorWithSchema()
         throws Exception
  {
    LDIFReader.decodeChangeRecord(true, schema, false,
                                  "dn: ou=People,dc=example,dc=com",
                                  "changetype: moddn",
                                  "newrdn: ou=Users",
                                  "deleteoldrdn: 1");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a valid modify DN change
   * record with a newSuperior DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeModifyDNChangeRecordWithNewSuperior()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: ou=People,dc=example,dc=com",
                                  "changetype: moddn",
                                  "newrdn: ou=Users",
                                  "deleteoldrdn: 1",
                                  "newsuperior: o=example.com");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a valid modify DN change
   * record with a newSuperior DN with schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeModifyDNChangeRecordWithNewSuperiorWithSchema()
         throws Exception
  {
    LDIFReader.decodeChangeRecord(true, schema, false,
                                  "dn: ou=People,dc=example,dc=com",
                                  "changetype: moddn",
                                  "newrdn: ou=Users",
                                  "deleteoldrdn: 1",
                                  "newsuperior: o=example.com");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify DN change record
   * that doesn't have a newRDN line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyDNChangeRecordNoNewRDN()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: ou=People,dc=example,dc=com",
                                  "changetype: moddn");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify DN change record
   * where the third line isn't a new RDN line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyDNChangeRecordThirdLineNotNewRDN()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: ou=People,dc=example,dc=com",
                                  "changetype: moddn",
                                  "deleteoldrdn: 1");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify DN change record
   * that doesn't have a colon in the newRDN line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyDNChangeRecordNoNewRDNColon()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: ou=People,dc=example,dc=com",
                                  "changetype: moddn",
                                  "newrdn ou=Users",
                                  "deleteoldrdn: 1");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify DN change record
   * that doesn't have a value in the newRDN line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyDNChangeRecordNoNewRDNValue()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: ou=People,dc=example,dc=com",
                                  "changetype: moddn",
                                  "newrdn:",
                                  "deleteoldrdn: 1");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify DN change record
   * that doesn't have a value in the newRDN line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyDNChangeRecordNoNewRDNValueWithSpace()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: ou=People,dc=example,dc=com",
                                  "changetype: moddn",
                                  "newrdn: ",
                                  "deleteoldrdn: 1");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify DN change record
   * that has an invalid base64-encoded new RDN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyDNChangeRecordInvalidBase64NewRDN()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: ou=People,dc=example,dc=com",
                                  "changetype: moddn",
                                  "newrdn:: invalid-base64",
                                  "deleteoldrdn: 1");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify DN change record
   * that doesn't have a deleteOldRDN line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyDNChangeRecordNoDeleteOldRDN()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: ou=People,dc=example,dc=com",
                                  "changetype: moddn",
                                  "newrdn: ou=Users");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify DN change record
   * that doesn't have a colon on the deleteOldRDN line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyDNChangeRecordNoDeleteOldRDNColon()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: ou=People,dc=example,dc=com",
                                  "changetype: moddn",
                                  "newrdn: ou=Users",
                                  "deleteoldrdn 1");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify DN change record
   * that doesn't have a value on the deleteOldRDN line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyDNChangeRecordNoDeleteOldRDNValue()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: ou=People,dc=example,dc=com",
                                  "changetype: moddn",
                                  "newrdn: ou=Users",
                                  "deleteoldrdn:");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify DN change record
   * that doesn't have a value on the deleteOldRDN line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyDNChangeRecordNoDeleteOldRDNValueWithSpace()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: ou=People,dc=example,dc=com",
                                  "changetype: moddn",
                                  "newrdn: ou=Users",
                                  "deleteoldrdn: ");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify DN change record
   * that has an invalid deleteOldRDN value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyDNChangeRecordInvalidDeleteOldRDNValue()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: ou=People,dc=example,dc=com",
                                  "changetype: moddn",
                                  "newrdn: ou=Users",
                                  "deleteoldrdn: invalid");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify DN change record
   * that has an invalid deleteOldRDN value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyDNChangeRecordInvalidDeleteOldRDNBase64Value()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: ou=People,dc=example,dc=com",
                                  "changetype: moddn",
                                  "newrdn: ou=Users",
                                  "deleteoldrdn:: invalid-base64");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify DN change record
   * where the fourth line isn't a deleteOldRDN line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyDNChangeRecordFourthLineNotDeleteOldRDN()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: ou=People,dc=example,dc=com",
                                  "changetype: moddn",
                                  "newrdn: ou=Users",
                                  "newsuperior: o=example.com");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify DN change record
   * that doesn't have a colon in the newSuperior line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyDNChangeRecordNoNewSuperiorColon()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: ou=People,dc=example,dc=com",
                                  "changetype: moddn",
                                  "newrdn: ou=Users",
                                  "deleteoldrdn: 1",
                                  "newsuperior o=example.com");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify DN change record
   * that has an invalid base64-encoded value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyDNChangeRecordInvalidNewSuperiorBase64Value()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: ou=People,dc=example,dc=com",
                                  "changetype: moddn",
                                  "newrdn: ou=Users",
                                  "deleteoldrdn: 1",
                                  "newsuperior:: invalid-base64");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify DN change record
   * where the fifth line isn't a deleteOldRDN line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyDNChangeRecordFifthLineNotNewSuperior()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: ou=People,dc=example,dc=com",
                                  "changetype: moddn",
                                  "newrdn: ou=Users",
                                  "deleteoldrdn: 1",
                                  "notnewsuperior: o=example.com");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a modify DN change record
   * where there is extra data after the newSuperior line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeModifyDNChangeRecordExtraDataAfterNewSuperior()
         throws Exception
  {
    LDIFReader.decodeChangeRecord("dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newrdn: ou=Users",
         "deleteoldrdn: 1",
         "newsuperior: o=example.com",
         "invalid: foo");
  }



  /**
   * Tests the {@code decodeEntry} method with a {@code null} argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testDecodeEntryNull()
         throws Exception
  {
    LDIFReader.decodeEntry((String[]) null);
  }



  /**
   * Tests the {@code decodeEntry} method with an empty set of lines.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testDecodeEntryEmpty()
         throws Exception
  {
    LDIFReader.decodeEntry();
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a {@code null} argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testDecodeChangeRecordNull()
         throws Exception
  {
    LDIFReader.decodeChangeRecord((String[]) null);
  }



  /**
   * Tests the {@code decodeChangeRecord} method with an empty set of lines.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testDecodeChangeRecordEmpty()
         throws Exception
  {
    LDIFReader.decodeChangeRecord();
  }



  /**
   * Retrieves a string array containing several valid LDIF-formatted entries.
   *
   * @return  A string array containing several valid LDIF-formatted entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private String[] getValidLDIFEntries()
          throws Exception
  {
    // Create a small file that we'll use to hold the value for an attribute.
    File f = File.createTempFile("ldapsdk-attr-data-", ".value");
    f.deleteOnExit();

    FileWriter fw = new FileWriter(f);
    fw.write("foo");
    fw.close();


    // Create a "file://" URL that points to the file.
    StringBuilder fileURL = new StringBuilder();
    fileURL.append("file:/");
    appendPathComponentsToURL(f, fileURL);


    return new String[]
    {
      "# This is a comment at the beginning of the file.",
      "version: 1",
      "",
      "dn: dc=example,dc=com", // Just a normal entry
      "objectClass: top",
      "objectClass: domain",
      "dc: example",
      "",
      "# This is a comment before an entry",
      "dn: ou=People,dc=example,dc=com", // Mess with spacing around the colons
      "objectClass:top",
      "objectClass:  organizationalUnit",
      "ou:     People",
      "",
      "dn:: b3U9R3JvcHVzLGRjPWV4YW1wbGUsZGM9Y29t", // Everything in base64
      "objectClass::dg9w",
      "objectClass::     b3JnYW5pemF0aW9uYWxVbml0",
      "ou:: R3JvdXBz",
      "",
      "",  // Really long values.
      "dn: cn=This is a really really really really really really really ",
      " really really really really really really really really long RDN,ou=",
      " This is a really really really really really really really long pare",
      " nt DN,dc=example,dc=com",
      "objectClass: top",
      "objectClass: device",
      "cn: This is a really really really really really really really ",
      " really really really really really really really really long RDN",
      "cn: This is an even longer value.  It is really really really really ",
      " really really really really really really really really really ",
      " really really really really really really really really really ",
      " really really really really really really really really really ",
      " really really really really really really really really really ",
      " really really really really really really really really really ",
      " really really really really really really really really really ",
      " really really really really really really really really long.",
      "",
      "", // Multiple blank lines between entries
      "",
      "",
      "# A comment in the middle of nowhere",
      "",
      "",
      "",
      "dn: uid=test.user,ou=People,dc=example,dc=com",
      "objectClass: top",
      "objectClass: person",
      "uid: test.user",
      "objectClass: organziationalPerson", // Non-contiguous multi-valued attr
      "objectclass: inetOrgPerson", // Different case for attr name
      "givenName: Test",
      "sn: User",
      "cn: Test User",
      "# This is a comment in the middle of an entry",
      "description: This line is going to be ",
      " wrapped onto the next line",
      "# This comment is going to be ",
      " also wrapped onto the next line",
      "description:: Zm9v", // Mix base64 and non-base64 values for an attr
      "a:", // Empty value with no space after the colon
      "b: ", // Empty value with one space after the colon
      "c:     ", // Empty value with multiple spaces after the colon
      "d::", // Empty base64-encoded value with no space after the colon
      "e:: ", // Empty base64-encoded value with one space after the colon
      "f::    ", // Empty base64-encoded value with multiple spaces after colon
      "g:< " + fileURL.toString(), // Data read from a file.
      "f:< " + fileURL.toString(), // Data read from a file for existing attr.
      "# This is a comment at the end of the entry"
      // No space after the last entry.
    };
  }



  /**
   * Retrieves a set of lines that provide valid LDIF change records.
   *
   * @return  A set of lines that provide valid LDIF change records.
   */
  private String[] getLDIFChangeRecords()
  {
    return new String[]
    {
      "dn: dc=example,dc=com",
      "changetype: add",
      "objectClass: top",
      "objectClass: domain",
      "dc: example",
      "",
      "dn: dc=example,dc=com",
      "changetype: delete",
      "",
      "dn: dc=example,dc=com",
      "changetype: modify",
      "add: description",
      "description: foo",
      "description: bar",
      "-",
      "delete: cn",
      "-",
      "replace: objectClass",
      "objectClass: top",
      "objectClass: domain",
      "objectClass: extensibleObject",
      "-",
      "increment: intValue",
      "intValue: 5",
      "",
      "dn: ou=People,dc=example,dc=com",
      "changetype: moddn",
      "newrdn: ou=Users",
      "deleteoldrdn: 1",
      "newsuperior: o=example.com",
      "",
      "dn: ou=People,dc=example,dc=com",
      "changeType: modrdn",
      "newRDN: ou=Users",
      "deleteOldRDN: 1",
      "",
      "dn:",
      "changetype: modify",
      "replace: description",
      "description: foo",
      "",
      "dn: ",
      "changetype: modify",
      "replace: description",
      "description: foo",
      "",
      "dn:    ",
      "changetype: modify",
      "replace: description",
      "description: foo",
      "",
      "dn::",
      "changetype: modify",
      "replace: description",
      "description: foo",
      "",
      "dn:: ",
      "changetype: modify",
      "replace: description",
      "description: foo",
      "",
      "dn::     ",
      "changetype: modify",
      "replace: description",
      "description: foo",
      "",
      "dn:: ZGM9ZXhhbXBsZSxkYz1jb20=",
      "changetype: modify",
      "replace: description",
      "description: foo",
      "",
      "dn: dc=example,dc=com",
      "changetype: modify",
      "replace: description",
      "description:foo",
      "",
      "dn: dc=example,dc=com",
      "changetype: modify",
      "replace: description",
      "description:    foo",
      "",
      "dn: dc=example,dc=com",
      "changetype: modify",
      "replace: description",
      "description::Zm9v",
      "",
      "dn: dc=example,dc=com",
      "changetype: modify",
      "replace: description",
      "description:: Zm9v",
      "",
      "dn: dc=example,dc=com",
      "changetype: modify",
      "replace: description",
      "description::     Zm9v",
      "",
      "dn: dc=example,dc=com",
      "changetype:modify",
      "replace: description",
      "description: foo",
      "",
      "dn: dc=example,dc=com",
      "changetype:     modify",
      "replace: description",
      "description: foo",
      "",
      "dn: dc=example,dc=com",
      "changetype:: bW9kaWZ5",
      "replace: description",
      "description: foo",
      "",
      "dn: dc=example,dc=com",
      "changetype::bW9kaWZ5",
      "replace: description",
      "description: foo",
      "",
      "dn: dc=example,dc=com",
      "changetype::      bW9kaWZ5",
      "replace: description",
      "description: foo",
      "",
      "dn: dc=example,dc=com",
      "changetype: modify",
      "replace:description",
      "description: foo",
      "",
      "dn: dc=example,dc=com",
      "changetype: modify",
      "replace:     description",
      "description: foo",
      "",
      "dn: dc=example,dc=com",
      "changetype: modify",
      "replace::ZGVzY3JpcHRpb24=",
      "description: foo",
      "",
      "dn: dc=example,dc=com",
      "changetype: modify",
      "replace:: ZGVzY3JpcHRpb24=",
      "description: foo",
      "",
      "dn: dc=example,dc=com",
      "changetype: modify",
      "replace::     ZGVzY3JpcHRpb24=",
      "description: foo",
      "",
      "dn: dc=example,dc=com",
      "changetype: modify",
      "replace: description",
      "description:",
      "",
      "dn: dc=example,dc=com",
      "changetype: modify",
      "replace: description",
      "description: ",
      "",
      "dn: dc=example,dc=com",
      "changetype: modify",
      "replace: description",
      "description:     ",
      "",
      "dn: dc=example,dc=com",
      "changetype: modify",
      "replace: description",
      "description::",
      "",
      "dn: dc=example,dc=com",
      "changetype: modify",
      "replace: description",
      "description:: ",
      "",
      "dn: dc=example,dc=com",
      "changetype: modify",
      "replace: description",
      "description::     ",
      "",
      "dn:ou=People,dc=example,dc=com",
      "changetype:moddn",
      "newrdn:ou=Users",
      "deleteoldrdn:1",
      "newsuperior:o=example.com",
      "",
      "dn:     ou=People,dc=example,dc=com",
      "changetype:     moddn",
      "newrdn:     ou=Users",
      "deleteoldrdn:     1",
      "newsuperior:     o=example.com",
      "",
      "dn: ou=People,dc=example,dc=com",
      "changetype: moddn",
      "newrdn::b3U9VXNlcnM=",
      "deleteoldrdn::MA==",
      "newsuperior::bz1leGFtcGxlLmNvbQ==",
      "",
      "dn: ou=People,dc=example,dc=com",
      "changetype: moddn",
      "newrdn:: b3U9VXNlcnM=",
      "deleteoldrdn:: MA==",
      "newsuperior:: bz1leGFtcGxlLmNvbQ==",
      "",
      "dn: ou=People,dc=example,dc=com",
      "changetype: moddn",
      "newrdn::     b3U9VXNlcnM=",
      "deleteoldrdn::     MA==",
      "newsuperior::     bz1leGFtcGxlLmNvbQ==",
      "",
      "dn: ou=People,dc=example,dc=com",
      "changetype: moddn",
      "newrdn: ou=Users",
      "deleteoldrdn: true",
      "newsuperior: o=example.com",
      "",
      "dn: ou=People,dc=example,dc=com",
      "changetype: moddn",
      "newrdn: ou=Users",
      "deleteoldrdn: yes",
      "newsuperior: o=example.com",
      "",
      "dn: ou=People,dc=example,dc=com",
      "changetype: moddn",
      "newrdn: ou=Users",
      "deleteoldrdn: false",
      "newsuperior: o=example.com",
      "",
      "dn: ou=People,dc=example,dc=com",
      "changetype: moddn",
      "newrdn: ou=Users",
      "deleteoldrdn: no",
      "newsuperior: o=example.com",
      "",
      "dn: ou=People,dc=example,dc=com",
      "changetype: moddn",
      "newrdn: ou=Users",
      "deleteoldrdn: 1",
      "newsuperior:",
      "",
      "dn: ou=People,dc=example,dc=com",
      "changetype: moddn",
      "newrdn: ou=Users",
      "deleteoldrdn: 1",
      "newsuperior: ",
      "",
      "dn: ou=People,dc=example,dc=com",
      "changetype: moddn",
      "newrdn: ou=Users",
      "deleteoldrdn: 1",
      "newsuperior:     ",
      "",
      "",  // Really long values.
      "dn: cn=This is a really really really really really really really ",
      " really really really really really really really really long RDN,ou=",
      " This is a really really really really really really really long pare",
      " nt DN,dc=example,dc=com",
      "changetype: moddn",
      "newrdn: This is an even longer value.  It is really really really ",
      " really really really really really really really really really ",
      " really really really really really really really really really ",
      " really really really really really really really really really ",
      " really really really really really really really really really ",
      " really really really really really really really really really ",
      " really really really really really really really really really ",
      " really really really really really really really really long.",
      "deleteoldrdn: 1"
    };
  }



  /**
   * Recursively appends the path to the specified file to the provided buffer.
   *
   * @param  f       The file to be processed.
   * @param  buffer  The buffer to which the file URL data is to be appended.
   */
  private void appendPathComponentsToURL(File f, StringBuilder buffer)
  {
    File parentFile = f.getParentFile();
    if ((parentFile != null) && (parentFile.getName().length() > 0))
    {
      appendPathComponentsToURL(parentFile, buffer);
    }

    buffer.append('/');
    buffer.append(f.getName());
  }



  /**
   * Retrieves a set of integer values that indicate the columns on which to
   * wrap long lines.
   *
   * @return  A set of integer values that indicate the columns on which to wrap
   *          long lines.
   */
  @DataProvider(name = "testWrapColumns")
  private Object[][] getTestWrapColumns()
  {
    return new Object[][]
    {
      new Object[] { -1 },
      new Object[] { 0 },
      new Object[] { 5 },
      new Object[] { 10 },
      new Object[] { 25 },
      new Object[] { 50 },
      new Object[] { 78 },
      new Object[] { 79 },
      new Object[] { 80 },
      new Object[] { 81 },
      new Object[] { 82 },
      new Object[] { 100 },
    };
  }



  /**
   * Retrieves a set of integer values that indicate the columns on which to
   * wrap long lines and the number of threads to use when parsing.
   *
   * @return  A set of integer values that indicate the columns on which to wrap
   *          long lines and the number of threads to use when parsing.
   */
  @DataProvider(name = "testWrapColumnsAndThreads")
  private Object[][] getTestWrapColumnsAndThreads()
  {
    List<Object[]> params = new ArrayList<Object[]>();

    for (int numThreads : new int[]{0, 1, 2, 16, 100})
    {
      for (int wrapColumn : new int[]{-1, 0, 5, 10, 25, 50, 78,
                                      79, 80, 81, 82, 100})
      {
        params.add(new Object[]{ wrapColumn, numThreads });
      }
    }

    return params.toArray(new Object[params.size()][]);
  }



  /**
   * Retrieves a set of integer values that indicate the number of threads to
   * use when reading the LDIF file.
   *
   * @return  A set of integer values that indicate the nubmer of threads to use
   *          when reading the LDIF file.
   */
  @DataProvider(name = "testNumThreads")
  public Object[][] getNumThreads()
  {
    List<Object[]> params = new ArrayList<Object[]>();

    for (int numThreads : new int[]{0, 1, 2, 16, 100})
    {
      params.add(new Object[]{ numThreads });
    }

    return params.toArray(new Object[params.size()][]);
  }



  /**
   * Provides coverage for the {@code writeComment} method.
   *
   * @param  wrapColumn  The column at which to wrap long lines.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testWrapColumns")
  public void testWriteComment(int wrapColumn)
         throws Exception
  {
    String emptyComment = "";
    String shortComment = "a";
    String midComment = "This is a decent-sized comment";
    String longComment =
         "This is a really really really really really really really really " +
         "really really really really\nreally really really really really " +
         "really really really really really really really really really " +
         "really really really really really\r\nreally really really really " +
         "really really really really really really really really really " +
         "really really really really really really really really really " +
         "really really really really really\nreally really really really " +
         "really really really really really really really really really " +
         "really really really really really\n\nreally really really really " +
         "really really really really really really really really really " +
         "really really really really really\r\nreally really really really " +
         "really really really really really really really long comment.\n";

    LDIFWriter writer = new LDIFWriter(new ByteArrayOutputStream());
    writer.setWrapColumn(wrapColumn);

    writer.writeComment(emptyComment, true, true);
    writer.writeComment(emptyComment, true, false);
    writer.writeComment(emptyComment, false, true);
    writer.writeComment(emptyComment, false, false);

    writer.writeComment(shortComment, true, true);
    writer.writeComment(shortComment, true, false);
    writer.writeComment(shortComment, false, true);
    writer.writeComment(shortComment, false, false);

    writer.writeComment(midComment, true, true);
    writer.writeComment(midComment, true, false);
    writer.writeComment(midComment, false, true);
    writer.writeComment(midComment, false, false);

    writer.writeComment(longComment, true, true);
    writer.writeComment(longComment, true, false);
    writer.writeComment(longComment, false, true);
    writer.writeComment(longComment, false, false);
  }



  /**
   * Tests the ability to read entries from LDIF, convert them back to LDIF via
   * LDIFRecord.toLDIF(), and parse the result as valid LDIF and ensure that
   * the entry is the same.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtensiveViaToLDIF()
         throws Exception
  {
    File ldifFile = File.createTempFile("ldapsdk-test-", ".ldif");
    ldifFile.deleteOnExit();

    BufferedWriter bw = new BufferedWriter(new FileWriter(ldifFile));
    for (String line : getValidLDIFEntries())
    {
      bw.write(line);
      bw.newLine();
    }
    bw.newLine();
    for (String line : getLDIFChangeRecords())
    {
      bw.write(line);
      bw.newLine();
    }
    bw.close();


    // First, read and write using string paths.
    LDIFReader ldifReader = new LDIFReader(ldifFile.getAbsolutePath());

    while (true)
    {
      LDIFRecord r = ldifReader.readLDIFRecord();
      if (r == null)
      {
        break;
      }

      String[] ldifLines = r.toLDIF();

      LDIFRecord r2;
      if (r instanceof Entry)
      {
        r2 = LDIFReader.decodeEntry(ldifLines);
      }
      else
      {
        r2 = LDIFReader.decodeChangeRecord(ldifLines);
      }

      assertEquals(r, r2, r.toString());
    }

    ldifReader.close();
    ldifFile.delete();
  }



  /**
   * Tests the ability to read entries from LDIF, convert them back to wrapped
   * LDIF via LDIFRecord.toLDIF(int), and parse the result as valid LDIF and
   * ensure that the entry is the same.
   *
   * @param  wrapColumn  The column at which to wrap long lines.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testWrapColumns")
  public void testExtensiveViaToLDIFWithWrapping(int wrapColumn)
         throws Exception
  {
    File ldifFile = File.createTempFile("ldapsdk-test-", ".ldif");
    ldifFile.deleteOnExit();

    BufferedWriter bw = new BufferedWriter(new FileWriter(ldifFile));
    for (String line : getValidLDIFEntries())
    {
      bw.write(line);
      bw.newLine();
    }
    bw.newLine();
    for (String line : getLDIFChangeRecords())
    {
      bw.write(line);
      bw.newLine();
    }
    bw.close();


    // First, read and write using string paths.
    LDIFReader ldifReader = new LDIFReader(ldifFile.getAbsolutePath());

    while (true)
    {
      LDIFRecord r = ldifReader.readLDIFRecord();
      if (r == null)
      {
        break;
      }

      String[] ldifLines = r.toLDIF(wrapColumn);
      if (wrapColumn > 0)
      {
        for (int i=0; i < ldifLines.length; i++)
        {
          assertTrue(ldifLines[i].length() <= wrapColumn);
          if (ldifLines[i].startsWith(" "))
          {
            assertEquals(ldifLines[i-1].length(), wrapColumn);
          }
        }
      }

      LDIFWriter.wrapLines(wrapColumn, ldifLines);

      LDIFRecord r2;
      if (r instanceof Entry)
      {
        r2 = LDIFReader.decodeEntry(ldifLines);
      }
      else
      {
        r2 = LDIFReader.decodeChangeRecord(ldifLines);
      }

      assertEquals(r, r2, r.toString());
    }

    ldifReader.close();
    ldifFile.delete();
  }



  /**
   * Tests the ability to read entries from LDIF, convert them back to LDIF via
   * LDIFRecord.toLDIF(ByteStringBuffer), and parse the result as valid LDIF and
   * ensure that the entry is the same.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtensiveViaToLDIFWithByteStringBuffer()
         throws Exception
  {
    File ldifFile = File.createTempFile("ldapsdk-test-", ".ldif");
    ldifFile.deleteOnExit();

    BufferedWriter bw = new BufferedWriter(new FileWriter(ldifFile));
    for (String line : getValidLDIFEntries())
    {
      bw.write(line);
      bw.newLine();
    }
    bw.newLine();
    for (String line : getLDIFChangeRecords())
    {
      bw.write(line);
      bw.newLine();
    }
    bw.close();


    // First, read and write using string paths.
    LDIFReader ldifReader = new LDIFReader(ldifFile.getAbsolutePath());

    while (true)
    {
      LDIFRecord r = ldifReader.readLDIFRecord();
      if (r == null)
      {
        break;
      }

      ByteStringBuffer buffer = new ByteStringBuffer();
      r.toLDIF(buffer);
      String[] ldifLines = stringToLines(buffer.toString());

      LDIFRecord r2;
      if (r instanceof Entry)
      {
        r2 = LDIFReader.decodeEntry(ldifLines);
      }
      else
      {
        r2 = LDIFReader.decodeChangeRecord(ldifLines);
      }

      assertEquals(r, r2, r.toString());
    }

    ldifReader.close();
    ldifFile.delete();
  }



  /**
   * Tests the ability to read entries from LDIF, convert them back to LDIF via
   * LDIFRecord.toLDIF(ByteStringBuffer,int), and parse the result as valid LDIF
   * and ensure that the entry is the same.
   *
   * @param  wrapColumn  The column at which to wrap long lines.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testWrapColumns")
  public void testExtensiveViaToLDIFWithByteStringBufferWithWrapping(
                   int wrapColumn)
         throws Exception
  {
    File ldifFile = File.createTempFile("ldapsdk-test-", ".ldif");
    ldifFile.deleteOnExit();

    BufferedWriter bw = new BufferedWriter(new FileWriter(ldifFile));
    for (String line : getValidLDIFEntries())
    {
      bw.write(line);
      bw.newLine();
    }
    bw.newLine();
    for (String line : getLDIFChangeRecords())
    {
      bw.write(line);
      bw.newLine();
    }
    bw.close();


    // First, read and write using string paths.
    LDIFReader ldifReader = new LDIFReader(ldifFile.getAbsolutePath());

    while (true)
    {
      LDIFRecord r = ldifReader.readLDIFRecord();
      if (r == null)
      {
        break;
      }

      ByteStringBuffer buffer = new ByteStringBuffer();
      r.toLDIF(buffer, wrapColumn);
      String[] ldifLines = stringToLines(buffer.toString());
      if (wrapColumn > 0)
      {
        for (int i=0; i < ldifLines.length; i++)
        {
          assertTrue(ldifLines[i].length() <= wrapColumn);
          if (ldifLines[i].startsWith(" "))
          {
            assertEquals(ldifLines[i-1].length(), wrapColumn,
                         "Offending line:  " + i + "; LDIF:\n" +
                         buffer.toString());
          }
        }
      }

      LDIFWriter.wrapLines(wrapColumn, ldifLines);

      LDIFRecord r2;
      if (r instanceof Entry)
      {
        r2 = LDIFReader.decodeEntry(ldifLines);
      }
      else
      {
        r2 = LDIFReader.decodeChangeRecord(ldifLines);
      }

      assertEquals(r, r2, r.toString());
    }

    ldifReader.close();
    ldifFile.delete();
  }



  /**
   * Tests the ability to read entries from LDIF, convert them back to LDIF via
   * LDIFRecord.toLDIFString(StringBuilder), and parse the result as valid LDIF
   * and ensure that the entry is the same.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtensiveViaToLDIFString()
         throws Exception
  {
    File ldifFile = File.createTempFile("ldapsdk-test-", ".ldif");
    ldifFile.deleteOnExit();

    BufferedWriter bw = new BufferedWriter(new FileWriter(ldifFile));
    for (String line : getValidLDIFEntries())
    {
      bw.write(line);
      bw.newLine();
    }
    bw.newLine();
    for (String line : getLDIFChangeRecords())
    {
      bw.write(line);
      bw.newLine();
    }
    bw.close();


    // First, read and write using string paths.
    LDIFReader ldifReader = new LDIFReader(ldifFile.getAbsolutePath());

    while (true)
    {
      LDIFRecord r = ldifReader.readLDIFRecord();
      if (r == null)
      {
        break;
      }

      StringBuilder buffer = new StringBuilder();
      r.toLDIFString(buffer);
      String[] ldifLines = stringToLines(buffer.toString());

      LDIFRecord r2;
      if (r instanceof Entry)
      {
        r2 = LDIFReader.decodeEntry(ldifLines);
      }
      else
      {
        r2 = LDIFReader.decodeChangeRecord(ldifLines);
      }

      assertEquals(r, r2, r.toString());
    }

    ldifReader.close();
    ldifFile.delete();
  }



  /**
   * Tests the ability to read entries from LDIF, convert them back to LDIF via
   * LDIFRecord.toLDIFString(StringBuilder,int), and parse the result as valid
   * LDIF and ensure that the entry is the same.
   *
   * @param  wrapColumn  The column at which to wrap long lines.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testWrapColumns")
  public void testExtensiveViaToLDIFStringWithWrapping(int wrapColumn)
         throws Exception
  {
    File ldifFile = File.createTempFile("ldapsdk-test-", ".ldif");
    ldifFile.deleteOnExit();

    BufferedWriter bw = new BufferedWriter(new FileWriter(ldifFile));
    for (String line : getValidLDIFEntries())
    {
      bw.write(line);
      bw.newLine();
    }
    bw.newLine();
    for (String line : getLDIFChangeRecords())
    {
      bw.write(line);
      bw.newLine();
    }
    bw.close();


    // First, read and write using string paths.
    LDIFReader ldifReader = new LDIFReader(ldifFile.getAbsolutePath());

    while (true)
    {
      LDIFRecord r = ldifReader.readLDIFRecord();
      if (r == null)
      {
        break;
      }

      StringBuilder buffer = new StringBuilder();
      r.toLDIFString(buffer, wrapColumn);
      String[] ldifLines = stringToLines(buffer.toString());
      if (wrapColumn > 0)
      {
        for (int i=0; i < ldifLines.length; i++)
        {
          assertTrue(ldifLines[i].length() <= wrapColumn);
          if (ldifLines[i].startsWith(" "))
          {
            assertEquals(ldifLines[i-1].length(), wrapColumn,
                         "Offending line:  " + i + "; LDIF:\n" +
                         buffer.toString());
          }
        }
      }

      LDIFWriter.wrapLines(wrapColumn, ldifLines);

      LDIFRecord r2;
      if (r instanceof Entry)
      {
        r2 = LDIFReader.decodeEntry(ldifLines);
      }
      else
      {
        r2 = LDIFReader.decodeChangeRecord(ldifLines);
      }

      assertEquals(r, r2, r.toString());
    }

    ldifReader.close();
    ldifFile.delete();
  }



  /**
   * Provides test coverage for a large entry that includes an attribute with a
   * large number of values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLargeEntry()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=Test Group,ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: groupOfNames",
         "cn: Test Group");

    String[] values = new String[1000];
    for (int i=0; i < 1000; i++)
    {
      values[i] = "uid=user." + i + ",ou=People,dc=example,dc=com";
    }
    e.addAttribute("member", values);


    File ldifFile = createTempFile();
    ldifFile.delete();

    LDIFWriter writer = new LDIFWriter(ldifFile);
    writer.writeVersionHeader();
    writer.writeEntry(e);
    writer.close();

    LDIFReader reader = new LDIFReader(ldifFile);
    Entry e2 = reader.readEntry();
    reader.close();

    assertNotNull(e2);
    assertEquals(e2, e);

    ldifFile.delete();
  }



  /**
   * Provides test coverage for a large entry that includes an attribute with a
   * large number of values, as well as data read from a file.  This will only
   * be invoked on UNIX-based systems to avoid potential problems with Windows
   * paths.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLargeEntryWithDataFromFile()
         throws Exception
  {
    File dataFile1 = createTempFile();
    FileWriter w = new FileWriter(dataFile1);
    w.write("foo");
    w.close();

    StringBuilder url1 = new StringBuilder();
    url1.append("file://");
    appendPathComponentsToURL(dataFile1, url1);

    File dataFile2 = createTempFile();
    w = new FileWriter(dataFile2);
    w.write("bar");
    w.close();

    StringBuilder url2 = new StringBuilder();
    url2.append("file://");
    appendPathComponentsToURL(dataFile2, url2);

    ArrayList<String> lines = new ArrayList<String>();
    lines.add("dn: cn=Test Group,ou=Groups,dc=example,dc=com");
    lines.add("objectClass: top");
    lines.add("objectClass: groupOfNames");
    lines.add("objectClass: extensibleObject");
    lines.add("cn: Test Group");
    lines.add("singleValueFromFile:< " + url1.toString());
    lines.add("multipleValuesFromFile:< " + url1.toString());
    lines.add("multipleValuesFromFile:< " + url2.toString());
    lines.add("singleEmptyValue: ");
    lines.add("multipleValuesWithFirstEmpty: ");
    lines.add("multipleValuesWithFirstEmpty: secondNotEmpty");
    lines.add("multipleValuesWithSecondEmpty: firstNotEmpty");
    lines.add("multipleValuesWithSecondEmpty: ");
    lines.add("singleEmptyBase64Value:: ");
    lines.add("multipleBase64ValuesWithFirstEmpty:: ");
    lines.add("multipleBase64ValuesWithFirstEmpty:: Zm9v");
    lines.add("multipleBase64ValuesWithSecondEmpty:: Zm9v");
    lines.add("multipleBase64ValuesWithSecondEmpty:: ");
    lines.add("singleEmptyValueNoSpace:");
    lines.add("multipleValuesWithFirstEmptyNoSpace:");
    lines.add("multipleValuesWithFirstEmptyNoSpace:secondNotEmpty");
    lines.add("multipleValuesWithSecondEmptyNoSpace:firstNotEmpty");
    lines.add("multipleValuesWithSecondEmptyNoSpace:");
    lines.add("singleEmptyBase64ValueNoSpace::");
    lines.add("multipleBase64ValuesWithFirstEmptyNoSpace::");
    lines.add("multipleBase64ValuesWithFirstEmptyNoSpace::Zm9v");
    lines.add("multipleBase64ValuesWithSecondEmptyNoSpace::Zm9v");
    lines.add("multipleBase64ValuesWithSecondEmptyNoSpace::");

    for (int i=0; i < 1000; i++)
    {
      lines.add("member: uid=user." + i + ",ou=People,dc=example,dc=com");
    }

    String[] lineArray = new String[lines.size()];
    lines.toArray(lineArray);

    Entry e = LDIFReader.decodeEntry(lineArray);

    assertNotNull(e);

    assertTrue(e.hasAttribute("singleValueFromFile"));
    assertEquals(e.getAttribute("singleValueFromFile").size(), 1);

    assertTrue(e.hasAttribute("multipleValuesFromFile"));
    assertEquals(e.getAttribute("multipleValuesFromFile").size(), 2);

    assertTrue(e.hasAttribute("member"));
    assertEquals(e.getAttribute("member").size(), 1000);

    dataFile1.delete();
    dataFile2.delete();
  }



  /**
   * Retrieves an entry full of special cases for LDIF processing.
   *
   * @return  An entry with special cases for LDIF processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static Entry getSpecialCaseEntry()
          throws Exception
  {
    Entry e = new Entry(
         "dn: cn=Special Case Entry,dc=example,dc=com",
         "objectClass: top",
         "objectClass: untypedObject",
         "objectClass: extensibleObject",
         "cn: Special Case Entry");

    e.addAttribute("valueStartsWithSpace", " starts with space");
    e.addAttribute("valueStartsWithColon", ":starts with colon");
    e.addAttribute("valueStartsWithLessThan", "<starts with less than");
    e.addAttribute("valueEndsWithSpace", "ends with a space ");
    e.addAttribute("nonASCIICharacters", "Jos\u00e9 Jalape\u00f1o");
    e.addAttribute("valueContainsNUL", new byte[] { 'H', 'i', 0x00 });
    e.addAttribute("valueContainsLF", new byte[] { 'H', 'i', 0x0A });
    e.addAttribute("valueContainsCR", new byte[] { 'H', 'i', 0x0D });
    e.addAttribute("multiple", "<Jos\u00e9\u0000Jalape\u00f1o\r\n");
    e.addAttribute("onlyEmptyValue", "");
    e.addAttribute("multipleValuesWithFirstEmpty", "", "notEmpty");
    e.addAttribute("multipleValuesWithSecondEmpty", "notEmpty", "");
    e.addAttribute("multipleValuesWithBase64", "Jos\u00e9");
    e.addAttribute("multipleValuesWithBase64", "Jos\u00e9\tJalape\u00f1o");

    return e;
  }



  /**
   * Performs an encoding and decoding test with an entry full of special cases.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEncodeAndDecodeSpecialCaseWithToLDIF()
          throws Exception
  {
    Entry e = getSpecialCaseEntry();
    String[] ldifLines = e.toLDIF();
    Entry e2 = LDIFReader.decodeEntry(ldifLines);
    assertEquals(e, e2);
  }



  /**
   * Performs an encoding and decoding test with an entry full of special cases.
   *
   * @param  wrapColumn  The column at which to wrap long lines.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testWrapColumns")
  public void testEncodeAndDecodeSpecialCaseWithToLDIF(int wrapColumn)
          throws Exception
  {
    Entry e = getSpecialCaseEntry();
    String[] ldifLines = e.toLDIF(wrapColumn);
    Entry e2 = LDIFReader.decodeEntry(ldifLines);
    assertEquals(e, e2);
  }



  /**
   * Performs an encoding and decoding test with an entry full of special cases.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEncodeAndDecodeSpecialCaseWithToLDIFByteBuffer()
          throws Exception
  {
    Entry e = getSpecialCaseEntry();
    ByteStringBuffer buffer = new ByteStringBuffer();
    e.toLDIF(buffer);
    String[] ldifLines = stringToLines(buffer.toString());
    Entry e2 = LDIFReader.decodeEntry(ldifLines);
    assertEquals(e, e2);
  }



  /**
   * Performs an encoding and decoding test with an entry full of special cases.
   *
   * @param  wrapColumn  The column at which to wrap long lines.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testWrapColumns")
  public void testEncodeAndDecodeSpecialCaseWithToLDIFByteBuffer(int wrapColumn)
          throws Exception
  {
    Entry e = getSpecialCaseEntry();
    ByteStringBuffer buffer = new ByteStringBuffer();
    e.toLDIF(buffer, wrapColumn);
    String[] ldifLines = stringToLines(buffer.toString());
    Entry e2 = LDIFReader.decodeEntry(ldifLines);
    assertEquals(e, e2);
  }



  /**
   * Performs an encoding and decoding test with an entry full of special cases.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEncodeAndDecodeSpecialCaseWithToLDIFStringBuffer()
          throws Exception
  {
    Entry e = getSpecialCaseEntry();
    StringBuilder buffer = new StringBuilder();
    e.toLDIFString(buffer);
    String[] ldifLines = stringToLines(buffer.toString());
    Entry e2 = LDIFReader.decodeEntry(ldifLines);
    assertEquals(e, e2);
  }



  /**
   * Performs an encoding and decoding test with an entry full of special cases.
   *
   * @param  wrapColumn  The column at which to wrap long lines.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testWrapColumns")
  public void testEncodeAndDecodeSpecialCaseWithToLDIFStringBuffer(
                   int wrapColumn)
          throws Exception
  {
    Entry e = getSpecialCaseEntry();
    StringBuilder buffer = new StringBuilder();
    e.toLDIFString(buffer, wrapColumn);
    String[] ldifLines = stringToLines(buffer.toString());
    Entry e2 = LDIFReader.decodeEntry(ldifLines);
    assertEquals(e, e2);
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with a duplicate value
   * when that value is empty and ignoring duplicate values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryDuplicateEmptyValueWithIgnore()
         throws Exception
  {
    LDIFReader.decodeEntry(true, null,
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description:",
         "description:");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with a duplicate value
   * when that value is empty and not ignoring duplicate values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeEntryDuplicateEmptyValueWithoutIgnore()
         throws Exception
  {
    LDIFReader.decodeEntry(false, null,
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description:",
         "description:");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with a duplicate value
   * when that value is non-empty and ignoring duplicate values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryDuplicateNonEmptyValueWithIgnore()
         throws Exception
  {
    LDIFReader.decodeEntry(true, null,
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: duplicate",
         "description: duplicate");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with a duplicate value
   * when that value is non-empty and not ignoring duplicate values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeEntryDuplicateNonEmptyValueWithoutIgnore()
         throws Exception
  {
    LDIFReader.decodeEntry(false, null,
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: duplicate",
         "description: duplicate");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with a duplicate value
   * when that value is non-empty and base64-encoded and ignoring duplicate
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryDuplicateNonEmptyBase64ValueWithIgnore()
         throws Exception
  {
    LDIFReader.decodeEntry(true, null,
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description:: Zm9v",
         "description:: Zm9v");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with a duplicate value
   * when that value is non-empty and base64-encoded and not ignoring duplicate
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeEntryDuplicateNonEmptyBase64ValueWithoutIgnore()
         throws Exception
  {
    LDIFReader.decodeEntry(false, null,
                           "dn: dc=example,dc=com",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example",
                           "description:: Zm9v",
                           "description:: Zm9v");
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with a duplicate value
   * when that value is non-empty and read from a file and ignoring duplicate
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryDuplicateNonEmptyValueReadFromFileWithIgnore()
         throws Exception
  {
    File dataFile1 = createTempFile();
    FileWriter w = new FileWriter(dataFile1);
    w.write("foo");
    w.close();

    StringBuilder fileURL = new StringBuilder();
    fileURL.append("file://");
    appendPathComponentsToURL(dataFile1, fileURL);

    LDIFReader.decodeEntry(true, null,
                           "dn: dc=example,dc=com",
                           "objectClass: top",
                           "objectClass: domain",
                           "dc: example",
                           "description:< " + fileURL,
                           "description:< " + fileURL);
  }



  /**
   * Tests the {@code decodeEntry} method with an entry with a duplicate value
   * when that value is non-empty and read from a file and not ignoring
   * duplicate values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeEntryDuplicateNonEmptyValueReadFromFileWithoutIgnore()
         throws Exception
  {
    File dataFile1 = createTempFile();
    FileWriter w = new FileWriter(dataFile1);
    w.write("foo");
    w.close();

    StringBuilder fileURL = new StringBuilder();
    fileURL.append("file://");
    appendPathComponentsToURL(dataFile1, fileURL);

    LDIFReader.decodeEntry(false, null,
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description:< " + fileURL,
         "description:< " + fileURL);
  }



  /**
   * Tests the {@code LDIFReader.rethrow} method with a {@code null} throwable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReaderRethrowNull()
         throws Exception
  {
    LDIFReader.rethrow(null);
  }



  /**
   * Tests the {@code LDIFReader.rethrow} method with an {@code IOException}
   * throwable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testReaderRethrowIOException()
         throws Exception
  {
    LDIFReader.rethrow(new IOException());
  }



  /**
   * Tests the {@code LDIFReader.rethrow} method with an {@code LDIFException}
   * throwable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testReaderRethrowLDIFException()
         throws Exception
  {
    LDIFReader.rethrow(new LDIFException("foo", 1L, true));
  }



  /**
   * Tests the {@code LDIFReader.rethrow} method with a {@code RuntimeException}
   * throwable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { RuntimeException.class })
  public void testReaderRethrowRuntimeException()
         throws Exception
  {
    LDIFReader.rethrow(new RuntimeException());
  }



  /**
   * Tests the {@code LDIFReader.rethrow} method with an {@code Error}
   * throwable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { Error.class })
  public void testReaderRethrowError()
         throws Exception
  {
    LDIFReader.rethrow(new Error());
  }



  /**
   * Tests the {@code LDIFReader.rethrow} method with a checked
   * {@code Exception} throwable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testReaderRethrowCheckedException()
         throws Exception
  {
    LDIFReader.rethrow(new Exception());
  }



  /**
   * Tests the {@code LDIFWriter.rethrow} method with an {@code IOException}
   * throwable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testWriterRethrowIOException()
         throws Exception
  {
    LDIFWriter.rethrow(new IOException());
  }



  /**
   * Tests the {@code LDIFWriter.rethrow} method with a {@code RuntimeException}
   * throwable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { RuntimeException.class })
  public void testWriterRethrowRuntimeException()
         throws Exception
  {
    LDIFWriter.rethrow(new RuntimeException());
  }



  /**
   * Tests the {@code LDIFWriter.rethrow} method with an {@code Error}
   * throwable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { Error.class })
  public void testWriterRethrowError()
         throws Exception
  {
    LDIFWriter.rethrow(new Error());
  }



  /**
   * Tests the {@code LDIFWriter.rethrow} method with a checked
   * {@code Exception} throwable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testWriterRethrowCheckedException()
         throws Exception
  {
    LDIFWriter.rethrow(new Exception());
  }



  /**
   * Converts the provided string to an array of lines.
   *
   * @param  s  The string to convert to an array of lines.
   *
   * @return  The array of lines to be decoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static String[] stringToLines(String s)
          throws Exception
  {
    ArrayList<String> lineList = new ArrayList<String>();
    StringTokenizer tokenizer = new StringTokenizer(s, "\r\n");
    while (tokenizer.hasMoreTokens())
    {
      lineList.add(tokenizer.nextToken());
    }

    String[] array = new String[lineList.size()];
    return lineList.toArray(array);
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering records containing a single trailing space in the DN line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testSingleTrailingSpaceInDN()
         throws Exception
  {
    // Test an entry with a single trailing space in the DN.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in dn,dc=example,dc=com ",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: trailing space in dn");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readEntry();
      fail("Expected an exception for an entry with a single trailing space " +
           "in the DN.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final Entry entry = reader.readEntry();
    assertEquals(entry, new Entry(
         "dn: ou=trailing space in dn,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: trailing space in dn"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering records containing multiple trailing spaces in the DN line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testMultipleTrailingSpacesInDN()
         throws Exception
  {
    // Test an entry with multiple trailing spaces in the DN.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in dn,dc=example,dc=com      ",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: trailing space in dn");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readEntry();
      fail("Expected an exception for an entry with multiple trailing spaces " +
           "in the DN.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final Entry entry = reader.readEntry();
    assertEquals(entry, new Entry(
         "dn: ou=trailing space in dn,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: trailing space in dn"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering records containing a single trailing space in the first
   * attribute line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testSingleTrailingSpaceFirstAttr()
         throws Exception
  {
    // Test an entry with a single trailing space in the first attribute line.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in first attr,dc=example,dc=com",
         "objectClass: top ",
         "objectClass: organizationalUnit",
         "ou: trailing space in first attr");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readEntry();
      fail("Expected an exception for an entry with a single trailing space " +
           "in the first attribute.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final Entry entry = reader.readEntry();
    assertEquals(entry, new Entry(
         "dn: ou=trailing space in first attr,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: trailing space in first attr"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering records containing multiple trailing spaces in the first
   * attribute line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testMultipleTrailingSpacesFirstAttr()
         throws Exception
  {
    // Test an entry with multiple trailing spaces in the first attribute line.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in first attr,dc=example,dc=com",
         "objectClass: top      ",
         "objectClass: organizationalUnit",
         "ou: trailing space in first attr");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readEntry();
      fail("Expected an exception for an entry with multiple trailing spaces " +
           "in the first attribute.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final Entry entry = reader.readEntry();
    assertEquals(entry, new Entry(
         "dn: ou=trailing space in first attr,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: trailing space in first attr"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering records containing a single trailing space in the middle
   * attribute line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testSingleTrailingSpaceMiddleAttr()
         throws Exception
  {
    // Test an entry with a single trailing space in the second attribute line.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in middle attr,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit ",
         "ou: trailing space in middle attr");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readEntry();
      fail("Expected an exception for an entry with a single trailing space " +
           "in the middle attribute.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final Entry entry = reader.readEntry();
    assertEquals(entry, new Entry(
         "dn: ou=trailing space in middle attr,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: trailing space in middle attr"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering records containing multiple trailing spaces in the middle
   * attribute line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testMultipleTrailingSpacesMiddleAttr()
         throws Exception
  {
    // Test an entry with multiple trailing spaces in the second attribute line.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in middle attr,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit      ",
         "ou: trailing space in middle attr");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readEntry();
      fail("Expected an exception for an entry with multiple trailing spaces " +
           "in the middle attribute.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final Entry entry = reader.readEntry();
    assertEquals(entry, new Entry(
         "dn: ou=trailing space in middle attr,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: trailing space in middle attr"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering records containing a single trailing space in the last
   * attribute line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testSingleTrailingSpaceLastAttr()
         throws Exception
  {
    // Test an entry with a single trailing space in the last attribute line.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in last attr,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: trailing space in last attr ");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readEntry();
      fail("Expected an exception for an entry with a single trailing space " +
           "in the last attribute.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final Entry entry = reader.readEntry();
    assertEquals(entry, new Entry(
         "dn: ou=trailing space in last attr,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: trailing space in last attr"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering records containing multiple trailing spaces in the last
   * attribute line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testMultipleTrailingSpacesLastAttr()
         throws Exception
  {
    // Test an entry with multiple trailing spaces in the last attribute line.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in last attr,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: trailing space in last attr      ");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readEntry();
      fail("Expected an exception for an entry with multiple trailing spaces " +
           "in the last attribute.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final Entry entry = reader.readEntry();
    assertEquals(entry, new Entry(
         "dn: ou=trailing space in last attr,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: trailing space in last attr"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering records containing a line with base64-encoded data where the
   * base64-encoded data ends with a space, but there is no space after the
   * base64-encoded value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testBase64EndsWithSpace()
         throws Exception
  {
    // Test an entry with a base64-encoded value that contains an embedded space
    // but is not followed by any illegal trailing spaces.
    final File ldifFile = createTempFile(
         "dn: ou=base64 ends with space,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: base64 ends with space",
         "description:: ZW5kcyB3aXRoIGEgc3BhY2Ug");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    Entry entry = reader.readEntry();
    assertEquals(entry, new Entry(
         "dn: ou=base64 ends with space,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: base64 ends with space",
         "description:: ZW5kcyB3aXRoIGEgc3BhY2Ug"));
    reader.close();

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    entry = reader.readEntry();
    assertEquals(entry, new Entry(
         "dn: ou=base64 ends with space,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: base64 ends with space",
         "description:: ZW5kcyB3aXRoIGEgc3BhY2Ug"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering records containing a line with base64-encoded data where the
   * base64-encoded data does not end with a space, but there is a trailing
   * space after the base64-encoded value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testSpaceAfterBase64WithoutSpace()
         throws Exception
  {
    // Test an entry with a base64-encoded value that contains a base64-encoded
    // value that does not contain an embedded space but is followed by an
    // illegal trailing space.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space after base64 without space,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: trailing space after base64 without space",
         "description:: ZG9lcyBub3QgZW5kIHdpdGggYSBzcGFjZQ== ");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readEntry();
      fail("Expected an exception for an entry with a trailing space after a " +
           "base64-encoded value that does not end with a space.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final Entry entry = reader.readEntry();
    assertEquals(entry, new Entry(
         "dn: ou=trailing space after base64 without space,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: trailing space after base64 without space",
         "description: does not end with a space"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering records containing a line with base64-encoded data where the
   * base64-encoded data ends with a space, and there is also a trailing space
   * after the base64-encoded value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testSpaceAfterBase64WithSpace()
         throws Exception
  {
    // Test an entry with a base64-encoded value that contains a base64-encoded
    // value that has an embedded space and is also followed by an illegal
    // trailing space.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space after base64 with space,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: trailing space after base64 with space",
         "description:: ZW5kcyB3aXRoIGEgc3BhY2Ug ");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readEntry();
      fail("Expected an exception for an entry with a trailing space after a " +
           "base64-encoded value ending with a space.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final Entry entry = reader.readEntry();
    assertEquals(entry, new Entry(
         "dn: ou=trailing space after base64 with space,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: trailing space after base64 with space",
         "description:: ZW5kcyB3aXRoIGEgc3BhY2Ug"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering add change records with a trailing space in the DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testTrailingSpaceInAddChangeRecordDN()
         throws Exception
  {
    // Test an add change record with a trailing space in the DN.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in dn,dc=example,dc=com ",
         "changeType: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: trailing space in dn");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readChangeRecord();
      fail("Expected an exception for an add change record with a single " +
           "trailing space in the DN.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final LDIFAddChangeRecord addChangeRecord =
         (LDIFAddChangeRecord) reader.readChangeRecord();
    assertEquals(addChangeRecord, LDIFReader.decodeChangeRecord(
         "dn: ou=trailing space in dn,dc=example,dc=com",
         "changeType: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: trailing space in dn"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering add change records with a trailing space in the changeType
   * line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testTrailingSpaceInAddChangeRecordChangeType()
         throws Exception
  {
    // Test an add change record with a trailing space in the changeType.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in changeType,dc=example,dc=com",
         "changeType: add ",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: trailing space in changeType");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readChangeRecord();
      fail("Expected an exception for an add change record with a single " +
           "trailing space in the changeType.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final LDIFAddChangeRecord addChangeRecord =
         (LDIFAddChangeRecord) reader.readChangeRecord();
    assertEquals(addChangeRecord, LDIFReader.decodeChangeRecord(
         "dn: ou=trailing space in changeType,dc=example,dc=com",
         "changeType: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: trailing space in changeType"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering add change records with a trailing space in an attribute line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testTrailingSpaceInAddChangeRecordAttribute()
         throws Exception
  {
    // Test an add change record with a trailing space in an attribute.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in attribute,dc=example,dc=com",
         "changeType: add",
         "objectClass: top",
         "objectClass: organizationalUnit ",
         "ou: trailing space in attribute");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readChangeRecord();
      fail("Expected an exception for an add change record with a single " +
           "trailing space in an attribute line.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final LDIFAddChangeRecord addChangeRecord =
         (LDIFAddChangeRecord) reader.readChangeRecord();
    assertEquals(addChangeRecord, LDIFReader.decodeChangeRecord(
         "dn: ou=trailing space in attribute,dc=example,dc=com",
         "changeType: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: trailing space in attribute"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering delete change records with a trailing space in the DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testTrailingSpaceInDeleteChangeRecordDN()
         throws Exception
  {
    // Test a delete change record with a trailing space in the DN.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in dn,dc=example,dc=com ",
         "changeType: delete");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readChangeRecord();
      fail("Expected an exception for a delete change record with a single " +
           "trailing space in the DN.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final LDIFDeleteChangeRecord deleteChangeRecord =
         (LDIFDeleteChangeRecord) reader.readChangeRecord();
    assertEquals(deleteChangeRecord, LDIFReader.decodeChangeRecord(
         "dn: ou=trailing space in dn,dc=example,dc=com",
         "changeType: delete"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering delete change records with a trailing space in the change
   * type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testTrailingSpaceInDeleteChangeRecordChangeType()
         throws Exception
  {
    // Test a delete change record with a trailing space in the changeType.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in changeType,dc=example,dc=com",
         "changeType: delete ");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readChangeRecord();
      fail("Expected an exception for a delete change record with a single " +
           "trailing space in the changeType.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final LDIFDeleteChangeRecord deleteChangeRecord =
         (LDIFDeleteChangeRecord) reader.readChangeRecord();
    assertEquals(deleteChangeRecord, LDIFReader.decodeChangeRecord(
         "dn: ou=trailing space in changeType,dc=example,dc=com",
         "changeType: delete"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering modify change records with a trailing space in the DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testTrailingSpaceInModifyChangeRecordDN()
         throws Exception
  {
    // Test a modify change record with a trailing space in the DN.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in dn,dc=example,dc=com ",
         "changeType: modify",
         "replace: a",
         "a: value1",
         "a: value2",
         "-",
         "replace: b",
         "b: value1",
         "b: value2");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readChangeRecord();
      fail("Expected an exception for a modify change record with a single " +
           "trailing space in the DN.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final LDIFModifyChangeRecord modifyChangeRecord =
         (LDIFModifyChangeRecord) reader.readChangeRecord();
    assertEquals(modifyChangeRecord, LDIFReader.decodeChangeRecord(
         "dn: ou=trailing space in dn,dc=example,dc=com",
         "changeType: modify",
         "replace: a",
         "a: value1",
         "a: value2",
         "-",
         "replace: b",
         "b: value1",
         "b: value2"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering modify change records with a trailing space in the changeType.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testTrailingSpaceInModifyChangeRecordChangeType()
         throws Exception
  {
    // Test a modify change record with a trailing space in the changeType.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in changeType,dc=example,dc=com",
         "changeType: modify ",
         "replace: a",
         "a: value1",
         "a: value2",
         "-",
         "replace: b",
         "b: value1",
         "b: value2");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readChangeRecord();
      fail("Expected an exception for a modify change record with a single " +
           "trailing space in the changeType.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final LDIFModifyChangeRecord modifyChangeRecord =
         (LDIFModifyChangeRecord) reader.readChangeRecord();
    assertEquals(modifyChangeRecord, LDIFReader.decodeChangeRecord(
         "dn: ou=trailing space in changeType,dc=example,dc=com",
         "changeType: modify",
         "replace: a",
         "a: value1",
         "a: value2",
         "-",
         "replace: b",
         "b: value1",
         "b: value2"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering modify change records with a trailing space after the
   * modification type for the first attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testTrailingSpaceInModifyChangeRecordChangeAttr1ModType()
         throws Exception
  {
    // Test a modify change record with a trailing space in the modification
    // type for the first attribute.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in attr 1 mod type,dc=example,dc=com",
         "changeType: modify",
         "replace: a ",
         "a: value1",
         "a: value2",
         "-",
         "replace: b",
         "b: value1",
         "b: value2");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readChangeRecord();
      fail("Expected an exception for a modify change record with a single " +
           "trailing space in the first attribute modification type.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final LDIFModifyChangeRecord modifyChangeRecord =
         (LDIFModifyChangeRecord) reader.readChangeRecord();
    assertEquals(modifyChangeRecord, LDIFReader.decodeChangeRecord(
         "dn: ou=trailing space in attr 1 mod type,dc=example,dc=com",
         "changeType: modify",
         "replace: a",
         "a: value1",
         "a: value2",
         "-",
         "replace: b",
         "b: value1",
         "b: value2"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering modify change records with a trailing space after the first
   * value for the first attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testTrailingSpaceInModifyChangeRecordChangeAttr1Value1()
         throws Exception
  {
    // Test a modify change record with a trailing space in the first value for
    // the first attribute.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in attr 1 value 1,dc=example,dc=com",
         "changeType: modify",
         "replace: a",
         "a: value1 ",
         "a: value2",
         "-",
         "replace: b",
         "b: value1",
         "b: value2");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readChangeRecord();
      fail("Expected an exception for a modify change record with a single " +
           "trailing space in the first value for the first attribute.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final LDIFModifyChangeRecord modifyChangeRecord =
         (LDIFModifyChangeRecord) reader.readChangeRecord();
    assertEquals(modifyChangeRecord, LDIFReader.decodeChangeRecord(
         "dn: ou=trailing space in attr 1 value 1,dc=example,dc=com",
         "changeType: modify",
         "replace: a",
         "a: value1",
         "a: value2",
         "-",
         "replace: b",
         "b: value1",
         "b: value2"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering modify change records with a trailing space after the second
   * value for the first attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testTrailingSpaceInModifyChangeRecordChangeAttr1Value2()
         throws Exception
  {
    // Test a modify change record with a trailing space in the second value for
    // the first attribute.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in attr 1 value 2,dc=example,dc=com",
         "changeType: modify",
         "replace: a",
         "a: value1",
         "a: value2 ",
         "-",
         "replace: b",
         "b: value1",
         "b: value2");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readChangeRecord();
      fail("Expected an exception for a modify change record with a single " +
           "trailing space in the second value for the first attribute.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final LDIFModifyChangeRecord modifyChangeRecord =
         (LDIFModifyChangeRecord) reader.readChangeRecord();
    assertEquals(modifyChangeRecord, LDIFReader.decodeChangeRecord(
         "dn: ou=trailing space in attr 1 value 2,dc=example,dc=com",
         "changeType: modify",
         "replace: a",
         "a: value1",
         "a: value2",
         "-",
         "replace: b",
         "b: value1",
         "b: value2"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering modify change records with a trailing space after the dash
   * between modifications.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testTrailingSpaceInModifyChangeRecordDash()
         throws Exception
  {
    // Test a modify change record with a trailing space in the dash between
    // modifications.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in dash,dc=example,dc=com",
         "changeType: modify",
         "replace: a",
         "a: value1",
         "a: value2",
         "- ",
         "replace: b",
         "b: value1",
         "b: value2");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readChangeRecord();
      fail("Expected an exception for a modify change record with a single " +
           "trailing space in the dash between modifications.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final LDIFModifyChangeRecord modifyChangeRecord =
         (LDIFModifyChangeRecord) reader.readChangeRecord();
    assertEquals(modifyChangeRecord, LDIFReader.decodeChangeRecord(
         "dn: ou=trailing space in dash,dc=example,dc=com",
         "changeType: modify",
         "replace: a",
         "a: value1",
         "a: value2",
         "-",
         "replace: b",
         "b: value1",
         "b: value2"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering modify change records with a trailing space after the
   * modification type for the second attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testTrailingSpaceInModifyChangeRecordChangeAttr2ModType()
         throws Exception
  {
    // Test a modify change record with a trailing space in the modification
    // type for the second attribute.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in attr 2 mod type,dc=example,dc=com",
         "changeType: modify",
         "replace: a",
         "a: value1",
         "a: value2",
         "-",
         "replace: b ",
         "b: value1",
         "b: value2");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readChangeRecord();
      fail("Expected an exception for a modify change record with a single " +
           "trailing space in the second attribute modification type.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final LDIFModifyChangeRecord modifyChangeRecord =
         (LDIFModifyChangeRecord) reader.readChangeRecord();
    assertEquals(modifyChangeRecord, LDIFReader.decodeChangeRecord(
         "dn: ou=trailing space in attr 2 mod type,dc=example,dc=com",
         "changeType: modify",
         "replace: a",
         "a: value1",
         "a: value2",
         "-",
         "replace: b",
         "b: value1",
         "b: value2"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering modify change records with a trailing space after the first
   * value for the second attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testTrailingSpaceInModifyChangeRecordChangeAttr2Value1()
         throws Exception
  {
    // Test a modify change record with a trailing space in the first value for
    // the second attribute.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in attr 2 value 1,dc=example,dc=com",
         "changeType: modify",
         "replace: a",
         "a: value1",
         "a: value2",
         "-",
         "replace: b",
         "b: value1 ",
         "b: value2");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readChangeRecord();
      fail("Expected an exception for a modify change record with a single " +
           "trailing space in the first value for the second attribute.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final LDIFModifyChangeRecord modifyChangeRecord =
         (LDIFModifyChangeRecord) reader.readChangeRecord();
    assertEquals(modifyChangeRecord, LDIFReader.decodeChangeRecord(
         "dn: ou=trailing space in attr 2 value 1,dc=example,dc=com",
         "changeType: modify",
         "replace: a",
         "a: value1",
         "a: value2",
         "-",
         "replace: b",
         "b: value1",
         "b: value2"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering modify change records with a trailing space after the second
   * value for the second attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testTrailingSpaceInModifyChangeRecordChangeAttr2Value2()
         throws Exception
  {
    // Test a modify change record with a trailing space in the second value for
    // the second attribute.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in attr 2 value 2,dc=example,dc=com",
         "changeType: modify",
         "replace: a",
         "a: value1",
         "a: value2",
         "-",
         "replace: b",
         "b: value1",
         "b: value2 ");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readChangeRecord();
      fail("Expected an exception for a modify change record with a single " +
           "trailing space in the second value for the second attribute.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final LDIFModifyChangeRecord modifyChangeRecord =
         (LDIFModifyChangeRecord) reader.readChangeRecord();
    assertEquals(modifyChangeRecord, LDIFReader.decodeChangeRecord(
         "dn: ou=trailing space in attr 2 value 2,dc=example,dc=com",
         "changeType: modify",
         "replace: a",
         "a: value1",
         "a: value2",
         "-",
         "replace: b",
         "b: value1",
         "b: value2"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering modify DN change records with a trailing space in the DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testTrailingSpaceInModifyDNChangeRecordDN()
         throws Exception
  {
    // Test a modify DN change record with a trailing space in the DN.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in dn,dc=example,dc=com ",
         "changeType: moddn",
         "newRDN: ou=foo",
         "deleteOldRDN: 1",
         "newSuperior: o=example.com");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readChangeRecord();
      fail("Expected an exception for a modify DN change record with a " +
           "single trailing space in the DN.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final LDIFModifyDNChangeRecord modifyDNChangeRecord =
         (LDIFModifyDNChangeRecord) reader.readChangeRecord();
    assertEquals(modifyDNChangeRecord, LDIFReader.decodeChangeRecord(
         "dn: ou=trailing space in dn,dc=example,dc=com",
         "changeType: moddn",
         "newRDN: ou=foo",
         "deleteOldRDN: 1",
         "newSuperior: o=example.com"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering modify DN change records with a trailing space in the
   * changeType.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testTrailingSpaceInModifyDNChangeRecordChangeType()
         throws Exception
  {
    // Test a modify DN change record with a trailing space in the changeType.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in changeType,dc=example,dc=com",
         "changeType: moddn ",
         "newRDN: ou=foo",
         "deleteOldRDN: 1",
         "newSuperior: o=example.com");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readChangeRecord();
      fail("Expected an exception for a modify DN change record with a " +
           "single trailing space in the DN.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final LDIFModifyDNChangeRecord modifyDNChangeRecord =
         (LDIFModifyDNChangeRecord) reader.readChangeRecord();
    assertEquals(modifyDNChangeRecord, LDIFReader.decodeChangeRecord(
         "dn: ou=trailing space in changeType,dc=example,dc=com",
         "changeType: moddn",
         "newRDN: ou=foo",
         "deleteOldRDN: 1",
         "newSuperior: o=example.com"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering modify DN change records with a trailing space in the new RDN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testTrailingSpaceInModifyDNChangeRecordNewRDN()
         throws Exception
  {
    // Test a modify DN change record with a trailing space in the new RDN.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in new rdn,dc=example,dc=com",
         "changeType: moddn",
         "newRDN: ou=foo ",
         "deleteOldRDN: 1",
         "newSuperior: o=example.com");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readChangeRecord();
      fail("Expected an exception for a modify DN change record with a " +
           "single trailing space in the new RDN.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final LDIFModifyDNChangeRecord modifyDNChangeRecord =
         (LDIFModifyDNChangeRecord) reader.readChangeRecord();
    assertEquals(modifyDNChangeRecord, LDIFReader.decodeChangeRecord(
         "dn: ou=trailing space in new rdn,dc=example,dc=com",
         "changeType: moddn",
         "newRDN: ou=foo",
         "deleteOldRDN: 1",
         "newSuperior: o=example.com"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering modify DN change records with a trailing space in the new RDN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testTrailingSpaceInModifyDNChangeRecordDeleteOldRDN()
         throws Exception
  {
    // Test a modify DN change record with a trailing space in the deleteOldRDN
    // flag.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in delete old rdn,dc=example,dc=com",
         "changeType: moddn",
         "newRDN: ou=foo",
         "deleteOldRDN: 1 ",
         "newSuperior: o=example.com");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readChangeRecord();
      fail("Expected an exception for a modify DN change record with a " +
           "single trailing space in the delete old RDN flag.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final LDIFModifyDNChangeRecord modifyDNChangeRecord =
         (LDIFModifyDNChangeRecord) reader.readChangeRecord();
    assertEquals(modifyDNChangeRecord, LDIFReader.decodeChangeRecord(
         "dn: ou=trailing space in delete old rdn,dc=example,dc=com",
         "changeType: moddn",
         "newRDN: ou=foo",
         "deleteOldRDN: 1",
         "newSuperior: o=example.com"));
    reader.close();
  }



  /**
   * Tests to ensure that the LDIF reader exhibits the correct behavior when
   * encountering modify DN change records with a trailing space in the new RDN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testTrailingSpaceInModifyDNChangeRecordNewSuperior()
         throws Exception
  {
    // Test a modify DN change record with a trailing space in the new superior.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in new superior,dc=example,dc=com",
         "changeType: moddn",
         "newRDN: ou=foo",
         "deleteOldRDN: 1",
         "newSuperior: o=example.com ");

    LDIFReader reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(false);
    assertFalse(reader.stripTrailingSpaces());

    try
    {
      reader.readChangeRecord();
      fail("Expected an exception for a modify DN change record with a " +
           "single trailing space in the new superior DN.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    assertFalse(reader.stripTrailingSpaces());
    reader.setStripTrailingSpaces(true);
    assertTrue(reader.stripTrailingSpaces());

    final LDIFModifyDNChangeRecord modifyDNChangeRecord =
         (LDIFModifyDNChangeRecord) reader.readChangeRecord();
    assertEquals(modifyDNChangeRecord, LDIFReader.decodeChangeRecord(
         "dn: ou=trailing space in new superior,dc=example,dc=com",
         "changeType: moddn",
         "newRDN: ou=foo",
         "deleteOldRDN: 1",
         "newSuperior: o=example.com"));
    reader.close();
  }



  /**
   * Tests a number of methods pertaining to the LDIF reader's trailing space
   * behavior.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTrailingSpaceBehavior()
         throws Exception
  {
    // Test an entry with a single trailing space in the first attribute line.
    final File ldifFile = createTempFile(
         "dn: ou=trailing space in first attr,dc=example,dc=com",
         "objectClass: top ",
         "objectClass: organizationalUnit",
         "ou: trailing space in first attr");

    LDIFReader reader = new LDIFReader(ldifFile);

    assertNotNull(reader.getTrailingSpaceBehavior());
    assertEquals(reader.getTrailingSpaceBehavior(),
         TrailingSpaceBehavior.REJECT);

    try
    {
      reader.readEntry();
      fail("Expected an exception for an entry with a single trailing space " +
           "in the first attribute.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
      assertTrue(le.getMessage().contains("trailing space"));
    }
    finally
    {
      reader.close();
    }

    reader = new LDIFReader(ldifFile);
    reader.setTrailingSpaceBehavior(TrailingSpaceBehavior.STRIP);
    assertEquals(reader.getTrailingSpaceBehavior(),
         TrailingSpaceBehavior.STRIP);

    Entry entry = reader.readEntry();
    assertEquals(entry, new Entry(
         "dn: ou=trailing space in first attr,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: trailing space in first attr"));
    reader.close();

    reader = new LDIFReader(ldifFile);
    reader.setTrailingSpaceBehavior(TrailingSpaceBehavior.RETAIN);
    assertEquals(reader.getTrailingSpaceBehavior(),
         TrailingSpaceBehavior.RETAIN);

    entry = reader.readEntry();
    assertEquals(entry, new Entry(
         "dn: ou=trailing space in first attr,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou:: " + Base64.encode("trailing space in first attr ")));
    reader.close();
  }



  /**
   * Tests a number of methods pertaining to the LDIF reader's duplicate value
   * behavior.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDuplicateValueBehavior()
         throws Exception
  {
    // Test an entry with a duplicate object class value.
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "objectClass: domain");


    LDIFReader reader = new LDIFReader(ldifFile);

    assertNotNull(reader.getDuplicateValueBehavior());
    assertEquals(reader.getDuplicateValueBehavior(),
         DuplicateValueBehavior.STRIP);

    Entry entry = reader.readEntry();
    reader.close();

    assertNotNull(entry);
    assertTrue(entry.hasAttribute("objectClass"));
    assertTrue(entry.hasAttributeValue("objectClass", "top"));
    assertTrue(entry.hasAttributeValue("objectClass", "domain"));
    assertEquals(entry.getAttribute("objectClass").size(), 2);


    reader = new LDIFReader(ldifFile);
    reader.setDuplicateValueBehavior(DuplicateValueBehavior.REJECT);
    assertEquals(reader.getDuplicateValueBehavior(),
         DuplicateValueBehavior.REJECT);

    try
    {
      reader.readEntry();
      fail("Expected an exception for an entry with a duplicate value");
    }
    catch (final Exception e)
    {
      // This was expected.
    }
    finally
    {
      reader.close();
    }


    reader = new LDIFReader(ldifFile);
    reader.setDuplicateValueBehavior(DuplicateValueBehavior.RETAIN);
    assertEquals(reader.getDuplicateValueBehavior(),
         DuplicateValueBehavior.RETAIN);

    entry = reader.readEntry();
    reader.close();

    assertNotNull(entry);
    assertTrue(entry.hasAttribute("objectClass"));
    assertTrue(entry.hasAttributeValue("objectClass", "top"));
    assertTrue(entry.hasAttributeValue("objectClass", "domain"));
    assertEquals(entry.getAttribute("objectClass").size(), 3);
  }



  /**
   * Tests the behavior when attempting to read LDIF data when provided with an
   * empty file array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testReadFileArrayEmpty()
         throws Exception
  {
    new LDIFReader(new File[0], 0, null);
  }



  /**
   * Tests the behavior when attempting to read LDIF data when provided with an
   * array containing a single file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadFileArraySingle()
         throws Exception
  {
    final File f1 = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "",
         "dn: uid=test.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.1",
         "givenName: Test",
         "sn: 1",
         "cn: Test 1",
         "userPassword: password",
         "",
         "dn: uid=test.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.2",
         "givenName: Test",
         "sn: 2",
         "cn: Test 2",
         "userPassword: password",
         "",
         "dn: uid=test.3,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.3",
         "givenName: Test",
         "sn: 3",
         "cn: Test 3",
         "userPassword: password",
         "",
         "dn: uid=test.4,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.4",
         "givenName: Test",
         "sn: 4",
         "cn: Test 4",
         "userPassword: password",
         "",
         "dn: uid=test.5,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.5",
         "givenName: Test",
         "sn: 5",
         "cn: Test 5",
         "userPassword: password");

    final LDIFReader ldifReader = new LDIFReader(new File[] { f1 }, 0, null);

    Entry e = ldifReader.readEntry();
    assertNotNull(e);
    assertEquals(e.getParsedDN(), new DN("dc=example,dc=com"));
    assertFalse(e.hasAttribute("description"));

    e = ldifReader.readEntry();
    assertNotNull(e);
    assertEquals(e.getParsedDN(), new DN("ou=People,dc=example,dc=com"));
    assertFalse(e.hasAttribute("description"));

    e = ldifReader.readEntry();
    assertNotNull(e);
    assertEquals(e.getParsedDN(),
         new DN("uid=test.1,ou=People,dc=example,dc=com"));
    assertFalse(e.hasAttribute("description"));

    e = ldifReader.readEntry();
    assertNotNull(e);
    assertEquals(e.getParsedDN(),
         new DN("uid=test.2,ou=People,dc=example,dc=com"));
    assertFalse(e.hasAttribute("description"));

    e = ldifReader.readEntry();
    assertNotNull(e);
    assertEquals(e.getParsedDN(),
         new DN("uid=test.3,ou=People,dc=example,dc=com"));
    assertFalse(e.hasAttribute("description"));

    e = ldifReader.readEntry();
    assertNotNull(e);
    assertEquals(e.getParsedDN(),
         new DN("uid=test.4,ou=People,dc=example,dc=com"));
    assertFalse(e.hasAttribute("description"));

    e = ldifReader.readEntry();
    assertNotNull(e);
    assertEquals(e.getParsedDN(),
         new DN("uid=test.5,ou=People,dc=example,dc=com"));
    assertFalse(e.hasAttribute("description"));

    e = ldifReader.readEntry();
    assertNull(e);

    ldifReader.close();
  }



  /**
   * Tests the behavior when attempting to read LDIF data when provided with an
   * array containing multiple files.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadFileArrayMultiple()
         throws Exception
  {
    final File f1 = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "",
         "dn: uid=test.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.1",
         "givenName: Test",
         "sn: 1",
         "cn: Test 1",
         "userPassword: password");

    final File f2 = createTempFile(
         "dn: uid=test.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.2",
         "givenName: Test",
         "sn: 2",
         "cn: Test 2",
         "userPassword: password",
         "",
         "dn: uid=test.3,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.3",
         "givenName: Test",
         "sn: 3",
         "cn: Test 3",
         "userPassword: password",
         "",
         "dn: uid=test.4,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.4",
         "givenName: Test",
         "sn: 4",
         "cn: Test 4",
         "userPassword: password");

    final File f3 = createTempFile(
         "dn: uid=test.5,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.5",
         "givenName: Test",
         "sn: 5",
         "cn: Test 5",
         "userPassword: password");

    final LDIFReader ldifReader =
         new LDIFReader(new File[] { f1, f2, f3}, 0, this);

    Entry e = ldifReader.readEntry();
    assertNotNull(e);
    assertEquals(e.getParsedDN(), new DN("dc=example,dc=com"));
    assertTrue(e.hasAttributeValue("description", "replacedOnRead"));

    e = ldifReader.readEntry();
    assertNotNull(e);
    assertEquals(e.getParsedDN(), new DN("ou=People,dc=example,dc=com"));
    assertTrue(e.hasAttributeValue("description", "replacedOnRead"));

    e = ldifReader.readEntry();
    assertNotNull(e);
    assertEquals(e.getParsedDN(),
         new DN("uid=test.1,ou=People,dc=example,dc=com"));
    assertTrue(e.hasAttributeValue("description", "replacedOnRead"));

    e = ldifReader.readEntry();
    assertNotNull(e);
    assertEquals(e.getParsedDN(),
         new DN("uid=test.2,ou=People,dc=example,dc=com"));
    assertTrue(e.hasAttributeValue("description", "replacedOnRead"));

    e = ldifReader.readEntry();
    assertNotNull(e);
    assertEquals(e.getParsedDN(),
         new DN("uid=test.3,ou=People,dc=example,dc=com"));
    assertTrue(e.hasAttributeValue("description", "replacedOnRead"));

    e = ldifReader.readEntry();
    assertNotNull(e);
    assertEquals(e.getParsedDN(),
         new DN("uid=test.4,ou=People,dc=example,dc=com"));
    assertTrue(e.hasAttributeValue("description", "replacedOnRead"));

    e = ldifReader.readEntry();
    assertNotNull(e);
    assertEquals(e.getParsedDN(),
         new DN("uid=test.5,ou=People,dc=example,dc=com"));
    assertTrue(e.hasAttributeValue("description", "replacedOnRead"));

    e = ldifReader.readEntry();
    assertNull(e);

    ldifReader.close();
  }



  /**
   * Provides test coverage for the static {@code readEntries} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadEntries()
         throws Exception
  {
    final File f = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User");

    final List<Entry> fromPath = LDIFReader.readEntries(f.getAbsolutePath());
    final List<Entry> fromFile = LDIFReader.readEntries(f);
    final List<Entry> fromStream =
         LDIFReader.readEntries(new FileInputStream(f));

    assertNotNull(fromPath);
    assertNotNull(fromFile);
    assertNotNull(fromStream);

    assertEquals(fromPath.size(), 3);

    assertEquals(fromPath.get(0), new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));

    assertEquals(fromPath.get(1), new Entry(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People"));

    assertEquals(fromPath.get(2), new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User"));

    assertEquals(fromPath, fromFile);
    assertEquals(fromPath, fromStream);
  }



  /**
   * Tests the ability to interact with data in files using relative paths.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRelativeFilePaths()
         throws Exception
  {
    final File f = createTempFile();
    final File p = f.getParentFile();
    assertFalse(p.getAbsolutePath().endsWith(File.separator));

    final FileWriter w = new FileWriter(f, false);
    w.write("testRelativeFilePaths");
    w.close();

    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description:< file:" + f.getName());

    final LDIFReader r = new LDIFReader(ldifFile);

    assertNotNull(r.getRelativeBasePath());
    assertTrue(r.getRelativeBasePath().endsWith(File.separator));

    r.setRelativeBasePath(p.getAbsolutePath());
    assertNotNull(r.getRelativeBasePath());
    assertEquals(r.getRelativeBasePath(),
         (p.getAbsolutePath() + File.separator));

    final Entry e = r.readEntry();
    assertNotNull(e);
    assertEquals(e.getAttributeValue("description"), "testRelativeFilePaths");

    r.close();
  }



  /**
   * Tests the behavior when trying to read LDIF data containing a wrapped
   * comment.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadWrappedComment()
         throws Exception
  {
    final File f = createTempFile(
         "# This is a comment that will be wrap",
         " ped across multiple lines",
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final List<Entry> entries = LDIFReader.readEntries(f);
    assertEquals(entries.size(), 1);
    assertEquals(entries.get(0),
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));
  }



  /**
   * Tests the behavior of the LDIF writer when an entry without a comment using
   * a single thread and a translator.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWriteEntryNoCommentUsingTranslatorSingleThreaded()
         throws Exception
  {
    final File ldifFile = createTempFile();
    final LDIFWriter writer =
         new LDIFWriter(new FileOutputStream(ldifFile, false), 1, this);
    writer.writeVersionHeader();
    writer.writeEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));
    writer.close();
    assertTrue(ldifFile.length() > 0L);

    final LDIFReader reader = new LDIFReader(ldifFile);
    final Entry e = reader.readEntry();
    reader.close();

    assertNotNull(e);
    assertEquals(e, new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: replacedOnWrite"));
  }



  /**
   * Tests the behavior of the LDIF writer when an entry with a comment using
   * a single thread and a translator.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWriteEntryWithCommentUsingTranslatorSingleThreaded()
         throws Exception
  {
    final File ldifFile = createTempFile();
    final LDIFWriter writer =
         new LDIFWriter(new FileOutputStream(ldifFile, false), 1, this);
    writer.writeVersionHeader();
    writer.writeEntry(
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"),
         "This is a comment");
    writer.close();
    assertTrue(ldifFile.length() > 0L);

    final LDIFReader reader = new LDIFReader(ldifFile);
    final Entry e = reader.readEntry();
    reader.close();

    assertNotNull(e);
    assertEquals(e, new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: replacedOnWrite"));
  }



  /**
   * Tests the behavior of the LDIF writer when an entry should be suppressed
   * by a translator when using a single-threaded writer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWriteEntrySuppressedNoCommentUsingTranslatorSingleThreaded()
         throws Exception
  {
    final File ldifFile = createTempFile();
    final LDIFWriter writer =
         new LDIFWriter(new FileOutputStream(ldifFile, false), 1, this);
    writer.writeEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: suppress"));
    writer.close();
    assertEquals(ldifFile.length(), 0L);
  }



  /**
   * Tests the behavior of the LDIF writer when an entry without a comment using
   * a single thread and a translator.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWriteRecordNoCommentUsingTranslatorSingleThreaded()
         throws Exception
  {
    final File ldifFile = createTempFile();
    final LDIFWriter writer =
         new LDIFWriter(new FileOutputStream(ldifFile, false), 1, this);
    writer.writeVersionHeader();
    writer.writeLDIFRecord(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));
    writer.close();
    assertTrue(ldifFile.length() > 0L);

    final LDIFReader reader = new LDIFReader(ldifFile);
    final Entry e = reader.readEntry();
    reader.close();

    assertNotNull(e);
    assertEquals(e, new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: replacedOnWrite"));
  }



  /**
   * Tests the behavior of the LDIF writer when an entry with a comment using
   * a single thread and a translator.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWriteRecordWithCommentUsingTranslatorSingleThreaded()
         throws Exception
  {
    final File ldifFile = createTempFile();
    final LDIFWriter writer =
         new LDIFWriter(new FileOutputStream(ldifFile, false), 1, this);
    writer.writeVersionHeader();
    writer.writeLDIFRecord(
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"),
         "This is a comment");
    writer.close();
    assertTrue(ldifFile.length() > 0L);

    final LDIFReader reader = new LDIFReader(ldifFile);
    final Entry e = reader.readEntry();
    reader.close();

    assertNotNull(e);
    assertEquals(e, new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: replacedOnWrite"));
  }



  /**
   * Tests the behavior of the LDIF writer when an entry should be suppressed
   * by a translator when using a single-threaded writer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWriteRecordSuppressedNoCommentUsingTranslatorSingleThreaded()
         throws Exception
  {
    final File ldifFile = createTempFile();
    final LDIFWriter writer =
         new LDIFWriter(new FileOutputStream(ldifFile, false), 1, this);
    writer.writeLDIFRecord(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: suppress"));
    writer.close();
    assertEquals(ldifFile.length(), 0L);
  }



  /**
   * Tests the behavior of the LDIF writer when using multiple threads and a
   * translator.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWriteRecordsUsingTranslatorMultiThreaded()
         throws Exception
  {
    final File ldifFile = createTempFile();

    final List<LDIFRecord> records = Arrays.<LDIFRecord>asList(
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"),
         new Entry(
              "dn: ou=test1,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: test1",
              "description: foo"),
         new Entry(
              "dn: ou=test2,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: test2",
              "description: suppress"));

    final LDIFWriter writer =
         new LDIFWriter(new FileOutputStream(ldifFile, false), 10, this);
    writer.writeVersionHeader();
    writer.writeLDIFRecords(records);
    writer.close();
    assertTrue(ldifFile.length() > 0L);

    final LDIFReader reader = new LDIFReader(ldifFile);

    Entry e = reader.readEntry();
    assertNotNull(e);
    assertEquals(e, new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: replacedOnWrite"));

    e = reader.readEntry();
    assertNotNull(e);
    assertEquals(e, new Entry(
         "dn: ou=test1,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test1",
         "description: replacedOnWrite"));

    e = reader.readEntry();
    assertNull(e);

    reader.close();
  }



  /**
   * Tests the behavior when writing several change records in a single-threaded
   * manner with a translator.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWriteChangeRecordUsingTranslatorSingleThreaded()
         throws Exception
  {
    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final LDIFWriter w = new LDIFWriter(new FileOutputStream(outputFile), 0,
         this, this);

    w.writeChangeRecord(new LDIFAddChangeRecord(new Entry(
         "dn: dc=one,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: one")));

    w.writeChangeRecord(new LDIFAddChangeRecord(new Entry(
         "dn: dc=two,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: two",
         "description: foo")));

    w.writeChangeRecord(new LDIFAddChangeRecord(new Entry(
         "dn: dc=three,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: three",
         "description: suppress")));

    w.writeChangeRecord(new LDIFDeleteChangeRecord("dc=four,dc=com"));

    w.writeChangeRecord(new LDIFModifyChangeRecord(new ModifyRequest(
         "dn: dc=five,dc=com",
         "changetype: modify",
         "add: objectClass",
         "objectClass: extensibleObject")));

    w.writeChangeRecord(new LDIFModifyChangeRecord(new ModifyRequest(
         "dn: dc=six,dc=com",
         "changetype: modify",
         "add: description",
         "description: foo")));

    w.writeChangeRecord(new LDIFModifyChangeRecord(new ModifyRequest(
         "dn: dc=seven,dc=com",
         "changetype: modify",
         "replace: description",
         "description: bar")));

    w.writeChangeRecord(new LDIFModifyChangeRecord(new ModifyRequest(
         "dn: dc=eight,dc=com",
         "changetype: modify",
         "delete: description",
         "description: baz")));

    w.writeChangeRecord(new LDIFModifyChangeRecord(new ModifyRequest(
         "dn: dc=nine,dc=com",
         "changetype: modify",
         "add: description",
         "description: suppress")));

    w.writeChangeRecord(new LDIFModifyChangeRecord(new ModifyRequest(
         "dn: dc=ten,dc=com",
         "changetype: modify",
         "replace: description",
         "description: suppress")));

    w.writeChangeRecord(new LDIFModifyDNChangeRecord(
         "dc=eleven,dc=com", "dc=11", true, null));

    w.close();


    final LDIFReader r = new LDIFReader(outputFile);

    assertEquals(r.readChangeRecord(),
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=one,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: one",
              "description: replacedOnWrite")));

    assertEquals(r.readChangeRecord(),
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=two,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: two",
              "description: replacedOnWrite")));

    assertEquals(r.readChangeRecord(),
         new LDIFDeleteChangeRecord("dc=four,dc=com"));

    assertEquals(r.readChangeRecord(),
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=five,dc=com",
              "changetype: modify",
              "add: objectClass",
              "objectClass: extensibleObject",
              "-",
              "replace: description",
              "description: replacedOnWrite")));

    assertEquals(r.readChangeRecord(),
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=six,dc=com",
              "changetype: modify",
              "add: description",
              "description: replacedOnWrite")));

    assertEquals(r.readChangeRecord(),
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=seven,dc=com",
              "changetype: modify",
              "replace: description",
              "description: replacedOnWrite")));

    assertEquals(r.readChangeRecord(),
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=eight,dc=com",
              "changetype: modify",
              "delete: description",
              "description: baz",
              "-",
              "replace: description",
              "description: replacedOnWrite")));

    assertEquals(r.readChangeRecord(),
         new LDIFModifyDNChangeRecord("dc=eleven,dc=com", "dc=11", true, null));

    assertNull(r.readChangeRecord());

    r.close();
  }



  /**
   * Tests the behavior when writing several change records in a single-threaded
   * manner with a translator.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWriteLDIFRecordUsingTranslatorSingleThreaded()
         throws Exception
  {
    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final LDIFWriter w = new LDIFWriter(new FileOutputStream(outputFile), 0,
         this, this);

    w.writeLDIFRecord(new LDIFAddChangeRecord(new Entry(
         "dn: dc=one,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: one")));

    w.writeLDIFRecord(new LDIFAddChangeRecord(new Entry(
         "dn: dc=two,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: two",
         "description: foo")));

    w.writeLDIFRecord(new LDIFAddChangeRecord(new Entry(
         "dn: dc=three,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: three",
         "description: suppress")));

    w.writeLDIFRecord(new LDIFDeleteChangeRecord("dc=four,dc=com"));

    w.writeLDIFRecord(new LDIFModifyChangeRecord(new ModifyRequest(
         "dn: dc=five,dc=com",
         "changetype: modify",
         "add: objectClass",
         "objectClass: extensibleObject")));

    w.writeLDIFRecord(new LDIFModifyChangeRecord(new ModifyRequest(
         "dn: dc=six,dc=com",
         "changetype: modify",
         "add: description",
         "description: foo")));

    w.writeLDIFRecord(new LDIFModifyChangeRecord(new ModifyRequest(
         "dn: dc=seven,dc=com",
         "changetype: modify",
         "replace: description",
         "description: bar")));

    w.writeLDIFRecord(new LDIFModifyChangeRecord(new ModifyRequest(
         "dn: dc=eight,dc=com",
         "changetype: modify",
         "delete: description",
         "description: baz")));

    w.writeLDIFRecord(new LDIFModifyChangeRecord(new ModifyRequest(
         "dn: dc=nine,dc=com",
         "changetype: modify",
         "add: description",
         "description: suppress")));

    w.writeLDIFRecord(new LDIFModifyChangeRecord(new ModifyRequest(
         "dn: dc=ten,dc=com",
         "changetype: modify",
         "replace: description",
         "description: suppress")));

    w.writeLDIFRecord(new LDIFModifyDNChangeRecord(
         "dc=eleven,dc=com", "dc=11", true, null));

    w.close();


    final LDIFReader r = new LDIFReader(outputFile);

    assertEquals(r.readChangeRecord(),
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=one,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: one",
              "description: replacedOnWrite")));

    assertEquals(r.readChangeRecord(),
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=two,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: two",
              "description: replacedOnWrite")));

    assertEquals(r.readChangeRecord(),
         new LDIFDeleteChangeRecord("dc=four,dc=com"));

    assertEquals(r.readChangeRecord(),
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=five,dc=com",
              "changetype: modify",
              "add: objectClass",
              "objectClass: extensibleObject",
              "-",
              "replace: description",
              "description: replacedOnWrite")));

    assertEquals(r.readChangeRecord(),
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=six,dc=com",
              "changetype: modify",
              "add: description",
              "description: replacedOnWrite")));

    assertEquals(r.readChangeRecord(),
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=seven,dc=com",
              "changetype: modify",
              "replace: description",
              "description: replacedOnWrite")));

    assertEquals(r.readChangeRecord(),
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=eight,dc=com",
              "changetype: modify",
              "delete: description",
              "description: baz",
              "-",
              "replace: description",
              "description: replacedOnWrite")));

    assertEquals(r.readChangeRecord(),
         new LDIFModifyDNChangeRecord("dc=eleven,dc=com", "dc=11", true, null));

    assertNull(r.readChangeRecord());

    r.close();
  }



  /**
   * Tests the behavior when writing several change records in a multithreaded
   * manner with a translator.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWriteLDIFRecordUsingTranslatorMultiThreaded()
         throws Exception
  {
    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final LDIFWriter w = new LDIFWriter(new FileOutputStream(outputFile), 5,
         this, this);

    w.writeLDIFRecords(Arrays.asList(
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=one,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: one")),
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=two,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: two",
              "description: foo")),
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=three,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: three",
              "description: suppress")),
         new LDIFDeleteChangeRecord("dc=four,dc=com"),
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=five,dc=com",
              "changetype: modify",
              "add: objectClass",
              "objectClass: extensibleObject")),
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=six,dc=com",
              "changetype: modify",
              "add: description",
              "description: foo")),
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=seven,dc=com",
              "changetype: modify",
              "replace: description",
              "description: bar")),
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=eight,dc=com",
              "changetype: modify",
              "delete: description",
              "description: baz")),
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=nine,dc=com",
              "changetype: modify",
              "add: description",
              "description: suppress")),
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=ten,dc=com",
              "changetype: modify",
              "replace: description",
              "description: suppress")),
         new LDIFModifyDNChangeRecord(
              "dc=eleven,dc=com", "dc=11", true, null)));

    w.close();


    final LDIFReader r = new LDIFReader(outputFile);

    assertEquals(r.readChangeRecord(),
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=one,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: one",
              "description: replacedOnWrite")));

    assertEquals(r.readChangeRecord(),
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=two,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: two",
              "description: replacedOnWrite")));

    assertEquals(r.readChangeRecord(),
         new LDIFDeleteChangeRecord("dc=four,dc=com"));

    assertEquals(r.readChangeRecord(),
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=five,dc=com",
              "changetype: modify",
              "add: objectClass",
              "objectClass: extensibleObject",
              "-",
              "replace: description",
              "description: replacedOnWrite")));

    assertEquals(r.readChangeRecord(),
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=six,dc=com",
              "changetype: modify",
              "add: description",
              "description: replacedOnWrite")));

    assertEquals(r.readChangeRecord(),
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=seven,dc=com",
              "changetype: modify",
              "replace: description",
              "description: replacedOnWrite")));

    assertEquals(r.readChangeRecord(),
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=eight,dc=com",
              "changetype: modify",
              "delete: description",
              "description: baz",
              "-",
              "replace: description",
              "description: replacedOnWrite")));

    assertEquals(r.readChangeRecord(),
         new LDIFModifyDNChangeRecord("dc=eleven,dc=com", "dc=11", true, null));

    assertNull(r.readChangeRecord());

    r.close();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDIFChangeRecord translate(final LDIFChangeRecord original,
                                    final long firstLineNumber)
       throws LDIFException
  {
    if (original.getDN().contains("suppress"))
    {
      return null;
    }
    else if (original.getDN().contains("throw"))
    {
      throw new LDIFException("Throwing because of the change", firstLineNumber,
           true);
    }

    if (original instanceof LDIFAddChangeRecord)
    {
      final AddRequest addRequest =
           ((LDIFAddChangeRecord) original).toAddRequest();
      addRequest.replaceAttribute("description", "replacedOnRead");
      return new LDIFAddChangeRecord(addRequest);
    }
    else if (original instanceof LDIFModifyChangeRecord)
    {
      final ModifyRequest modifyRequest =
           ((LDIFModifyChangeRecord) original).toModifyRequest();

      boolean updated = false;
      final ArrayList<Modification> modList = new ArrayList<Modification>(
           modifyRequest.getModifications().size() + 1);
      for (final Modification m : modifyRequest.getModifications())
      {
        final Attribute a = m.getAttribute();
        if (a.getName().equalsIgnoreCase("description") && (a.size() > 0) &&
            ((m.getModificationType() == ModificationType.ADD) ||
             (m.getModificationType() == ModificationType.REPLACE)))
        {
          modList.add(new Modification(m.getModificationType(), "description",
               "replacedOnRead"));
          updated = true;
        }
        else
        {
          modList.add(m);
        }
      }

      if (! updated)
      {
        modList.add(new Modification(ModificationType.REPLACE, "description",
             "replacedOnRead"));
      }

      return new LDIFModifyChangeRecord(modifyRequest.getDN(),
           modList);
    }

    return original;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Entry translate(final Entry original, final long firstLineNumber)
         throws LDIFException
  {
    original.setAttribute("description", "replacedOnRead");
    return original;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDIFChangeRecord translateChangeRecordToWrite(
                               final LDIFChangeRecord original)
  {
    if (original instanceof LDIFAddChangeRecord)
    {
      final AddRequest addRequest =
           ((LDIFAddChangeRecord) original).toAddRequest();
      if (addRequest.hasAttributeValue("description", "suppress"))
      {
        return null;
      }
      else
      {
        addRequest.replaceAttribute("description", "replacedOnWrite");
      }
      return new LDIFAddChangeRecord(addRequest);
    }
    else if (original instanceof LDIFModifyChangeRecord)
    {
      final ModifyRequest modifyRequest =
           ((LDIFModifyChangeRecord) original).toModifyRequest();

      boolean updated = false;
      final ArrayList<Modification> modList = new ArrayList<Modification>(
           modifyRequest.getModifications().size()+1);
      for (final Modification m : modifyRequest.getModifications())
      {
        final Attribute a = m.getAttribute();
        if (a.getName().equalsIgnoreCase("description") && (a.size() > 0) &&
            ((m.getModificationType() == ModificationType.ADD) ||
             (m.getModificationType() == ModificationType.REPLACE)))
        {
          if (a.hasValue("suppress"))
          {
            return null;
          }

          modList.add(new Modification(m.getModificationType(), "description",
               "replacedOnWrite"));
          updated = true;
        }
        else
        {
          modList.add(m);
        }
      }

      if (! updated)
      {
        modList.add(new Modification(ModificationType.REPLACE, "description",
             "replacedOnWrite"));
      }

      return new LDIFModifyChangeRecord(modifyRequest.getDN(),
           modList);
    }

    return original;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Entry translateEntryToWrite(final Entry original)
  {
    if (original.hasAttributeValue("description", "suppress"))
    {
      return null;
    }

    original.setAttribute("description", "replacedOnWrite");
    return original;
  }



  /**
   * Tests the {@code decodeEntry} method with a valid LDIF entry that starts
   * with a version header.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEntryWithVersion()
         throws Exception
  {
    LDIFReader.decodeEntry(
         "version: 1",
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
  }



  /**
   * Tests the {@code decodeEntry} method with a version header that isn't
   * followed by a DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeEntryWithVersionNotFollowedByDN()
         throws Exception
  {
    LDIFReader.decodeEntry(
         "version: 1",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a record that starts with
   * a version identifier.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeChangeRecordWithVersion()
         throws Exception
  {
    final LDIFChangeRecord changeRecord =
         LDIFReader.decodeChangeRecord(true, schema, true,
              "version: 1",
              "dn: dc=example,dc=com",
              "changetype: add",
              "objectClass: top",
              "objectClass: domain",
              "dc: example");

    assertTrue(changeRecord instanceof LDIFAddChangeRecord);
  }



  /**
   * Tests the {@code decodeChangeRecord} method with a record that starts with
   * a version identifier.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeChangeRecordWithVersionNotFollowedByDN()
         throws Exception
  {
    LDIFReader.decodeChangeRecord(true, schema, true,
         "version: 1",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
  }



  /**
   * Tests to ensure that values that need to be base64-encoded will have
   * comments with the expected content.
   *
   * @param  valueString             The value string to include in the entry.
   * @param  expectedCommentContent  The expected comment content that is
   *                                 expected to be in the LDIF representation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="base64CommentTestData")
  public void testBase64Comments(final String valueString,
                                 final String expectedCommentContent)
         throws Exception
  {
    final Entry e = new Entry(
         "dc=example,dc=com",
         new Attribute("objectClass", "top", "domain"),
         new Attribute("dc", "example"),
         new Attribute("description", valueString));

    try (ByteArrayOutputStream out = new ByteArrayOutputStream();
         LDIFWriter writer = new LDIFWriter(out))
    {
      writer.setWrapColumn(Integer.MAX_VALUE);

      writer.writeEntry(e);
      writer.flush();

      final String ldifString = StaticUtils.toUTF8String(out.toByteArray());
      assertTrue(ldifString.contains(expectedCommentContent),
           ldifString);
    }
  }



  /**
   * Retrieves data that may be used for testing comments for base64-encoded
   * data.
   *
   * @return  Data that may be used for testing comments for base64-encoded
   *          data.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="base64CommentTestData")
  public Object[][] getBase64CommentTestData()
         throws Exception
  {
    return new Object[][]
    {
      new Object[]
      {
        " a\tb\r\nc d ",
        "{LEADING SPACE}a{TAB}b{LINE FEED}{CARRIAGE RETURN}c d{TRAILING SPACE}"
      },
      new Object[]
      {
        "jalape\\u00F1o",
        "jalape\\u00F1o"
      },
      new Object[]
      {
        "::",
        "{LEADING COLON}:"
      },
      new Object[]
      {
        "<<",
        "{LEADING LESS THAN}<"
      },
      new Object[]
      {
        "{\ud83d\ude00}",
        "{OPENING CURLY BRACE}{GRINNING FACE}{CLOSING CURLY BRACE}"
      },
      new Object[]
      {
        "\ud83d\udeff}",
        "{0xf09f9bbf}"
      },
    };
  }
}
