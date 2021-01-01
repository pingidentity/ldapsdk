/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
package com.unboundid.util.args;



import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.util.UtilTestCase;



/**
 * This class provides test coverage for the FileArgument class.
 */
public class FileArgumentTestCase
       extends UtilTestCase
{
  // A path to a file that we will use for testing purposes.
  private File testFile;



  /**
   * Creates a test file that will be used for test cases in this class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void createTestFile()
         throws Exception
  {
    testFile = createTempFile("line 1",
                              "",
                              "line 3",
                              "",
                              "",
                              "line 6");
  }



  /**
   * Tests the minimal constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalConstructor()
         throws Exception
  {
    FileArgument a = new FileArgument('f', "fileArg", "foo");
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('f'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('f'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "fileArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "fileArg");

    assertEquals(a.getIdentifierString(), "--fileArg");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertFalse(a.fileMustExist());

    assertFalse(a.parentMustExist());

    assertFalse(a.mustBeFile());

    assertFalse(a.mustBeDirectory());

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());

    final ArgumentParser newParser = new ArgumentParser("test", "test");
    newParser.addArgument(a);
    assertNotNull(newParser.getFileArgument(a.getIdentifierString()));

    assertNull(newParser.getFileArgument("--noSuchArgument"));
  }



  /**
   * Tests the first constructor with a valid invocation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Valid()
         throws Exception
  {
    FileArgument a = new FileArgument('f', "fileArg", false, 1, "{path}",
                                      "foo");
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('f'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('f'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "fileArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "fileArg");

    assertEquals(a.getIdentifierString(), "--fileArg");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertFalse(a.fileMustExist());

    assertFalse(a.parentMustExist());

    assertFalse(a.mustBeFile());

    assertFalse(a.mustBeDirectory());

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the second constructor with a valid invocation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Valid()
         throws Exception
  {
    FileArgument a = new FileArgument('f', "fileArg", false, 1, "{path}",
                                      "foo", true, true, true, false);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('f'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('f'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "fileArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "fileArg");

    assertEquals(a.getIdentifierString(), "--fileArg");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertTrue(a.fileMustExist());

    assertTrue(a.parentMustExist());

    assertTrue(a.mustBeFile());

    assertFalse(a.mustBeDirectory());

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the second constructor with conflicting values for the
   * {@code mustBeFile} and {@code mustBeDirectory} arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testConstructor2ConflictingRequirements()
         throws Exception
  {
    new FileArgument('f', "fileArg", false, 1, "{path}", "foo", true, true,
                     true, true);
  }



  /**
   * Tests the third constructor with a {@code null} set of default values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3NullDefaultValues()
         throws Exception
  {
    FileArgument a = new FileArgument('f', "fileArg", false, 1, "{path}",
                                      "foo", true, true, true, false, null);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('f'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('f'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "fileArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "fileArg");

    assertEquals(a.getIdentifierString(), "--fileArg");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertTrue(a.fileMustExist());

    assertTrue(a.parentMustExist());

    assertTrue(a.mustBeFile());

    assertFalse(a.mustBeDirectory());

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the third constructor with an empty set of default values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3EmptyDefaultValues()
         throws Exception
  {
    ArrayList<File> defaultValues = new ArrayList<File>();

    FileArgument a = new FileArgument('f', "fileArg", false, 1, "{path}",
                                      "foo", true, true, true, false,
                                      defaultValues);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('f'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('f'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "fileArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "fileArg");

    assertEquals(a.getIdentifierString(), "--fileArg");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertTrue(a.fileMustExist());

    assertTrue(a.parentMustExist());

    assertTrue(a.mustBeFile());

    assertFalse(a.mustBeDirectory());

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the third constructor with a non-empty set of default values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3NonEmptyDefaultValues()
         throws Exception
  {
    ArrayList<File> defaultValues = new ArrayList<File>();
    defaultValues.add(testFile);

    FileArgument a = new FileArgument('f', "fileArg", false, 1, "{path}",
                                      "foo", true, true, true, false,
                                      defaultValues);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('f'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('f'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "fileArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "fileArg");

    assertEquals(a.getIdentifierString(), "--fileArg");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertTrue(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertTrue(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertTrue(a.fileMustExist());

    assertTrue(a.parentMustExist());

    assertTrue(a.mustBeFile());

    assertFalse(a.mustBeDirectory());

    assertNotNull(a.getDefaultValues());
    assertEquals(a.getDefaultValues().size(), 1);
    assertEquals(a.getDefaultValues().get(0), testFile);

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), testFile);

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), testFile);

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the {@code addValue} method when there are no constraints and no
   * default value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddValueNoConstraintsNoDefault()
         throws Exception
  {
    FileArgument a = new FileArgument('f', "fileArg", false, 1, "{path}",
                                      "foo");
    a = a.getCleanCopy();

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    a.addValue(testFile.getAbsolutePath());

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), testFile);

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), testFile);

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the {@code addValue} method when there are no constraints but there
   * is a default value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddValueNoConstraintsWithDefault()
         throws Exception
  {
    File defaultFile = new File(testFile.getAbsolutePath() + ".default");
    ArrayList<File> defaultValues = new ArrayList<File>();
    defaultValues.add(defaultFile);

    FileArgument a = new FileArgument('f', "fileArg", false, 1, "{path}",
                                      "foo", false, false, false, false,
                                      defaultValues);
    a = a.getCleanCopy();

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), defaultFile);

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), defaultFile);

    a.addValue(testFile.getAbsolutePath());

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), testFile);

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), testFile);

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the {@code addValue} method when the target file must exist and must
   * be a regular file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddValueRegularFileMustExist()
         throws Exception
  {
    FileArgument a = new FileArgument('f', "fileArg", false, 1, "{path}",
                                      "foo", true, true, true, false);
    a = a.getCleanCopy();

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    a.addValue(testFile.getAbsolutePath());

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), testFile);

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), testFile);

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the {@code addValue} method when the target file must exist and must
   * be a directory.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddValueDirectoryMustExist()
         throws Exception
  {
    FileArgument a = new FileArgument('f', "fileArg", false, 1, "{path}",
                                      "foo", true, true, false, true);
    a = a.getCleanCopy();

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    a.addValue(testFile.getParent());

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), testFile.getParentFile());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), testFile.getParentFile());

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the {@code addValue} method when the target file must exist but
   * doesn't.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testAddValueFileDoesNotExist()
         throws Exception
  {
    FileArgument a = new FileArgument('f', "fileArg", false, 1, "{path}",
                                      "foo", true, true, true, false);
    a = a.getCleanCopy();

    a.addValue(testFile.getAbsolutePath() + ".nonexistent");
  }



  /**
   * Tests the {@code addValue} method when the file's parent directory must
   * exist but doesn't.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testAddValueParentDoesNotExist()
         throws Exception
  {
    String path = testFile.getParent() + File.separator + "missingParent" +
                  File.separator + "missingFile";

    FileArgument a = new FileArgument('f', "fileArg", false, 1, "{path}",
                                      "foo", false, true, true, false);
    a = a.getCleanCopy();

    a.addValue(path);
  }



  /**
   * Tests the {@code addValue} method when the target file must exist and must
   * be a file but isn't.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testAddValueFileNotFile()
         throws Exception
  {
    FileArgument a = new FileArgument('f', "fileArg", false, 1, "{path}",
                                      "foo", true, true, true, false);
    a = a.getCleanCopy();

    a.addValue(testFile.getParent());
  }



  /**
   * Tests the {@code addValue} method when the target file must exist and must
   * be a directory but isn't.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testAddValueFileNotDirectory()
         throws Exception
  {
    FileArgument a = new FileArgument('f', "fileArg", false, 1, "{path}",
                                      "foo", true, true, false, true);
    a = a.getCleanCopy();

    a.addValue(testFile.getAbsolutePath());
  }



  /**
   * Tests the {@code addValue} method when the parent exists but isn't a
   * directory.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testAddValueParentNotDirectory()
         throws Exception
  {
    FileArgument a = new FileArgument('f', "fileArg", false, 1, "{path}",
                                      "foo", false, true, true, false);
    a = a.getCleanCopy();

    a.addValue(testFile.getAbsolutePath() + File.separator + "child");
  }



  /**
   * Tests the {@code addValue} method when there are too many values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testAddValueTooManyValues()
         throws Exception
  {
    FileArgument a = new FileArgument('f', "fileArg", false, 1, "{path}",
                                      "foo");
    a = a.getCleanCopy();

    a.addValue(testFile.getAbsolutePath());
    a.addValue(testFile.getParent());
  }



  /**
   * Tests the argument's behavior with an argument value validator.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithArgumentValueValidator()
         throws Exception
  {
    final File tempFile1 = createTempFile();
    final File tempFile2 = createTempFile();

    FileArgument a = new FileArgument('f', "fileArg", false, 1, "{path}",
                                      "foo");
    a.addValueValidator(new TestArgumentValueValidator(
         tempFile1.getAbsolutePath()));

    assertNull(a.getValue());

    try
    {
      a.addValue(tempFile2.getAbsolutePath());
      fail("Expected an exception from an argument value validator.");
    }
    catch (final ArgumentException ae)
    {
      // This was expected
    }

    assertNull(a.getValue());

    a.addValue(tempFile1.getAbsolutePath());

    assertNotNull(a.getValue());
    assertEquals(a.getValue().getCanonicalPath(), tempFile1.getCanonicalPath());
  }



  /**
   * Tests the {@code getFileLines} method on a valid file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetFileLinesValid()
         throws Exception
  {
    FileArgument a = new FileArgument('f', "fileArg", false, 1, "{path}",
                                      "foo");
    a = a.getCleanCopy();

    a.addValue(testFile.getAbsolutePath());

    List<String> fileLines = a.getFileLines();
    assertNotNull(fileLines);
    assertEquals(fileLines.size(), 6);
  }



  /**
   * Tests the {@code getFileLines} method when no value has been set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetFileLinesNoValue()
         throws Exception
  {
    FileArgument a = new FileArgument('f', "fileArg", false, 1, "{path}",
                                      "foo");
    a = a.getCleanCopy();

    assertNull(a.getFileLines());
  }



  /**
   * Tests the {@code getNonBlankFileLines} method on a valid file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetNonBlankFileLinesValid()
         throws Exception
  {
    FileArgument a = new FileArgument('f', "fileArg", false, 1, "{path}",
                                      "foo");
    a = a.getCleanCopy();

    a.addValue(testFile.getAbsolutePath());

    List<String> fileLines = a.getNonBlankFileLines();
    assertNotNull(fileLines);
    assertEquals(fileLines.size(), 3);
  }



  /**
   * Tests the {@code getNonBlankFileLines} method when no value has been set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetNonBlankFileLinesNoValue()
         throws Exception
  {
    FileArgument a = new FileArgument('f', "fileArg", false, 1, "{path}",
                                      "foo");
    a = a.getCleanCopy();

    assertNull(a.getNonBlankFileLines());
  }



  /**
   * Tests the {@code getFileBytes} method on a valid file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetFileBytesValid()
         throws Exception
  {
    FileArgument a = new FileArgument('f', "fileArg", false, 1, "{path}",
                                      "foo");
    a = a.getCleanCopy();

    a.addValue(testFile.getAbsolutePath());

    byte[] fileBytes = a.getFileBytes();
    assertNotNull(fileBytes);
    assertTrue(fileBytes.length > 0);
  }



  /**
   * Tests the {@code getFileLines} method when no value has been set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetFileBytesNoValue()
         throws Exception
  {
    FileArgument a = new FileArgument('f', "fileArg", false, 1, "{path}",
                                      "foo");
    a = a.getCleanCopy();

    assertNull(a.getFileBytes());
  }



  /**
   * Tests the process for parsing a file argument when the target file is
   * specified using only the filename and it does not exist but we require the
   * parent directory to exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonExistingFileWithoutPathParentMustExist()
         throws Exception
  {
    FileArgument a = new FileArgument('f', "fileArg", true, 1, "{path}",
                                      "foo", false, true, true, false);
    a = a.getCleanCopy();

    // Create a filename that we assume doesn't exist.  If it does exist, then
    // the test is still valid, although it wasn't doing exactly what we
    // intended.
    String filename = "testNonExistingFileWithoutPathParentMustExist.test";
    a.addValue(filename);
    assertNotNull(a.getValue().getParent());
    assertNotNull(a.getValue().getParentFile());
  }



  /**
   * Tests the behavior when using relative paths.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRelativePaths()
         throws Exception
  {
    // Create a temporary directory that we will use for testing.
    final File tempDir = createTempDir();

    // Determine the current working directory, which will be the default base
    // for relative paths.
    final File workingDir = new File(System.getProperty("user.dir"));

    // First, test with an absolute path.
    FileArgument a = new FileArgument('f', "fileArg", true, 1, "{path}",
         "foo", false, true, true, false);
    a = a.getCleanCopy();

    assertNull(a.getRelativeBaseDirectory());
    File f = new File(tempDir, "foo");
    a.addValue(f.getAbsolutePath());
    assertEquals(a.getValue(), f);
    assertNotNull(a.getDataTypeName());
    assertNotNull(a.getValueConstraints());
    assertNotNull(a.toString());


    // Next, test with a relative path and no explicit base directory.
    a = new FileArgument('f', "fileArg", true, 1, "{path}", "foo", false, true,
         true, false);
    a = a.getCleanCopy();

    assertNull(a.getRelativeBaseDirectory());
    f = new File(workingDir, "foo");
    a.addValue("foo");
    assertEquals(a.getValue(), f);
    assertNotNull(a.getDataTypeName());
    assertNotNull(a.getValueConstraints());
    assertNotNull(a.toString());


    // Next, test with a relative path and an explicit base directory.
    a = new FileArgument('f', "fileArg", true, 1, "{path}", "foo", false, true,
         true, false);
    a = a.getCleanCopy();

    a.setRelativeBaseDirectory(tempDir);
    assertNotNull(a.getRelativeBaseDirectory());
    assertEquals(a.getRelativeBaseDirectory(), tempDir);
    f = new File(tempDir, "foo");
    a.addValue("foo");
    assertEquals(a.getValue(), f);
    assertNotNull(a.getDataTypeName());
    assertNotNull(a.getValueConstraints());
    assertNotNull(a.toString());


    // Test with a relative path and a different base directory.
    a = new FileArgument('f', "fileArg", true, 1, "{path}", "foo", false, true,
         true, false);
    a = a.getCleanCopy();

    a.setRelativeBaseDirectory(workingDir);
    assertNotNull(a.getRelativeBaseDirectory());
    assertEquals(a.getRelativeBaseDirectory(), workingDir);
    f = new File(workingDir, "foo");
    a.addValue("foo");
    assertEquals(a.getValue(), f);
    assertNotNull(a.getDataTypeName());
    assertNotNull(a.getValueConstraints());
    assertNotNull(a.toString());


    // Make sure that absolute paths still work.
    a = new FileArgument('f', "fileArg", true, 1, "{path}", "foo", false, true,
         true, false);
    a = a.getCleanCopy();

    a.setRelativeBaseDirectory(workingDir);
    assertNotNull(a.getRelativeBaseDirectory());
    assertEquals(a.getRelativeBaseDirectory(), workingDir);
    f = new File(tempDir, "foo");
    a.addValue(f.getAbsolutePath());
    assertEquals(a.getValue(), f);
    assertNotNull(a.getDataTypeName());
    assertNotNull(a.getValueConstraints());
    assertNotNull(a.toString());
  }
}
