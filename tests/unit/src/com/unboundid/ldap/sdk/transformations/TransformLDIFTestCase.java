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
package com.unboundid.ldap.sdk.transformations;



import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.ldif.LDIFDeleteChangeRecord;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.ldif.LDIFModifyDNChangeRecord;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.ldif.LDIFRecord;
import com.unboundid.util.PassphraseEncryptedInputStream;
import com.unboundid.util.PassphraseEncryptedOutputStream;
import com.unboundid.util.PasswordReader;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;



/**
 * This class provides a set of test cases for the transform-ldif tool.
 */
public final class TransformLDIFTestCase
       extends LDAPSDKTestCase
{
  // The path to a file containing only the attribute type definitions from
  // the default standard schema.
  private volatile File onlyAttributeTypesFile = null;

  // The path to a file containing only the object class definitions from
  // the default standard schema.
  private volatile File onlyObjectClassesFile = null;

  // The path to the directory containing the attribute types and object classes
  // schema files.
  private volatile File separatedSchemaFilesDirectory = null;

  // The path to a file containing all schema definitions in the default
  // standard schema.
  private volatile File singleSchemaFile = null;



  /**
   * Prepares the schema files to use in processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    final Schema defaultSchema = Schema.getDefaultStandardSchema();
    final Entry schemaEntry = defaultSchema.getSchemaEntry();

    singleSchemaFile = createTempFile(schemaEntry.toLDIF());

    final Entry attributeTypesEntry = new Entry(schemaEntry.getDN(),
         schemaEntry.getAttribute("cn"),
         schemaEntry.getAttribute("objectClass"),
         schemaEntry.getAttribute("attributeTypes"));
    final File tempATFile = createTempFile(attributeTypesEntry.toLDIF());

    final Entry objectClassesEntry = new Entry(schemaEntry.getDN(),
         schemaEntry.getAttribute("cn"),
         schemaEntry.getAttribute("objectClass"),
         schemaEntry.getAttribute("objectClasses"));
    final File tempOCFile = createTempFile(objectClassesEntry.toLDIF());

    separatedSchemaFilesDirectory = createTempDir();
    onlyAttributeTypesFile = new File(separatedSchemaFilesDirectory,
         "attribute-types.ldif");
    onlyObjectClassesFile = new File(separatedSchemaFilesDirectory,
         "object-classes.ldif");
    assertTrue(tempATFile.renameTo(onlyAttributeTypesFile));
    assertTrue(tempOCFile.renameTo(onlyObjectClassesFile));
  }



  /**
   * Verifies the ability to obtain usage information from the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUsage()
         throws Exception
  {
    assertEquals(TransformLDIF.main((OutputStream) null, null, "--help"),
         ResultCode.SUCCESS);
  }



  /**
   * Provides test coverage for the various tool methods that can be invoked
   * without actually running the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToolMethods()
         throws Exception
  {
    final TransformLDIF tool = new TransformLDIF(null, null);

    assertNotNull(tool.getToolName());
    assertEquals(tool.getToolName(), "transform-ldif");

    assertNotNull(tool.getToolVersion());

    assertTrue(tool.supportsInteractiveMode());

    assertTrue(tool.defaultsToInteractiveMode());

    assertTrue(tool.supportsPropertiesFile());

    assertNotNull(tool.getExampleUsages());
    assertFalse(tool.getExampleUsages().isEmpty());
  }



  /**
   * Tests the ability to scramble a set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testScrambleBasic()
         throws Exception
  {
    // Create the LDIF file to scramble.
    final File sourceLDIFFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: domain",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: orgUnit",
         "",
         "dn: uid=user.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.1",
         "givenName: User",
         "sn: 1",
         "cn: User 1",
         "userPassword: {CLEAR}password",
         "description: user",
         "",
         "dn: uid=user.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.2",
         "givenName: User",
         "sn: 2",
         "cn: User 2",
         "userPassword: {CLEAR}password",
         "description: user",
         "",
         "dn: uid=user.3,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.3",
         "givenName: User",
         "sn: 3",
         "cn: User 3",
         "userPassword: {CLEAR}password",
         "description: user",
         "",
         "dn: uid=user.4,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.4",
         "givenName: User",
         "sn: 4",
         "cn: User 4",
         "userPassword: {CLEAR}password",
         "description: user",
         "",
         "dn: uid=user.5,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.5",
         "givenName: User",
         "sn: 5",
         "cn: User 5",
         "userPassword: {CLEAR}password",
         "description: user");


    final File outputFile = runTool(
         "--sourceLDIF", sourceLDIFFile.getAbsolutePath(),
         "--scrambleAttribute", "uid",
         "--scrambleAttribute", "description",
         "--scrambleAttribute", "userPassword",
         "--processDNs",
         "--schemaPath", singleSchemaFile.getAbsolutePath());

    final LDIFReader reader = new LDIFReader(outputFile);

    Entry e = reader.readEntry();
    assertNotNull(e);
    assertDNsEqual(e.getDN(), "dc=example,dc=com");
    assertTrue(e.hasAttribute("description"));
    assertFalse(e.hasAttributeValue("description", "domain"));

    e = reader.readEntry();
    assertNotNull(e);
    assertDNsEqual(e.getDN(), "ou=People,dc=example,dc=com");
    assertTrue(e.hasAttribute("description"));
    assertFalse(e.hasAttributeValue("description", "orgUnit"));

    for (int i=1; i <= 5; i++)
    {
      e = reader.readEntry();
      assertNotNull(e);

      assertTrue(e.getDN().startsWith("uid="));
      assertTrue(e.getDN().endsWith(",ou=People,dc=example,dc=com"));
      assertFalse(e.getDN().equals(
           "uid=user." + i + ",ou=People,dc=example,dc=com"));

      assertTrue(e.hasAttribute("uid"));
      assertFalse(e.hasAttributeValue("uid", "user." + i));

      assertTrue(e.hasAttribute("description"));
      assertFalse(e.hasAttributeValue("description", "user"));

      assertTrue(e.hasAttribute("userPassword"));
      assertFalse(e.hasAttributeValue("userPassword", "{CLEAR}password"));
      assertTrue(e.getAttributeValue("userPassword").startsWith("{CLEAR}"));
    }

    assertNull(reader.readEntry());

    reader.close();
  }



  /**
   * Tests the ability to scramble entries containing JSON objects.  No specific
   * fields to scramble will be given, so all fields will be scrambled.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testScrambleJSONAllFields()
         throws Exception
  {
    // Create the LDIF file to scramble.
    final File sourceLDIFFile = createTempFile(
         "dn: uid=user.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.1",
         "givenName: User",
         "sn: 1",
         "cn: User 1",
         "userPassword: {CLEAR}password",
         "description: { \"userID\":\"user.1\", \"firstName\":\"User\", " +
              "\"lastName\":\"1\" }",
         "",
         "dn: uid=user.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.2",
         "givenName: User",
         "sn: 2",
         "cn: User 2",
         "userPassword: {CLEAR}password",
         "description: { \"userID\":\"user.2\", \"firstName\":\"User\", " +
              "\"lastName\":\"2\" }",
         "",
         "dn: uid=user.3,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.3",
         "givenName: User",
         "sn: 3",
         "cn: User 3",
         "userPassword: {CLEAR}password",
         "description: { \"userID\":\"user.3\", \"firstName\":\"User\", " +
              "\"lastName\":\"3\" }",
         "",
         "dn: uid=user.4,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.4",
         "givenName: User",
         "sn: 4",
         "cn: User 4",
         "userPassword: {CLEAR}password",
         "description: { \"userID\":\"user.4\", \"firstName\":\"User\", " +
              "\"lastName\":\"4\" }",
         "",
         "dn: uid=user.5,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.5",
         "givenName: User",
         "sn: 5",
         "cn: User 5",
         "userPassword: {CLEAR}password",
         "description: { \"userID\":\"user.5\", \"firstName\":\"User\", " +
              "\"lastName\":\"5\" }");


    final File outputFile = runTool(
         "--sourceLDIF", sourceLDIFFile.getAbsolutePath(),
         "--scrambleAttribute", "description",
         "--randomSeed", "0",
         "--numThreads", "2",
         "--appendToTargetLDIF",
         "--compressTarget",
         "--wrapColumn", "50",
         "--schemaPath", separatedSchemaFilesDirectory.getAbsolutePath());

    final LDIFReader reader =
         new LDIFReader(new GZIPInputStream(new FileInputStream(outputFile)));

    for (int i=1; i <= 5; i++)
    {
      final Entry e = reader.readEntry();
      assertNotNull(e);

      assertDNsEqual(e.getDN(),
           "uid=user." + i + ",ou=People,dc=example,dc=com");

      assertTrue(e.hasAttribute("description"));

      final JSONObject o = new JSONObject(e.getAttributeValue("description"));

      assertNotNull(o.getField("userID"));
      assertFalse(((JSONString) o.getField("userID")).stringValue().equals
           ("user." + i));

      assertNotNull(o.getField("firstName"));
      assertFalse(((JSONString) o.getField("firstName")).stringValue().equals(
           "User"));

      assertNotNull(o.getField("lastName"));
      // NOTE:  Since the last name is only a single digit, it's possible that
      // the same digit could be chosen at random, so don't verify that it's
      // different.
      // assertFalse(o.getField("lastName").equals(String.valueOf(i)));
    }

    assertNull(reader.readEntry());
    reader.close();
  }



  /**
   * Tests the ability to scramble entries containing JSON objects when
   * targeting a specific JSON field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testScrambleJSONSpecifiedField()
         throws Exception
  {
    // Create the LDIF file to scramble.
    final File sourceLDIFFile = createTempFile(
         "dn: uid=user.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.1",
         "givenName: User",
         "sn: 1",
         "cn: User 1",
         "userPassword: {CLEAR}password",
         "description: { \"userID\":\"user.1\", \"firstName\":\"User\", " +
              "\"lastName\":\"1\" }",
         "",
         "dn: uid=user.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.2",
         "givenName: User",
         "sn: 2",
         "cn: User 2",
         "userPassword: {CLEAR}password",
         "description: { \"userID\":\"user.2\", \"firstName\":\"User\", " +
              "\"lastName\":\"2\" }",
         "",
         "dn: uid=user.3,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.3",
         "givenName: User",
         "sn: 3",
         "cn: User 3",
         "userPassword: {CLEAR}password",
         "description: { \"userID\":\"user.3\", \"firstName\":\"User\", " +
              "\"lastName\":\"3\" }",
         "",
         "dn: uid=user.4,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.4",
         "givenName: User",
         "sn: 4",
         "cn: User 4",
         "userPassword: {CLEAR}password",
         "description: { \"userID\":\"user.4\", \"firstName\":\"User\", " +
              "\"lastName\":\"4\" }",
         "",
         "dn: uid=user.5,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.5",
         "givenName: User",
         "sn: 5",
         "cn: User 5",
         "userPassword: {CLEAR}password",
         "description: { \"userID\":\"user.5\", \"firstName\":\"User\", " +
              "\"lastName\":\"5\" }");


    final File outputFile = runTool(
         "--sourceLDIF", sourceLDIFFile.getAbsolutePath(),
         "--scrambleAttribute", "description",
         "--scrambleJSONField", "userID",
         "--randomSeed", "0",
         "--numThreads", "2",
         "--appendToTargetLDIF",
         "--compressTarget",
         "--schemaPath", onlyAttributeTypesFile.getAbsolutePath(),
         "--schemaPath", onlyObjectClassesFile.getAbsolutePath());

    final LDIFReader reader =
         new LDIFReader(new GZIPInputStream(new FileInputStream(outputFile)));

    for (int i=1; i <= 5; i++)
    {
      final Entry e = reader.readEntry();
      assertNotNull(e);

      assertDNsEqual(e.getDN(),
           "uid=user." + i + ",ou=People,dc=example,dc=com");

      assertTrue(e.hasAttribute("description"));

      final JSONObject o = new JSONObject(e.getAttributeValue("description"));

      assertNotNull(o.getField("userID"));
      assertFalse(((JSONString) o.getField("userID")).stringValue().equals
           ("user." + i));

      assertNotNull(o.getField("firstName"));
      assertTrue(((JSONString) o.getField("firstName")).stringValue().equals(
           "User"));

      assertNotNull(o.getField("lastName"));
      assertTrue(((JSONString) o.getField("lastName")).stringValue().equals(
           String.valueOf(i)));
    }

    assertNull(reader.readEntry());
    reader.close();
  }



  /**
   * Tests the ability to replace a specified attribute with a
   * sequentially-incrementing counter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSequentialCounter()
         throws Exception
  {
    // Create the LDIF file to process.  We will create multiple identical
    // entries and let the sequential counter make them different.
    final File sourceLDIFFile = createTempFile(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password");


    final File outputFile = runTool(
         "--sourceLDIF", sourceLDIFFile.getAbsolutePath(),
         "--sequentialAttribute", "uid",
         "--initialSequentialValue", "10",
         "--sequentialValueIncrement", "10",
         "--textBeforeSequentialValue", "user.",
         "--processDNs");

    final LDIFReader reader = new LDIFReader(outputFile);

    for (int i=1; i <= 5; i++)
    {
      final Entry e = reader.readEntry();
      assertNotNull(e);

      assertDNsEqual(e.getDN(),
           "uid=user." + (10*i) + ",ou=People,dc=example,dc=com");

      assertTrue(e.hasAttribute("uid"));
      assertFalse(e.hasAttributeValue("uid", "test.user"));
      assertTrue(e.hasAttributeValue("uid", "user." + (10*i)));
    }

    assertNull(reader.readEntry());
    reader.close();
  }



  /**
   * Tests the ability to replace a specified attribute with a given set of
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReplaceValues()
         throws Exception
  {
    // Create the LDIF files to process.  We will create multiple input files
    // to test the aggregation feature.
    final File sourceLDIFFile1 = createTempFile(
         "dn: uid=user.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.1",
         "givenName: User",
         "sn: 1",
         "cn: User 1",
         "userPassword: password",
         "description: foo");
    final File sourceLDIFFile2 = createTempFile(
         "dn: uid=user.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.2",
         "givenName: User",
         "sn: 2",
         "cn: User 2",
         "userPassword: password",
         "description: foo");
    final File sourceLDIFFile3 = createTempFile(
         "dn: uid=user.3,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.3",
         "givenName: User",
         "sn: 3",
         "cn: User 3",
         "userPassword: password",
         "description: foo");
    final File sourceLDIFFile4 = createTempFile(
         "dn: uid=user.4,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.4",
         "givenName: User",
         "sn: 4",
         "cn: User 4",
         "userPassword: password",
         "description: foo");
    final File sourceLDIFFile5 = createTempFile(
         "dn: uid=user.5,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.5",
         "givenName: User",
         "sn: 5",
         "cn: User 5",
         "userPassword: password",
         "description: foo");


    final File outputFile = runTool(
         "--sourceLDIF", sourceLDIFFile1.getAbsolutePath(),
         "--sourceLDIF", sourceLDIFFile2.getAbsolutePath(),
         "--sourceLDIF", sourceLDIFFile3.getAbsolutePath(),
         "--sourceLDIF", sourceLDIFFile4.getAbsolutePath(),
         "--sourceLDIF", sourceLDIFFile5.getAbsolutePath(),
         "--replaceValuesAttribute", "description",
         "--replacementValue", "bar",
         "--replacementValue", "baz");

    final LDIFReader reader = new LDIFReader(outputFile);

    for (int i=1; i <= 5; i++)
    {
      final Entry e = reader.readEntry();
      assertNotNull(e);

      assertDNsEqual(e.getDN(),
           "uid=user." + i + ",ou=People,dc=example,dc=com");

      assertTrue(e.hasAttribute("description"));
      assertFalse(e.hasAttributeValue("description", "foo"));
      assertTrue(e.hasAttributeValue("description", "bar"));
      assertTrue(e.hasAttributeValue("description", "baz"));
    }

    assertNull(reader.readEntry());
    reader.close();
  }



  /**
   * Tests the ability to add an attribute that is missing from an entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddMissingValues()
         throws Exception
  {
    // Create the LDIF file to process.  It will be compressed.
    final File sourceLDIFFile = createTempFile();
    assertTrue(sourceLDIFFile.delete());

    final PrintStream ps = new PrintStream(
         new GZIPOutputStream(new FileOutputStream(sourceLDIFFile)));
    for (int i=1; i <= 5; i++)
    {
      ps.println("dn: uid=user." + i + ",ou=People,dc=example,dc=com");
      ps.println("objectClass: top");
      ps.println("objectClass: person");
      ps.println("objectClass: organizationalPerson");
      ps.println("objectClass: inetOrgPerson");
      ps.println("uid: user." + i);
      ps.println("givenName: User");
      ps.println("sn: " + i);
      ps.println("cn: User " + i);
      ps.println("userPassword: password");
      ps.println();
    }
    ps.close();


    final File outputFile = runTool(
         "--sourceLDIF", sourceLDIFFile.getAbsolutePath(),
         "--sourceCompressed",
         "--addAttributeName", "description",
         "--addAttributeValue", "added");

    final LDIFReader reader = new LDIFReader(outputFile);

    for (int i=1; i <= 5; i++)
    {
      final Entry e = reader.readEntry();
      assertNotNull(e);

      assertDNsEqual(e.getDN(),
           "uid=user." + i + ",ou=People,dc=example,dc=com");

      assertTrue(e.hasAttribute("description"));
      assertFalse(e.hasAttributeValue("description", "existing"));
      assertTrue(e.hasAttributeValue("description", "added"));
    }

    assertNull(reader.readEntry());
    reader.close();
  }



  /**
   * Tests the ability to add an attribute that may already be present in an
   * entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddAdditionalValues()
         throws Exception
  {
    // Create the LDIF file to process.  It will be compressed.
    final File sourceLDIFFile = createTempFile();
    assertTrue(sourceLDIFFile.delete());

    final PrintStream ps = new PrintStream(
         new GZIPOutputStream(new FileOutputStream(sourceLDIFFile)));
    for (int i=1; i <= 5; i++)
    {
      ps.println("dn: uid=user." + i + ",ou=People,dc=example,dc=com");
      ps.println("objectClass: top");
      ps.println("objectClass: person");
      ps.println("objectClass: organizationalPerson");
      ps.println("objectClass: inetOrgPerson");
      ps.println("uid: user." + i);
      ps.println("givenName: User");
      ps.println("sn: " + i);
      ps.println("cn: User " + i);
      ps.println("userPassword: password");
      ps.println("description: existing");
      ps.println();
    }
    ps.close();


    final File outputFile = runTool(
         "--sourceLDIF", sourceLDIFFile.getAbsolutePath(),
         "--sourceCompressed",
         "--addAttributeName", "description",
         "--addAttributeValue", "added",
         "--addToExistingValues");

    final LDIFReader reader = new LDIFReader(outputFile);

    for (int i=1; i <= 5; i++)
    {
      final Entry e = reader.readEntry();
      assertNotNull(e);

      assertDNsEqual(e.getDN(),
           "uid=user." + i + ",ou=People,dc=example,dc=com");

      assertTrue(e.hasAttribute("description"));
      assertTrue(e.hasAttributeValue("description", "existing"));
      assertTrue(e.hasAttributeValue("description", "added"));
    }

    assertNull(reader.readEntry());
    reader.close();
  }



  /**
   * Tests the ability to rename a specified set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRenameAttributeValid()
         throws Exception
  {
    // Create the LDIF file to process.
    final File sourceLDIFFile = createTempFile(
         "dn: uid=user.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.1",
         "givenName: User",
         "sn: 1",
         "cn: User 1",
         "userPassword: password",
         "",
         "dn: uid=user.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.2",
         "givenName: User",
         "sn: 2",
         "cn: User 2",
         "userPassword: password",
         "",
         "dn: uid=user.3,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.3",
         "givenName: User",
         "sn: 3",
         "cn: User 3",
         "userPassword: password",
         "",
         "dn: uid=user.4,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.4",
         "givenName: User",
         "sn: 4",
         "cn: User 4",
         "userPassword: password",
         "",
         "dn: uid=user.5,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.5",
         "givenName: User",
         "sn: 5",
         "cn: User 5",
         "userPassword: password");


    final File outputFile = runTool(
         "--sourceLDIF", sourceLDIFFile.getAbsolutePath(),
         "--renameAttributeFrom", "givenName",
         "--renameAttributeTo", "firstName",
         "--renameAttributeFrom", "sn",
         "--renameAttributeTo", "lastName",
         "--renameAttributeFrom", "cn",
         "--renameAttributeTo", "fullName");

    final LDIFReader reader = new LDIFReader(outputFile);

    for (int i=1; i <= 5; i++)
    {
      final Entry e = reader.readEntry();
      assertNotNull(e);

      assertDNsEqual(e.getDN(),
           "uid=user." + i + ",ou=People,dc=example,dc=com");

      assertFalse(e.hasAttribute("givenName"));
      assertFalse(e.hasAttribute("sn"));
      assertFalse(e.hasAttribute("cn"));

      assertTrue(e.hasAttribute("firstName"));
      assertTrue(e.hasAttribute("lastName"));
      assertTrue(e.hasAttribute("fullName"));

      assertTrue(e.hasAttributeValue("firstName", "User"));
      assertTrue(e.hasAttributeValue("lastName", String.valueOf(i)));
      assertTrue(e.hasAttributeValue("fullName", "User " + i));
    }

    assertNull(reader.readEntry());
    reader.close();
  }



  /**
   * Tests the behavior when trying to rename attributes without an equal number
   * of from and to attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRenameAttributeMismatch()
         throws Exception
  {
    // Create the LDIF file to process.
    final File sourceLDIFFile = createTempFile(
         "dn: uid=user.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.1",
         "givenName: User",
         "sn: 1",
         "cn: User 1",
         "userPassword: password",
         "",
         "dn: uid=user.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.2",
         "givenName: User",
         "sn: 2",
         "cn: User 2",
         "userPassword: password",
         "",
         "dn: uid=user.3,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.3",
         "givenName: User",
         "sn: 3",
         "cn: User 3",
         "userPassword: password",
         "",
         "dn: uid=user.4,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.4",
         "givenName: User",
         "sn: 4",
         "cn: User 4",
         "userPassword: password",
         "",
         "dn: uid=user.5,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.5",
         "givenName: User",
         "sn: 5",
         "cn: User 5",
         "userPassword: password");

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode resultCode = TransformLDIF.main(out, out,
         "--sourceLDIF", sourceLDIFFile.getAbsolutePath(),
         "--targetLDIF", outputFile.getAbsolutePath(),
         "--renameAttributeFrom", "givenName",
         "--renameAttributeTo", "firstName",
         "--renameAttributeTo", "lastName");

    assertFalse(resultCode == ResultCode.SUCCESS);
  }



  /**
   * Tests the ability to relocate a subtree.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMoveSubtreeValid()
         throws Exception
  {
    // Create the LDIF file to process.
    final File sourceLDIFFile = createTempFile(
         "dn: uid=user.1,ou=Users,o=example.com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.1",
         "givenName: User",
         "sn: 1",
         "cn: User 1",
         "userPassword: password",
         "",
         "dn: uid=user.2,ou=Users,o=example.com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.2",
         "givenName: User",
         "sn: 2",
         "cn: User 2",
         "userPassword: password",
         "",
         "dn: uid=user.3,ou=Users,o=example.com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.3",
         "givenName: User",
         "sn: 3",
         "cn: User 3",
         "userPassword: password",
         "",
         "dn: uid=user.4,ou=Users,o=example.com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.4",
         "givenName: User",
         "sn: 4",
         "cn: User 4",
         "userPassword: password",
         "",
         "dn: uid=user.5,ou=Users,o=example.com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.5",
         "givenName: User",
         "sn: 5",
         "cn: User 5",
         "userPassword: password");


    final File outputFile = runTool(
         "--sourceLDIF", sourceLDIFFile.getAbsolutePath(),
         "--moveSubtreeFrom", "ou=Users,o=example.com",
         "--moveSubtreeTo", "ou=People,dc=example,dc=com");

    final LDIFReader reader = new LDIFReader(outputFile);

    for (int i=1; i <= 5; i++)
    {
      final Entry e = reader.readEntry();
      assertNotNull(e);

      assertDNsEqual(e.getDN(),
           "uid=user." + i + ",ou=People,dc=example,dc=com");
    }

    assertNull(reader.readEntry());
    reader.close();
  }



  /**
   * Tests the ability to flatten a DIT, using all applicable command-line
   * options.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFlattenWithAllOptions()
         throws Exception
  {
    // Create the LDIF file to process.
    final File sourceLDIFFile = createTempFile(
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
         "dn: ou=East,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: East",
         "",
         "dn: uid=john.doe,ou=East,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: john.doe",
         "givenName: John",
         "sn: Doe",
         "cn: John Doe",
         "",
         "dn: givenName=John+sn=Doe,ou=East,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: john.doe",
         "givenName: John",
         "sn: Doe",
         "cn: John Doe",
         "",
         "dn: ou=sub1,uid=john.doe,ou=East,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: sub1",
         "",
         "dn: ou=sub2a+ou=sub2b,givenName=John+sn=Doe,ou=East,ou=People," +
              "dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: sub2a",
         "ou: sub2b",
         "",
         "dn: ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Groups",
         "",
         "dn: cn=Group 1,ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: groupOfNames",
         "cn: Group 1",
         "member: not a DN 1",
         "member: uid=john.doe,ou=East,ou=People,dc=example,dc=com",
         "member: ou=People,dc=example,dc=com",
         "member: givenName=John+sn=Doe,ou=East,ou=People,dc=example,dc=com",
         "member: uid=admin,dc=example,dc=com",
         "member: ou=sub1,uid=john.doe,ou=East,ou=People,dc=example,dc=com",
         "member: not a DN 2",
         "member: ou=sub2a+ou=sub2b,givenName=John+sn=Doe,ou=East,ou=People," +
              "dc=example,dc=com");


    final File outputFile = runTool(
         "--sourceLDIF", sourceLDIFFile.getAbsolutePath(),
         "--flattenBaseDN", "ou=People,dc=example,dc=com",
         "--flattenAddOmittedRDNAttributesToEntry",
         "--flattenAddOmittedRDNAttributesToRDN",
         "--flattenExcludeFilter", "(objectClass=organizationalUnit)");

    final LDIFReader reader = new LDIFReader(outputFile);

    Entry e = reader.readEntry();
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));

    e = reader.readEntry();
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"));

    e = reader.readEntry();
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: uid=john.doe+ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: john.doe",
              "givenName: John",
              "sn: Doe",
              "cn: John Doe",
              "ou: East"));

    e = reader.readEntry();
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: givenName=John+sn=Doe+ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: john.doe",
              "givenName: John",
              "sn: Doe",
              "cn: John Doe",
              "ou: East"));

    e = reader.readEntry();
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=Groups,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: Groups"));

    e = reader.readEntry();
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: cn=Group 1,ou=Groups,dc=example,dc=com",
              "objectClass: top",
              "objectClass: groupOfNames",
              "cn: Group 1",
              "member: not a DN 1",
              "member: uid=john.doe+ou=East,ou=People,dc=example,dc=com",
              "member: ou=People,dc=example,dc=com",
              "member: givenName=John+sn=Doe+ou=East,ou=People,dc=example," +
                   "dc=com",
              "member: uid=admin,dc=example,dc=com",
              "member: ou=sub1+uid=john.doe+ou=East,ou=People,dc=example," +
                   "dc=com",
              "member: not a DN 2",
              "member: ou=sub2a+ou=sub2b+givenName=John+sn=Doe+ou=East," +
                   "ou=People,dc=example,dc=com"));

    assertNull(reader.readEntry());
    reader.close();
  }



  /**
   * Tests the behavior when trying to move a subtree but there is a mismatch
   * in the number of to and from arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMoveSubtreeMismatch()
         throws Exception
  {
    // Create the LDIF file to process.
    final File sourceLDIFFile = createTempFile(
         "dn: uid=user.1,ou=Users,o=example.com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.1",
         "givenName: User",
         "sn: 1",
         "cn: User 1",
         "userPassword: password",
         "",
         "dn: uid=user.2,ou=Users,o=example.com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.2",
         "givenName: User",
         "sn: 2",
         "cn: User 2",
         "userPassword: password",
         "",
         "dn: uid=user.3,ou=Users,o=example.com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.3",
         "givenName: User",
         "sn: 3",
         "cn: User 3",
         "userPassword: password",
         "",
         "dn: uid=user.4,ou=Users,o=example.com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.4",
         "givenName: User",
         "sn: 4",
         "cn: User 4",
         "userPassword: password",
         "",
         "dn: uid=user.5,ou=Users,o=example.com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.5",
         "givenName: User",
         "sn: 5",
         "cn: User 5",
         "userPassword: password");


    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode resultCode = TransformLDIF.main(out, out,
         "--sourceLDIF", sourceLDIFFile.getAbsolutePath(),
         "--targetLDIF", outputFile.getAbsolutePath(),
         "--moveSubtreeFrom", "o=example.org",
         "--moveSubtreeTo", "dc=example,dc=com",
         "--moveSubtreeFrom", "ou=Users,o=example.com");

    assertFalse(resultCode == ResultCode.SUCCESS);
  }



  /**
   * Tests the ability to redact attribute values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRedactAttribute()
         throws Exception
  {
    // Create the LDIF file to process.
    final File sourceLDIFFile = createTempFile(
         "dn: uid=user.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.1",
         "givenName: User",
         "sn: 1",
         "cn: User 1",
         "userPassword: password",
         "",
         "dn: uid=user.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.2",
         "givenName: User",
         "sn: 2",
         "cn: User 2",
         "userPassword: password",
         "",
         "dn: uid=user.3,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.3",
         "givenName: User",
         "sn: 3",
         "cn: User 3",
         "userPassword: password",
         "",
         "dn: uid=user.4,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.4",
         "givenName: User",
         "sn: 4",
         "cn: User 4",
         "userPassword: password",
         "",
         "dn: uid=user.5,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.5",
         "givenName: User",
         "sn: 5",
         "cn: User 5",
         "userPassword: password");


    final File outputFile = runTool(
         "--sourceLDIF", sourceLDIFFile.getAbsolutePath(),
         "--redactAttribute", "objectClass",
         "--redactAttribute", "userPassword");

    final LDIFReader reader = new LDIFReader(outputFile);

    for (int i=1; i <= 5; i++)
    {
      final Entry e = reader.readEntry();
      assertNotNull(e);

      assertDNsEqual(e.getDN(),
           "uid=user." + i + ",ou=People,dc=example,dc=com");

      assertEquals(e.getAttribute("objectClass").size(), 4);
      assertTrue(e.hasAttributeValue("objectClass", "***REDACTED1***"));
      assertTrue(e.hasAttributeValue("objectClass", "***REDACTED2***"));
      assertTrue(e.hasAttributeValue("objectClass", "***REDACTED3***"));
      assertTrue(e.hasAttributeValue("objectClass", "***REDACTED4***"));

      assertEquals(e.getAttribute("userPassword").size(), 1);
      assertTrue(e.hasAttributeValue("userPassword", "***REDACTED***"));
    }

    assertNull(reader.readEntry());
    reader.close();
  }



  /**
   * Tests the ability to exclude attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeAttribute()
         throws Exception
  {
    // Create the LDIF file to process.
    final File sourceLDIFFile = createTempFile(
         "dn: uid=user.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.1",
         "givenName: User",
         "sn: 1",
         "cn: User 1",
         "userPassword: password",
         "",
         "dn: uid=user.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.2",
         "givenName: User",
         "sn: 2",
         "cn: User 2",
         "userPassword: password",
         "",
         "dn: uid=user.3,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.3",
         "givenName: User",
         "sn: 3",
         "cn: User 3",
         "userPassword: password",
         "",
         "dn: uid=user.4,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.4",
         "givenName: User",
         "sn: 4",
         "cn: User 4",
         "userPassword: password",
         "",
         "dn: uid=user.5,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.5",
         "givenName: User",
         "sn: 5",
         "cn: User 5",
         "userPassword: password");


    final File outputFile = runTool(
         "--sourceLDIF", sourceLDIFFile.getAbsolutePath(),
         "--excludeAttribute", "userPassword");

    final LDIFReader reader = new LDIFReader(outputFile);

    for (int i=1; i <= 5; i++)
    {
      final Entry e = reader.readEntry();
      assertNotNull(e);

      assertDNsEqual(e.getDN(),
           "uid=user." + i + ",ou=People,dc=example,dc=com");

      assertFalse(e.hasAttribute("userPassword"));
    }

    assertNull(reader.readEntry());
    reader.close();
  }



  /**
   * Tests the ability to exclude entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeEntry()
         throws Exception
  {
    // Create the LDIF file to process.
    final File sourceLDIFFile = createTempFile(
         "dn: uid=user.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.1",
         "givenName: User",
         "sn: 1",
         "cn: User 1",
         "userPassword: password",
         "",
         "dn: uid=user.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.2",
         "givenName: User",
         "sn: 2",
         "cn: User 2",
         "userPassword: password",
         "",
         "dn: uid=user.3,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.3",
         "givenName: User",
         "sn: 3",
         "cn: User 3",
         "userPassword: password",
         "",
         "dn: uid=user.4,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.4",
         "givenName: User",
         "sn: 4",
         "cn: User 4",
         "userPassword: password",
         "",
         "dn: uid=user.5,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.5",
         "givenName: User",
         "sn: 5",
         "cn: User 5",
         "userPassword: password");


    final File outputFile = runTool(
         "--sourceLDIF", sourceLDIFFile.getAbsolutePath(),
         "--excludeEntryFilter", "(|(sn=2)(sn=4))");

    final LDIFReader reader = new LDIFReader(outputFile);

    Entry e = reader.readEntry();
    assertNotNull(e);
    assertDNsEqual(e.getDN(), "uid=user.1,ou=People,dc=example,dc=com");

    e = reader.readEntry();
    assertNotNull(e);
    assertDNsEqual(e.getDN(), "uid=user.3,ou=People,dc=example,dc=com");

    e = reader.readEntry();
    assertNotNull(e);
    assertDNsEqual(e.getDN(), "uid=user.5,ou=People,dc=example,dc=com");

    assertNull(reader.readEntry());
    reader.close();
  }



  /**
   * Tests the ability to exclude LDIF records without change types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeRecordsWithoutChangeType()
         throws Exception
  {
    // Create the LDIF file to process.
    final File sourceLDIFFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: modify",
         "add: description",
         "description: foo",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newrdn: ou=Users",
         "deleteoldrdn: 1",
         "",
         "dn: ou=Users,dc=example,dc=com",
         "changetype: delete");


    final File outputFile = runTool(
         "--sourceLDIF", sourceLDIFFile.getAbsolutePath(),
         "--excludeRecordsWithoutChangeType");

    final LDIFReader reader = new LDIFReader(outputFile);

    LDIFRecord r = reader.readLDIFRecord();
    assertNotNull(r);
    assertTrue(r instanceof LDIFAddChangeRecord);

    r = reader.readLDIFRecord();
    assertNotNull(r);
    assertTrue(r instanceof LDIFModifyChangeRecord);

    r = reader.readLDIFRecord();
    assertNotNull(r);
    assertTrue(r instanceof LDIFModifyDNChangeRecord);

    r = reader.readLDIFRecord();
    assertNotNull(r);
    assertTrue(r instanceof LDIFDeleteChangeRecord);

    assertNull(reader.readEntry());
    reader.close();
  }



  /**
   * Tests the ability to exclude LDIF records with a specified set of change
   * types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeChangeType()
         throws Exception
  {
    // Create the LDIF file to process.
    final File sourceLDIFFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: modify",
         "add: description",
         "description: foo",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newrdn: ou=Users",
         "deleteoldrdn: 1",
         "",
         "dn: ou=Users,dc=example,dc=com",
         "changetype: delete");


    final File outputFile = runTool(
         "--sourceLDIF", sourceLDIFFile.getAbsolutePath(),
         "--excludeChangeType", "add",
         "--excludeChangeType", "delete");

    final LDIFReader reader = new LDIFReader(outputFile);

    LDIFRecord r = reader.readLDIFRecord();
    assertNotNull(r);
    assertTrue(r instanceof Entry);

    r = reader.readLDIFRecord();
    assertNotNull(r);
    assertTrue(r instanceof LDIFModifyChangeRecord);

    r = reader.readLDIFRecord();
    assertNotNull(r);
    assertTrue(r instanceof LDIFModifyDNChangeRecord);

    assertNull(reader.readEntry());
    reader.close();
  }



  /**
   * Tests the behavior when writing to standard output and reading from
   * standard input.  This simulates piping the output from one invocation into
   * a second invocation, since it's not trivial to simulate piping in a test
   * case.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWriteToStandardOutAndReadFromStandardIn()
         throws Exception
  {
    // Create the LDIF file to scramble.
    final File sourceLDIFFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: domain",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: orgUnit",
         "",
         "dn: uid=user.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.1",
         "givenName: User",
         "sn: 1",
         "cn: User 1",
         "userPassword: {CLEAR}password",
         "description: user",
         "",
         "dn: uid=user.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.2",
         "givenName: User",
         "sn: 2",
         "cn: User 2",
         "userPassword: {CLEAR}password",
         "description: user",
         "",
         "dn: uid=user.3,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.3",
         "givenName: User",
         "sn: 3",
         "cn: User 3",
         "userPassword: {CLEAR}password",
         "description: user",
         "",
         "dn: uid=user.4,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.4",
         "givenName: User",
         "sn: 4",
         "cn: User 4",
         "userPassword: {CLEAR}password",
         "description: user",
         "",
         "dn: uid=user.5,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.5",
         "givenName: User",
         "sn: 5",
         "cn: User 5",
         "userPassword: {CLEAR}password",
         "description: user");


    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ResultCode scrambleResultCode = TransformLDIF.main(out, null,
         "--sourceLDIF", sourceLDIFFile.getAbsolutePath(),
         "--targetToStandardOutput",
         "--scrambleAttribute", "uid",
         "--scrambleAttribute", "description",
         "--scrambleAttribute", "userPassword",
         "--processDNs",
         "--schemaPath", singleSchemaFile.getAbsolutePath());
    assertEquals(scrambleResultCode, ResultCode.SUCCESS);

    final File outputFile;
    final InputStream originalIn = System.in;
    try
    {
      System.setIn(new ByteArrayInputStream(out.toByteArray()));
      outputFile = runTool(
           "--sourceFromStandardInput",
           "--excludeAttribute", "sn");
    }
    finally
    {
      System.setIn(originalIn);
    }

    final LDIFReader reader = new LDIFReader(outputFile);

    Entry e = reader.readEntry();
    assertNotNull(e);
    assertDNsEqual(e.getDN(), "dc=example,dc=com");
    assertTrue(e.hasAttribute("description"));
    assertFalse(e.hasAttributeValue("description", "domain"));

    e = reader.readEntry();
    assertNotNull(e);
    assertDNsEqual(e.getDN(), "ou=People,dc=example,dc=com");
    assertTrue(e.hasAttribute("description"));
    assertFalse(e.hasAttributeValue("description", "orgUnit"));

    for (int i=1; i <= 5; i++)
    {
      e = reader.readEntry();
      assertNotNull(e);

      assertTrue(e.getDN().startsWith("uid="));
      assertTrue(e.getDN().endsWith(",ou=People,dc=example,dc=com"));
      assertFalse(e.getDN().equals(
           "uid=user." + i + ",ou=People,dc=example,dc=com"));

      assertTrue(e.hasAttribute("uid"));
      assertFalse(e.hasAttributeValue("uid", "user." + i));

      assertTrue(e.hasAttribute("description"));
      assertFalse(e.hasAttributeValue("description", "user"));

      assertTrue(e.hasAttribute("userPassword"));
      assertFalse(e.hasAttributeValue("userPassword", "{CLEAR}password"));
      assertTrue(e.getAttributeValue("userPassword").startsWith("{CLEAR}"));

      assertFalse(e.hasAttribute("sn"));
    }

    assertNull(reader.readEntry());

    reader.close();
  }



  /**
   * Tests the behavior when trying to run the tool with a specified schema
   * directory that is empty.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptySchemaDirectory()
         throws Exception
  {
    // Create the schema directory.
    final File schemaDir = createTempDir();

    final File sourceLDIFFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File targetLDIFFile = createTempFile();
    assertTrue(targetLDIFFile.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode resultCode = TransformLDIF.main(out, out,
         "--schemaPath", schemaDir.getAbsolutePath(),
         "--sourceLDIF", sourceLDIFFile.getAbsolutePath(),
         "--targetLDIF", targetLDIFFile.getAbsolutePath(),
         "--excludeAttribute", "userPassword");

    assertFalse(resultCode == ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior when trying to read an LDIF file with a malformed
   * record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedLDIFRecord()
         throws Exception
  {
    final File sourceLDIFFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=malformed,dc=example,dc=com",
         "malformed",
         "");

    final File targetLDIFFile = createTempFile();
    assertTrue(targetLDIFFile.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode resultCode = TransformLDIF.main(out, out,
         "--sourceLDIF", sourceLDIFFile.getAbsolutePath(),
         "--targetLDIF", targetLDIFFile.getAbsolutePath(),
         "--excludeAttribute", "userPassword");

    assertFalse(resultCode == ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior with a file with a large number of LDIF change records.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLargeChangeRecordFile()
         throws Exception
  {
    final File sourceLDIFFile = createTempFile();
    assertTrue(sourceLDIFFile.delete());

    final PrintStream w = new PrintStream(sourceLDIFFile);

    for (int i=1; i <= 2500; i++)
    {
      w.println("dn: uid=user." + i + ",ou=People,dc=example,dc=com");
      w.println("changetype: modify");
      w.println("replace: description");
      w.println("description: foo");
      w.println();
    }

    w.close();

    final File targetLDIFFile = runTool(
         "--sourceLDIF", sourceLDIFFile.getAbsolutePath(),
         "--sourceContainsChangeRecords",
         "--redactAttribute", "description",
         "--numThreads", "10");

    final LDIFReader reader = new LDIFReader(targetLDIFFile);

    int readCount = 0;
    while (true)
    {
      final LDIFChangeRecord r = reader.readChangeRecord();
      if (r == null)
      {
        break;
      }

      readCount++;
      assertTrue(r instanceof LDIFModifyChangeRecord);
    }
    reader.close();

    assertEquals(readCount, 2500);
  }



  /**
   * Tests the behavior when trying to invoke the tool without a --targetLDIF
   * argument and the --scrambleAttribute argument is given.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMissingTargetLDIFWithScrambleAttribute()
         throws Exception
  {
    final File sourceLDIFFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: foo");

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode resultCode = TransformLDIF.main(out, out,
         "--sourceLDIF", sourceLDIFFile.getAbsolutePath(),
         "--scrambleAttribute", "description");

    assertTrue(resultCode == ResultCode.SUCCESS);

    final File expectedTargetFile =
         new File(sourceLDIFFile.getAbsolutePath() + ".scrambled");
    assertTrue(expectedTargetFile.exists());
  }



  /**
   * Tests the behavior when trying to invoke the tool without a --targetLDIF
   * argument and neither the --scrambleAttribute argument nor the
   * --sequentialAttribute argument is given.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMissingTargetLDIFWithoutScrambleOrSequentialAttribute()
         throws Exception
  {
    final File sourceLDIFFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: foo");

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode resultCode = TransformLDIF.main(out, out,
         "--sourceLDIF", sourceLDIFFile.getAbsolutePath(),
         "--excludeAttribute", "description");

    assertFalse(resultCode == ResultCode.SUCCESS);

    final File expectedTargetFile =
         new File(sourceLDIFFile.getAbsolutePath() + ".scrambled");
    assertFalse(expectedTargetFile.exists());
  }



  /**
   * Tests the tool's behavior when dealing with compressed and encrypted data
   * when using a passphrase obtained from a file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEncryptionWithPassphraseFromFile()
         throws Exception
  {
    // Define the source data that will be used for testing.
    final String[] sourceLines =
    {
      "dn: dc=example,dc=com",
      "objectClass: top",
      "objectClass: domain",
      "dc: example",
      "description: domain",
      "",
      "dn: ou=People,dc=example,dc=com",
      "objectClass: top",
      "objectClass: organizationalUnit",
      "ou: People",
      "description: orgUnit",
      "",
      "dn: uid=user.1,ou=People,dc=example,dc=com",
      "objectClass: top",
      "objectClass: person",
      "objectClass: organizationalPerson",
      "objectClass: inetOrgPerson",
      "uid: user.1",
      "givenName: User",
      "sn: 1",
      "cn: User 1",
      "userPassword: {CLEAR}password",
      "description: user",
      "",
      "dn: uid=user.2,ou=People,dc=example,dc=com",
      "objectClass: top",
      "objectClass: person",
      "objectClass: organizationalPerson",
      "objectClass: inetOrgPerson",
      "uid: user.2",
      "givenName: User",
      "sn: 2",
      "cn: User 2",
      "userPassword: {CLEAR}password",
      "description: user",
      "",
      "dn: uid=user.3,ou=People,dc=example,dc=com",
      "objectClass: top",
      "objectClass: person",
      "objectClass: organizationalPerson",
      "objectClass: inetOrgPerson",
      "uid: user.3",
      "givenName: User",
      "sn: 3",
      "cn: User 3",
      "userPassword: {CLEAR}password",
      "description: user",
      "",
      "dn: uid=user.4,ou=People,dc=example,dc=com",
      "objectClass: top",
      "objectClass: person",
      "objectClass: organizationalPerson",
      "objectClass: inetOrgPerson",
      "uid: user.4",
      "givenName: User",
      "sn: 4",
      "cn: User 4",
      "userPassword: {CLEAR}password",
      "description: user",
      "",
      "dn: uid=user.5,ou=People,dc=example,dc=com",
      "objectClass: top",
      "objectClass: person",
      "objectClass: organizationalPerson",
      "objectClass: inetOrgPerson",
      "uid: user.5",
      "givenName: User",
      "sn: 5",
      "cn: User 5",
      "userPassword: {CLEAR}password",
      "description: user"
    };


    // Create the LDIF file to scramble  It will be compressed and encrypted.
    final File sourceLDIFFile = createTempFile();
    assertTrue(sourceLDIFFile.delete());

    final PrintStream printStream = new PrintStream(new GZIPOutputStream(
         new PassphraseEncryptedOutputStream("passphrase",
              new FileOutputStream(sourceLDIFFile))));
    for (final String line : sourceLines)
    {
      printStream.println(line);
    }
    printStream.close();

    final File passphraseFile = createTempFile("passphrase");

    final File outputFile = runTool(
         "--sourceLDIF", sourceLDIFFile.getAbsolutePath(),
         "--scrambleAttribute", "uid",
         "--scrambleAttribute", "description",
         "--scrambleAttribute", "userPassword",
         "--processDNs",
         "--schemaPath", singleSchemaFile.getAbsolutePath(),
         "--compressTarget",
         "--encryptTarget",
         "--encryptionPassphraseFile", passphraseFile.getAbsolutePath());

    final LDIFReader reader = new LDIFReader(new GZIPInputStream(
         new BufferedInputStream(new PassphraseEncryptedInputStream(
              "passphrase", new BufferedInputStream(new FileInputStream(
                   outputFile))))));

    Entry e = reader.readEntry();
    assertNotNull(e);
    assertDNsEqual(e.getDN(), "dc=example,dc=com");
    assertTrue(e.hasAttribute("description"));
    assertFalse(e.hasAttributeValue("description", "domain"));

    e = reader.readEntry();
    assertNotNull(e);
    assertDNsEqual(e.getDN(), "ou=People,dc=example,dc=com");
    assertTrue(e.hasAttribute("description"));
    assertFalse(e.hasAttributeValue("description", "orgUnit"));

    for (int i=1; i <= 5; i++)
    {
      e = reader.readEntry();
      assertNotNull(e);

      assertTrue(e.getDN().startsWith("uid="));
      assertTrue(e.getDN().endsWith(",ou=People,dc=example,dc=com"));
      assertFalse(e.getDN().equals(
           "uid=user." + i + ",ou=People,dc=example,dc=com"));

      assertTrue(e.hasAttribute("uid"));
      assertFalse(e.hasAttributeValue("uid", "user." + i));

      assertTrue(e.hasAttribute("description"));
      assertFalse(e.hasAttributeValue("description", "user"));

      assertTrue(e.hasAttribute("userPassword"));
      assertFalse(e.hasAttributeValue("userPassword", "{CLEAR}password"));
      assertTrue(e.getAttributeValue("userPassword").startsWith("{CLEAR}"));
    }

    assertNull(reader.readEntry());

    reader.close();
  }



  /**
   * Tests the tool's behavior when dealing with compressed and encrypted data
   * when using a passphrase obtained via interactive prompting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEncryptionWithPassphraseFromPrompt()
         throws Exception
  {
    // Define the source data that will be used for testing.
    final String[] sourceLines =
    {
      "dn: dc=example,dc=com",
      "objectClass: top",
      "objectClass: domain",
      "dc: example",
      "description: domain",
      "",
      "dn: ou=People,dc=example,dc=com",
      "objectClass: top",
      "objectClass: organizationalUnit",
      "ou: People",
      "description: orgUnit",
      "",
      "dn: uid=user.1,ou=People,dc=example,dc=com",
      "objectClass: top",
      "objectClass: person",
      "objectClass: organizationalPerson",
      "objectClass: inetOrgPerson",
      "uid: user.1",
      "givenName: User",
      "sn: 1",
      "cn: User 1",
      "userPassword: {CLEAR}password",
      "description: user",
      "",
      "dn: uid=user.2,ou=People,dc=example,dc=com",
      "objectClass: top",
      "objectClass: person",
      "objectClass: organizationalPerson",
      "objectClass: inetOrgPerson",
      "uid: user.2",
      "givenName: User",
      "sn: 2",
      "cn: User 2",
      "userPassword: {CLEAR}password",
      "description: user",
      "",
      "dn: uid=user.3,ou=People,dc=example,dc=com",
      "objectClass: top",
      "objectClass: person",
      "objectClass: organizationalPerson",
      "objectClass: inetOrgPerson",
      "uid: user.3",
      "givenName: User",
      "sn: 3",
      "cn: User 3",
      "userPassword: {CLEAR}password",
      "description: user",
      "",
      "dn: uid=user.4,ou=People,dc=example,dc=com",
      "objectClass: top",
      "objectClass: person",
      "objectClass: organizationalPerson",
      "objectClass: inetOrgPerson",
      "uid: user.4",
      "givenName: User",
      "sn: 4",
      "cn: User 4",
      "userPassword: {CLEAR}password",
      "description: user",
      "",
      "dn: uid=user.5,ou=People,dc=example,dc=com",
      "objectClass: top",
      "objectClass: person",
      "objectClass: organizationalPerson",
      "objectClass: inetOrgPerson",
      "uid: user.5",
      "givenName: User",
      "sn: 5",
      "cn: User 5",
      "userPassword: {CLEAR}password",
      "description: user"
    };


    // Create the LDIF file to scramble  It will be compressed and encrypted.
    final File sourceLDIFFile = createTempFile();
    assertTrue(sourceLDIFFile.delete());

    final PrintStream printStream = new PrintStream(new GZIPOutputStream(
         new PassphraseEncryptedOutputStream("passphrase",
              new FileOutputStream(sourceLDIFFile))));
    for (final String line : sourceLines)
    {
      printStream.println(line);
    }
    printStream.close();

    final File outputFile;
    try
    {
      PasswordReader.setTestReaderLines("passphrase");

      outputFile = runTool(
           "--sourceLDIF", sourceLDIFFile.getAbsolutePath(),
           "--scrambleAttribute", "uid",
           "--scrambleAttribute", "description",
           "--scrambleAttribute", "userPassword",
           "--processDNs",
           "--schemaPath", singleSchemaFile.getAbsolutePath(),
           "--compressTarget",
           "--encryptTarget");
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }

    final LDIFReader reader = new LDIFReader(new GZIPInputStream(
         new BufferedInputStream(new PassphraseEncryptedInputStream(
              "passphrase", new BufferedInputStream(new FileInputStream(
                   outputFile))))));

    Entry e = reader.readEntry();
    assertNotNull(e);
    assertDNsEqual(e.getDN(), "dc=example,dc=com");
    assertTrue(e.hasAttribute("description"));
    assertFalse(e.hasAttributeValue("description", "domain"));

    e = reader.readEntry();
    assertNotNull(e);
    assertDNsEqual(e.getDN(), "ou=People,dc=example,dc=com");
    assertTrue(e.hasAttribute("description"));
    assertFalse(e.hasAttributeValue("description", "orgUnit"));

    for (int i=1; i <= 5; i++)
    {
      e = reader.readEntry();
      assertNotNull(e);

      assertTrue(e.getDN().startsWith("uid="));
      assertTrue(e.getDN().endsWith(",ou=People,dc=example,dc=com"));
      assertFalse(e.getDN().equals(
           "uid=user." + i + ",ou=People,dc=example,dc=com"));

      assertTrue(e.hasAttribute("uid"));
      assertFalse(e.hasAttributeValue("uid", "user." + i));

      assertTrue(e.hasAttribute("description"));
      assertFalse(e.hasAttributeValue("description", "user"));

      assertTrue(e.hasAttribute("userPassword"));
      assertFalse(e.hasAttributeValue("userPassword", "{CLEAR}password"));
      assertTrue(e.getAttributeValue("userPassword").startsWith("{CLEAR}"));
    }

    assertNull(reader.readEntry());

    reader.close();
  }



  /**
   * Tests the tool's behavior when dealing with compressed and encrypted data
   * when using a passphrase obtained via interactive prompting and the input
   * is not encrypted.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEncryptionWithPassphraseFromPromptUnencryptedInput()
         throws Exception
  {
    // Create the LDIF file to scramble.
    final File sourceLDIFFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: domain",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: orgUnit",
         "",
         "dn: uid=user.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.1",
         "givenName: User",
         "sn: 1",
         "cn: User 1",
         "userPassword: {CLEAR}password",
         "description: user",
         "",
         "dn: uid=user.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.2",
         "givenName: User",
         "sn: 2",
         "cn: User 2",
         "userPassword: {CLEAR}password",
         "description: user",
         "",
         "dn: uid=user.3,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.3",
         "givenName: User",
         "sn: 3",
         "cn: User 3",
         "userPassword: {CLEAR}password",
         "description: user",
         "",
         "dn: uid=user.4,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.4",
         "givenName: User",
         "sn: 4",
         "cn: User 4",
         "userPassword: {CLEAR}password",
         "description: user",
         "",
         "dn: uid=user.5,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.5",
         "givenName: User",
         "sn: 5",
         "cn: User 5",
         "userPassword: {CLEAR}password",
         "description: user");

    final File outputFile;
    try
    {
      PasswordReader.setTestReaderLines("passphrase", "passphrase");

      outputFile = runTool(
           "--sourceLDIF", sourceLDIFFile.getAbsolutePath(),
           "--scrambleAttribute", "uid",
           "--scrambleAttribute", "description",
           "--scrambleAttribute", "userPassword",
           "--processDNs",
           "--schemaPath", singleSchemaFile.getAbsolutePath(),
           "--encryptTarget");
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }

    final LDIFReader reader = new LDIFReader(new PassphraseEncryptedInputStream(
         "passphrase", new FileInputStream(outputFile)));

    Entry e = reader.readEntry();
    assertNotNull(e);
    assertDNsEqual(e.getDN(), "dc=example,dc=com");
    assertTrue(e.hasAttribute("description"));
    assertFalse(e.hasAttributeValue("description", "domain"));

    e = reader.readEntry();
    assertNotNull(e);
    assertDNsEqual(e.getDN(), "ou=People,dc=example,dc=com");
    assertTrue(e.hasAttribute("description"));
    assertFalse(e.hasAttributeValue("description", "orgUnit"));

    for (int i=1; i <= 5; i++)
    {
      e = reader.readEntry();
      assertNotNull(e);

      assertTrue(e.getDN().startsWith("uid="));
      assertTrue(e.getDN().endsWith(",ou=People,dc=example,dc=com"));
      assertFalse(e.getDN().equals(
           "uid=user." + i + ",ou=People,dc=example,dc=com"));

      assertTrue(e.hasAttribute("uid"));
      assertFalse(e.hasAttributeValue("uid", "user." + i));

      assertTrue(e.hasAttribute("description"));
      assertFalse(e.hasAttributeValue("description", "user"));

      assertTrue(e.hasAttribute("userPassword"));
      assertFalse(e.hasAttributeValue("userPassword", "{CLEAR}password"));
      assertTrue(e.getAttributeValue("userPassword").startsWith("{CLEAR}"));
    }

    assertNull(reader.readEntry());

    reader.close();
  }



  /**
   * Invokes the tool with the provided set of arguments.  The --targetLDIF
   * argument should not be included, as it will be added by this method.  The
   * tool must complete successfully.
   *
   * @param  args  The command-line arguments (other than those needed to
   *               specify the output file) to use when running the tool.
   *
   * @return  The path to the output file that was written.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static File runTool(final String... args)
          throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final ArrayList<String> argList = new ArrayList<String>(args.length + 2);
    argList.addAll(Arrays.asList(args));
    argList.add("--targetLDIF");
    argList.add(outputFile.getAbsolutePath());

    final String[] argArray = new String[argList.size()];
    argList.toArray(argArray);

    final ResultCode resultCode = TransformLDIF.main(out, out, argArray);
    assertEquals(resultCode, ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    return outputFile;
  }
}
