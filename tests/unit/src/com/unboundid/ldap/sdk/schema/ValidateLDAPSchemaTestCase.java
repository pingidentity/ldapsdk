/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.schema;



import java.io.ByteArrayOutputStream;
import java.io.File;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldif.LDIFWriter;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a number of test cases for the validate-ldap-schema
 * command-line tool.
 */
public final class ValidateLDAPSchemaTestCase
       extends LDAPSDKTestCase
{
  // An entry that contains a minimal schema definition.
  private Entry minimalSchemaEntry = null;

  // A file that holds a minimal schema definition.
  private File minimalSchemaFile = null;

  // The lines that make up the LDIF representation of the minimal schema.
  private String[] minimalSchemaLines;



  /**
   * Creates an entry with a minimal set of schema definitions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    minimalSchemaLines = new String[]
    {
      "dn: cn=schema",
      "objectClass: top",
      "objectClass: ldapSubEntry",
      "objectClass: subschema",
      "cn: schema",
      "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.3 DESC 'Attribute Type " +
           "Description' )",
      "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )",
      "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.16 DESC 'DIT Content Rule " +
           "Description' )",
      "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.17 " +
           "DESC 'DIT Structure Rule Description' )",
      "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.26 DESC 'IA5 String' )",
      "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.27 DESC 'INTEGER' )",
      "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.30 DESC 'Matching Rule " +
           "Description' )",
      "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.31 DESC 'Matching Rule Use " +
           "Description' )",
      "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.35 DESC 'Name Form " +
           "Description' )",
      "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.37 DESC 'Object Class " +
           "Description' )",
      "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.38 DESC 'OID' )",
      "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.54 DESC 'LDAP Syntax " +
           "Description' )",
      "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.58 DESC 'Substring " +
           "Assertion' )",
      "matchingRules: ( 1.3.6.1.4.1.1466.109.114.2 NAME 'caseIgnoreIA5Match' " +
           "SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
      "matchingRules: ( 1.3.6.1.4.1.1466.109.114.3 NAME " +
           "'caseIgnoreIA5SubstringsMatch' " +
           "SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
      "matchingRules: ( 2.5.13.0 NAME 'objectIdentifierMatch' " +
           "SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
      "matchingRules: ( 2.5.13.2 NAME 'caseIgnoreMatch' " +
           "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
      "matchingRules: ( 2.5.13.3 NAME 'caseIgnoreOrderingMatch' " +
           "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
      "matchingRules: ( 2.5.13.4 NAME 'caseIgnoreSubstringsMatch' " +
           "SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
      "matchingRules: ( 2.5.13.29 NAME 'integerFirstComponentMatch' " +
           "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
      "matchingRules: ( 2.5.13.30 " +
           "NAME 'objectIdentifierFirstComponentMatch' " +
           "SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
      "attributeTypes: ( 2.5.4.0 NAME 'objectClass' " +
           "EQUALITY objectIdentifierMatch " +
           "SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
      "attributeTypes: ( 2.5.4.41 NAME 'name' EQUALITY caseIgnoreMatch " +
           "SUBSTR caseIgnoreSubstringsMatch " +
           "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
      "attributeTypes: ( 2.5.4.3 NAME 'cn' SUP name )",
      "attributeTypes: ( 0.9.2342.19200300.100.1.25 NAME 'dc' " +
           "EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch " +
           "SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
      "attributeTypes: ( 2.5.21.6 NAME 'objectClasses' " +
           "EQUALITY objectIdentifierFirstComponentMatch " +
           "SYNTAX 1.3.6.1.4.1.1466.115.121.1.37 USAGE directoryOperation )",
      "attributeTypes: ( 2.5.21.5 NAME 'attributeTypes' " +
           "EQUALITY objectIdentifierFirstComponentMatch " +
           "SYNTAX 1.3.6.1.4.1.1466.115.121.1.3 USAGE directoryOperation )",
      "attributeTypes: ( 2.5.21.4 NAME 'matchingRules' " +
           "EQUALITY objectIdentifierFirstComponentMatch " +
           "SYNTAX 1.3.6.1.4.1.1466.115.121.1.30 USAGE directoryOperation )",
      "attributeTypes: ( 2.5.21.8 NAME 'matchingRuleUse' " +
           "EQUALITY objectIdentifierFirstComponentMatch " +
           "SYNTAX 1.3.6.1.4.1.1466.115.121.1.31 USAGE directoryOperation )",
      "attributeTypes: ( 1.3.6.1.4.1.1466.101.120.16 NAME 'ldapSyntaxes' " +
           "EQUALITY objectIdentifierFirstComponentMatch",
      "  SYNTAX 1.3.6.1.4.1.1466.115.121.1.54 USAGE directoryOperation )",
      "attributeTypes: ( 2.5.21.2 NAME 'dITContentRules' " +
           "EQUALITY objectIdentifierFirstComponentMatch " +
           "SYNTAX 1.3.6.1.4.1.1466.115.121.1.16 USAGE directoryOperation )",
      "attributeTypes: ( 2.5.21.1 NAME 'dITStructureRules' " +
           "EQUALITY integerFirstComponentMatch " +
           "SYNTAX 1.3.6.1.4.1.1466.115.121.1.17",
      "  USAGE directoryOperation )",
      "attributeTypes: ( 2.5.21.7 NAME 'nameForms' " +
           "EQUALITY objectIdentifierFirstComponentMatch " +
           "SYNTAX 1.3.6.1.4.1.1466.115.121.1.35",
      "  USAGE directoryOperation )",
      "objectClasses: ( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
      "objectClasses: ( 2.16.840.1.113719.2.142.6.1.1 NAME 'ldapSubEntry' " +
           "SUP top STRUCTURAL MAY cn )",
      "objectClasses: ( 2.5.20.1 NAME 'subschema' AUXILIARY " +
           "MAY ( dITStructureRules $ nameForms $ ditContentRules $ " +
           "objectClasses $ attributeTypes $ matchingRules $ " +
           "matchingRuleUse ) )",
      "objectClasses: ( 0.9.2342.19200300.100.4.13 NAME 'domain' SUP top " +
           "STRUCTURAL MUST dc )"
    };

    minimalSchemaEntry = new Entry(minimalSchemaLines);
    minimalSchemaFile = createTempFile(minimalSchemaLines);
  }
  /**
   * Tests various tool methods that can be used without actually invoking the
   * tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToolMethodsWithoutInvoking()
         throws Exception
  {
    final ValidateLDAPSchema tool = new ValidateLDAPSchema(null, null);

    assertNotNull(tool.getToolName());
    assertFalse(tool.getToolName().isEmpty());

    assertNotNull(tool.getToolDescription());
    assertFalse(tool.getToolDescription().isEmpty());

    assertNotNull(tool.getToolVersion());
    assertFalse(tool.getToolVersion().isEmpty());

    assertTrue(tool.supportsInteractiveMode());

    assertTrue(tool.defaultsToInteractiveMode());

    assertTrue(tool.supportsPropertiesFile());

    assertTrue(tool.supportsOutputFile());

    assertFalse(tool.logToolInvocationByDefault());

    assertNull(tool.getToolCompletionMessage());

    assertNotNull(tool.getExampleUsages());
    assertFalse(tool.getExampleUsages().isEmpty());
    assertEquals(tool.getExampleUsages().size(), 2);
  }



  /**
   * Tests the behavior when invoking the tool to obtain usage information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUsage()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();
    final ResultCode resultCode = ValidateLDAPSchema.main(out, err, "--help");

    assertEquals(resultCode, ResultCode.SUCCESS);

    assertTrue(out.toByteArray().length > 0);

    assertEquals(err.toByteArray().length, 0);
  }



  /**
   * Tests with a minimal set of arguments and the default standard schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithMinimalArgsAndDefaultSchema()
         throws Exception
  {
    final File sourceRootDir = new File(System.getProperty("basedir"));
    final File schemaFile = StaticUtils.constructPath(sourceRootDir,
         "resource", "standard-schema.ldif");

    runTool(true, true, false,
         "--schema-path", schemaFile.getAbsolutePath());
  }



  /**
   * Tests with a minimal set of arguments and a minimal set of schema
   * definitions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithMinimalArgsAndMinimalSchema()
         throws Exception
  {
    runTool(true, true, false,
         "--schema-path", minimalSchemaFile.getAbsolutePath());
  }



  /**
   * Tests with multiple schema files containing valid definitions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleSchemaFilesAllValid()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "ldapSyntaxes: ( 1.2.3.4 DESC 'Test Syntax' )");

    runTool(true, true, false,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--schema-path", additionalSchemaFile.getAbsolutePath());
  }



  /**
   * Tests with multiple schema files containing valid definitions in which the
   * second file contains an invalid definition.  This also tests with the
   * ability to allow empty descriptions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleSchemaFilesSecondNotValid()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "ldapSyntaxes: ( 1.2.3.4 DESC '' )");

    runTool(false, false, true,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--schema-path", additionalSchemaFile.getAbsolutePath());

    runTool(true, true, false,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--schema-path", additionalSchemaFile.getAbsolutePath(),
         "--allow-empty-descriptions");
  }



  /**
   * Tests with an empty file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyFile()
         throws Exception
  {
    final File emptyFile = createTempFile();

    runTool(false, false, true,
         "--schema-path", emptyFile.getAbsolutePath());
  }



  /**
   * Tests with a directory that does not contain any schema files.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyDirectory()
         throws Exception
  {
    final File emptyDirectory = createTempDir();

    runTool(false, false, true,
         "--schema-path", emptyDirectory.getAbsolutePath());
  }



  /**
   * Test with multiple entries in the same schema file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleEntriesPerSchemaFile()
         throws Exception
  {
    final File schemaFile = createTempFile();
    try (LDIFWriter ldifWriter = new LDIFWriter(schemaFile))
    {
      ldifWriter.writeEntry(minimalSchemaEntry);
      ldifWriter.writeEntry(new Entry(
           "dn: cn=schema",
           "objectClass: top",
           "objectClass: ldapSubEntry",
           "objectClass: subschema",
           "cn: schema",
           "ldapSyntaxes: ( 1.2.3.4 DESC 'Test Syntax' )"));
    }

    runTool(false, false, true,
         "--schema-path", schemaFile.getAbsolutePath());

    runTool(true, true, false,
         "--schema-path", schemaFile.getAbsolutePath(),
         "--allow-multiple-entries-per-schema-file");
  }



  /**
   * Tests the behavior for schema files in subdirectories.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSchemaFilesInSubDirectories()
         throws Exception
  {
    final File schemaDir = createTempDir();

    final File subDir1 = new File(schemaDir, "subdirectory-1");
    subDir1.mkdir();

    final File subDir2 = new File(schemaDir, "subdirectory-2");
    subDir2.mkdir();

    final File schemaFile1 = new File(subDir1, "schema-file-1.ldif");
    StaticUtils.writeFile(schemaFile1, minimalSchemaLines);

    final File schemaFile2 = new File(subDir2, "schema-file-2.ldif");
    StaticUtils.writeFile(schemaFile2,
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "ldapSyntaxes: ( 1.2.3.4 DESC 'Test Syntax' )");

    runTool(false, false, true,
         "--schema-path", schemaDir.getAbsolutePath());

    runTool(true, true, false,
         "--schema-path", schemaDir.getAbsolutePath(),
         "--allow-schema-files-in-subdirectories");
  }



  /**
   * Tests the behavior when using allowed element types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllowedElementTypes()
         throws Exception
  {
    // Test with a set of allowed element types that include all of the element
    // types used in the minimal schema.
    runTool(true, true, false,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--allowed-element-type", "attribute-syntax",
         "--allowed-element-type", "matching-rule",
         "--allowed-element-type", "attribute-type",
         "--allowed-element-type", "object-class");

    // Test with a set of allowed element types that does not include the
    // object class type, even though object classes are defined in the
    // schema file.
    runTool(false, false, true,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--allowed-element-type", "attribute-syntax",
         "--allowed-element-type", "matching-rule",
         "--allowed-element-type", "attribute-type");

    // Test with a set of allowed element types that include an invalid value.
    runTool(false, false, true,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--allowed-element-type", "attribute-syntax",
         "--allowed-element-type", "matching-rule",
         "--allowed-element-type", "attribute-type",
         "--allowed-element-type", "object-class",
         "--allowed-element-type", "invalid");
  }



  /**
   * Tests the behavior when using prohibited element types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProhibitedElementTypes()
         throws Exception
  {
    // Test with a set of prohibited element types that do not include any of
    // the element types used in the minimal schema.
    runTool(true, true, false,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--prohibited-element-type", "name-form",
         "--prohibited-element-type", "dit-content-rule",
         "--prohibited-element-type", "dit-structure-rule",
         "--prohibited-element-type", "matching-rule-use");

    // Test with a set of prohibited element types that include the object class
    // type, which is used in the minimal schema.
    runTool(false, false, true,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--prohibited-element-type", "object-class",
         "--prohibited-element-type", "name-form",
         "--prohibited-element-type", "dit-content-rule",
         "--prohibited-element-type", "dit-structure-rule",
         "--prohibited-element-type", "matching-rule-use");

    // Test with a set of prohibited element types that include all schema
    // element types.
    runTool(false, false, true,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--prohibited-element-type", "attribute-syntax",
         "--prohibited-element-type", "matching-rule",
         "--prohibited-element-type", "attribute-type",
         "--prohibited-element-type", "object-class",
         "--prohibited-element-type", "name-form",
         "--prohibited-element-type", "dit-content-rule",
         "--prohibited-element-type", "dit-structure-rule",
         "--prohibited-element-type", "matching-rule-use");

    // Test with a set of prohibited element types that include an invalid
    // prohibited element type.
    runTool(false, false, true,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--prohibited-element-type", "name-form",
         "--prohibited-element-type", "dit-content-rule",
         "--prohibited-element-type", "dit-structure-rule",
         "--prohibited-element-type", "matching-rule-use",
         "--prohibited-element-type", "invalid");
  }



  /**
   * Tests the behavior when the same element is defined multiple times.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRedefiningElements()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.3 DESC 'Attribute Type " +
              "Description' )");

    runTool(false, false, true,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--schema-path", additionalSchemaFile.getAbsolutePath());

    runTool(true, true, false,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--schema-path", additionalSchemaFile.getAbsolutePath(),
         "--allow-redefining-elements");
  }



  /**
   * Tests the behavior when encountering elements with references to undefined
   * types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUndefinedElementTypes()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "objectClasses: ( 1.2.3.4 NAME 'test-oc' SUP top MAY description )");

    runTool(false, false, true,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--schema-path", additionalSchemaFile.getAbsolutePath());

    runTool(true, true, false,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--schema-path", additionalSchemaFile.getAbsolutePath(),
         "--allow-undefined-element-type", "attribute-type");

    runTool(false, false, true,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--schema-path", additionalSchemaFile.getAbsolutePath(),
         "--allow-undefined-element-type", "attribute-type",
         "--allow-undefined-element-type", "invalid");
  }



  /**
   * Tests arguments related to OID validation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOIDValidation()
         throws Exception
  {
    final File additionalSchemaFile1 = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "attributeTypes: ( 1 NAME 'test-at' " +
              "EQUALITY caseIgnoreMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )");

    runTool(false, false, true,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--schema-path", additionalSchemaFile1.getAbsolutePath());

    runTool(true, true, false,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--schema-path", additionalSchemaFile1.getAbsolutePath(),
         "--use-lenient-oid-validation");


    final File additionalSchemaFile2 = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "attributeTypes: ( test-at-oid NAME 'test-at' " +
              "EQUALITY caseIgnoreMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )");

    runTool(false, false, true,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--schema-path", additionalSchemaFile2.getAbsolutePath());

    runTool(true, true, false,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--schema-path", additionalSchemaFile2.getAbsolutePath(),
         "--allow-non-numeric-oids");


    final File additionalSchemaFile3 = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "attributeTypes: ( test-at-oid NAME 'test-at' " +
              "EQUALITY caseIgnoreMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )");

    runTool(false, false, true,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--schema-path", additionalSchemaFile3.getAbsolutePath());

    runTool(true, true, false,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--schema-path", additionalSchemaFile3.getAbsolutePath(),
         "--allow-non-numeric-oids");
  }



  /**
   * Tests arguments related to name validation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameValidation()
         throws Exception
  {
    final File additionalSchemaFile1 = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "attributeTypes: ( 1.2.3.4 " +
              "EQUALITY caseIgnoreMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )");

    runTool(false, false, true,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--schema-path", additionalSchemaFile1.getAbsolutePath());

    runTool(true, true, false,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--schema-path", additionalSchemaFile1.getAbsolutePath(),
         "--allow-elements-without-names");


    final File additionalSchemaFile2 = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "attributeTypes: ( 1.2.3.4 NAME '1-test-at' " +
              "EQUALITY caseIgnoreMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
         "attributeTypes: ( 1.2.3.5 NAME '-test-at-2' " +
              "EQUALITY caseIgnoreMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
         "attributeTypes: ( 1.2.3.6 NAME 'test_at_3' " +
              "EQUALITY caseIgnoreMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
         "attributeTypes: ( 1.2.3.7 NAME '_test_at_4' " +
              "EQUALITY caseIgnoreMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )");

    runTool(false, false, true,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--schema-path", additionalSchemaFile2.getAbsolutePath());

    runTool(true, true, false,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--schema-path", additionalSchemaFile2.getAbsolutePath(),
         "--use-lenient-name-validation");
  }



  /**
   * Tests arguments related to attribute type definitions that do not include
   * a syntax.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypesWithoutSyntax()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "attributeTypes: ( 1.2.3.4 NAME 'test-at' " +
              "EQUALITY caseIgnoreMatch )");

    runTool(false, false, true,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--schema-path", additionalSchemaFile.getAbsolutePath());

    runTool(true, true, false,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--schema-path", additionalSchemaFile.getAbsolutePath(),
         "--allow-attribute-types-without-syntax");
  }



  /**
   * Tests arguments related to attribute type definitions that do not include
   * an equality matching rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypesWithoutEqualityMatchingRule()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "attributeTypes: ( 1.2.3.4 NAME 'test-at' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )");

    runTool(true, true, false,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--schema-path", additionalSchemaFile.getAbsolutePath());

    runTool(false, false, true,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--schema-path", additionalSchemaFile.getAbsolutePath(),
         "--reject-attribute-types-without-equality-matching-rule");
  }



  /**
   * Tests arguments related to object class inheritance.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassInheritance()
         throws Exception
  {
    final File additionalSchemaFile1 = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "objectClasses: ( 1.2.3.4 NAME 'test-oc' STRUCTURAL MAY cn )");

    runTool(false, false, true,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--schema-path", additionalSchemaFile1.getAbsolutePath());

    runTool(true, true, false,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--schema-path", additionalSchemaFile1.getAbsolutePath(),
         "--allow-structural-object-classes-without-superior");

    final File additionalSchemaFile2 = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "objectClasses: ( 1.2.3.4 NAME 'test-oc' SUP ( top $ domain ) " +
              "STRUCTURAL MAY cn )");

    runTool(true, true, false,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--schema-path", additionalSchemaFile2.getAbsolutePath());

    runTool(false, false, true,
         "--schema-path", minimalSchemaFile.getAbsolutePath(),
         "--schema-path", additionalSchemaFile2.getAbsolutePath(),
         "--reject-object-classes-with-multiple-superiors");
  }



  /**
   * Runs the tool with the provided set of command-line arguments and verifies
   * that it yields the expected result.
   *
   * @param  expectSuccess      Indicates whether the tool is expected to
   *                            complete with a result code of
   *                            {@link ResultCode#SUCCESS}.
   * @param  expectStandardOut  Indicates whether the tool is expected to write
   *                            to standard output.
   * @param  expectStandardErr  Indicates whether the tool is expected to write
   *                            to standard error.
   * @param  args               The arguments to use when running the tool.
   *
   * @return  The tool instance that ran.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static ValidateLDAPSchema runTool(final boolean expectSuccess,
                                            final boolean expectStandardOut,
                                            final boolean expectStandardErr,
                                            final String... args)
          throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();
    final ValidateLDAPSchema tool = new ValidateLDAPSchema(out, err);

    final ResultCode resultCode = tool.runTool(args);
    if (expectSuccess)
    {
      if (resultCode != ResultCode.SUCCESS)
      {
        fail("validate-ldap-schema did not complete with the expected " +
             "SUCCESS result." +
             getResultDetails(args, resultCode, out, err));
      }
    }
    else if (resultCode == ResultCode.SUCCESS)
    {
      fail("validate-ldap-schema unexpectedly completed with a SUCCESS " +
           "result." + getResultDetails(args, resultCode, out, err));
    }


    if (expectStandardOut)
    {
      if (out.size() <= 0)
      {
        fail("validate-ldap-schema did not write to standard output as " +
             "expected." + getResultDetails(args, resultCode, out, err));
      }
    }
    else if (out.size() > 0)
    {
      fail("validate-ldap-schema unexpectedly wrote to standard output." +
           getResultDetails(args, resultCode, out, err));
    }


    if (expectStandardErr)
    {
      if (err.size() <= 0)
      {
        fail("validate-ldap-schema did not write to standard error as " +
             "expected." + getResultDetails(args, resultCode, out, err));
      }
    }
    else if (err.size() > 0)
    {
      fail("validate-ldap-schema unexpectedly wrote to standard error." +
           getResultDetails(args, resultCode, out, err));
    }


    final String completionMessage = tool.getToolCompletionMessage();
    if ((completionMessage == null) || completionMessage.isEmpty())
    {
      fail("validate-ldap-schema did not set a completion message." +
           getResultDetails(args, resultCode, out, err));
    }

    return tool;
  }



  /**
   * Retrieves a multi-line string with information about the result of invoking
   * the validate-ldap-schema tool.
   *
   * @param  args        The arguments used to run the tool.
   * @param  resultCode  The result code obtained from running the tool.
   * @param  out         The output stream used for standard output.
   * @param  err         The output stream used for standard error.
   *
   * @return  A multi-line string with information about the result of
   *          invoking the validate-ldap-schema tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static String getResultDetails(final String[] args,
                                         final ResultCode resultCode,
                                         final ByteArrayOutputStream out,
                                         final ByteArrayOutputStream err)
          throws Exception
  {
    final StringBuilder buffer = new StringBuilder();

    buffer.append(StaticUtils.EOL);
    buffer.append(StaticUtils.EOL);
    buffer.append("Command-line arguments:");
    for (final String arg : args)
    {
      if (arg.startsWith("-"))
      {
        buffer.append(StaticUtils.EOL);
        buffer.append("     ");
      }
      else
      {
        buffer.append(" ");
      }

      buffer.append(StaticUtils.cleanExampleCommandLineArgument(arg));
    }

    buffer.append(StaticUtils.EOL);
    buffer.append(StaticUtils.EOL);
    buffer.append("ResultCode:  ");
    buffer.append(resultCode);
    buffer.append(StaticUtils.EOL);
    buffer.append(StaticUtils.EOL);
    buffer.append("Standard Output:");
    buffer.append(StaticUtils.EOL);
    buffer.append("----- BEGIN STDOUT -----");
    buffer.append(StaticUtils.EOL);
    buffer.append(StaticUtils.toUTF8String(out.toByteArray()));
    buffer.append("----- END STDOUT -----");
    buffer.append(StaticUtils.EOL);
    buffer.append(StaticUtils.EOL);
    buffer.append("Standard Error:");
    buffer.append(StaticUtils.EOL);
    buffer.append("----- BEGIN STDERR -----");
    buffer.append(StaticUtils.EOL);
    buffer.append(StaticUtils.toUTF8String(err.toByteArray()));
    buffer.append("----- END STDERR -----");
    buffer.append(StaticUtils.EOL);

    return buffer.toString();
  }
}
