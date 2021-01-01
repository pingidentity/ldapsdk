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



import java.io.File;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldif.LDIFWriter;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the {@code SchemaValidator}
 * enum.
 */
public class SchemaValidatorTestCase
       extends LDAPSDKTestCase
{
  // An entry that contains a minimal schema definition.
  private Entry minimalSchemaEntry = null;

  // A file that holds a minimal schema definition.
  private File minimalSchemaFile = null;

  // THe lines that make up the minimal schema definition.
  private String[] minimalSchemaLines = null;



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
   * Tests to verify the default configuration.
   */
  @Test()
  public void testDefaultConfiguration()
  {
    final SchemaValidator schemaValidator = new SchemaValidator();

    assertNull(schemaValidator.getSchemaFileNamePattern());

    assertTrue(schemaValidator.ignoreSchemaFilesNotMatchingFileNamePattern());

    assertFalse(schemaValidator.allowMultipleEntriesPerFile());

    assertFalse(schemaValidator.allowSchemaFilesInSubDirectories());

    assertTrue(schemaValidator.ensureSchemaEntryIsValid());

    assertNotNull(schemaValidator.getAllowedSchemaElementTypes());
    assertFalse(schemaValidator.getAllowedSchemaElementTypes().isEmpty());
    assertEquals(schemaValidator.getAllowedSchemaElementTypes(),
         EnumSet.allOf(SchemaElementType.class));

    assertNotNull(schemaValidator.getAllowReferencesToUndefinedElementTypes());
    assertTrue(
         schemaValidator.getAllowReferencesToUndefinedElementTypes().isEmpty());

    assertFalse(schemaValidator.allowRedefiningElements());

    assertTrue(schemaValidator.allowElementsWithoutNames());

    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());

    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());

    assertTrue(schemaValidator.useStrictOIDValidation());

    assertFalse(schemaValidator.allowNamesWithInitialDigit());

    assertFalse(schemaValidator.allowNamesWithInitialHyphen());

    assertFalse(schemaValidator.allowNamesWithUnderscore());

    assertFalse(schemaValidator.allowEmptyDescription());

    assertNotNull(schemaValidator.getAttributeSyntaxes());
    assertTrue(schemaValidator.getAttributeSyntaxes().isEmpty());

    assertFalse(schemaValidator.allowAttributeTypesWithoutSyntax());

    assertNotNull(schemaValidator.getMatchingRuleDefinitions());

    assertTrue(
         schemaValidator.allowAttributeTypesWithoutEqualityMatchingRule());

    assertTrue(schemaValidator.allowMultipleSuperiorObjectClasses());

    assertFalse(schemaValidator.allowStructuralObjectClassWithoutSuperior());

    assertFalse(schemaValidator.allowInvalidObjectClassInheritance());

    assertTrue(schemaValidator.allowCollectiveAttributes());

    assertTrue(schemaValidator.allowObsoleteElements());
  }



  /**
   * Tests to ensure that the default standard schema that ships with the LDAP
   * SDK is considered valid with the default settings.
   */
  @Test()
  public void testDefaultStandardSchema()
  {
    final SchemaValidator schemaValidator = new SchemaValidator();

    final File sourceRootDir = new File(System.getProperty("basedir"));
    final File schemaFile = StaticUtils.constructPath(sourceRootDir,
         "resource", "standard-schema.ldif");

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema = schemaValidator.validateSchema(schemaFile, null,
         errorMessages);

    assertNotNull(schema);

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests to ensure that the minimal schema is considered valid on its own.
   */
  @Test()
  public void testMinimalSchema()
  {
    final SchemaValidator schemaValidator = new SchemaValidator();

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema = schemaValidator.validateSchema(minimalSchemaFile,
         null, errorMessages);

    assertNotNull(schema);

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior with a directory containing multiple schema files,
   * including the use of a file name pattern.
   *
   * @throws  Exception  If an unexpected problem occurs.
    */
  @Test()
  public void testMultipleSchemaFilesInDirectory()
         throws Exception
  {
    final File schemaDir = createTempDir();

    final File schemaFile1 = new File(schemaDir, "01-first.ldif");
    StaticUtils.writeFile(schemaFile1, minimalSchemaLines);

    final File schemaFile2 = new File(schemaDir, "second.ldif");
    StaticUtils.writeFile(schemaFile2,
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "attributeTypes: ( 1.2.3.4 NAME 'test-at' " +
              "EQUALITY caseIgnoreMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )");

    SchemaValidator schemaValidator = new SchemaValidator();

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(schemaDir, null,
         errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("test-at"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setSchemaFileNamePattern(
         Pattern.compile("^\\d\\d-.+\\.ldif$"), true);

    schema = schemaValidator.validateSchema(schemaDir, null,
         errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNull(schema.getAttributeType("test-at"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setSchemaFileNamePattern(
         Pattern.compile("^\\d\\d-.+\\.ldif$"), false);

    schema = schemaValidator.validateSchema(schemaDir, null,
         errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNull(schema.getAttributeType("test-at"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setSchemaFileNamePattern(
         Pattern.compile("^a.*$"), true);

    schema = schemaValidator.validateSchema(schemaDir, null,
         errorMessages);

    assertNull(schema);

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setSchemaFileNamePattern(
         Pattern.compile("^a.*$"), false);

    schema = schemaValidator.validateSchema(schemaDir, null,
         errorMessages);

    assertNull(schema);

    assertFalse(errorMessages.isEmpty());


    assertTrue(schemaFile2.delete());

    schemaValidator = new SchemaValidator();
    schemaValidator.setSchemaFileNamePattern(
         Pattern.compile("^a.*$"), true);

    schema = schemaValidator.validateSchema(schemaFile1, null,
         errorMessages);


    assertNull(schema);

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests with a nonexistent path.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonexistentPath()
         throws Exception
  {
    final File schemaFile = createTempFile();
    assertTrue(schemaFile.delete());

    final SchemaValidator schemaValidator = new SchemaValidator();

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNull(schema);

    assertFalse(errorMessages.isEmpty());
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
    final File schemaFile = createTempFile();
    final SchemaValidator schemaValidator = new SchemaValidator();

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNull(schema);

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests with an empty directory.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyDirectory()
         throws Exception
  {
    final File schemaDir = createTempDir();
    final SchemaValidator schemaValidator = new SchemaValidator();

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema =
         schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNull(schema);

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests with a file that contains a malformed entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedLDIFFile()
         throws Exception
  {
    final File schemaFile = createTempFile("this is not a valid LDIF file");
    final SchemaValidator schemaValidator = new SchemaValidator();

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNull(schema);

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests with multiple entries in the same schema file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleEntriesPerFile()
         throws Exception
  {
    final File schemaFile = createTempFile();
    try (LDIFWriter writer = new LDIFWriter(schemaFile))
    {
      writer.writeEntry(minimalSchemaEntry);
      writer.writeEntry(new Entry(
           "dn: cn=schema",
           "objectClass: top",
           "objectClass: ldapSubEntry",
           "objectClass: subschema",
           "cn: schema",
           "attributeTypes: ( 1.2.3.4 NAME 'test-at' " +
                "EQUALITY caseIgnoreMatch " +
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"));
    }


    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowMultipleEntriesPerFile());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNull(schema.getAttributeType("test-at"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowMultipleEntriesPerFile(true);
    assertTrue(schemaValidator.allowMultipleEntriesPerFile());

    errorMessages.clear();
    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("test-at"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests with schema files in subdirectories.  In this case, there will be
   * one file in the specified directory and one file in a subdirectory.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSchemaFilesInSubdirectories()
         throws Exception
  {
    final File schemaDir = createTempDir();

    final File schemaFile1 = new File(schemaDir, "first.ldif");
    StaticUtils.writeFile(schemaFile1, minimalSchemaLines);

    final File subdirectory = new File(schemaDir, "subdirectory");
    assertTrue(subdirectory.mkdir());

    final File schemaFile2 = new File(subdirectory, "second.ldif");
    StaticUtils.writeFile(schemaFile2,
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "attributeTypes: ( 1.2.3.4 NAME 'test-at' " +
              "EQUALITY caseIgnoreMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )");


    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowSchemaFilesInSubDirectories());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNull(schema.getAttributeType("test-at"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowSchemaFilesInSubDirectories(true);
    assertTrue(schemaValidator.allowSchemaFilesInSubDirectories());

    errorMessages.clear();
    schema = schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("test-at"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests with schema files in subdirectories.  In this case, there will be
   * only files in subdirectories.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSchemaFilesOnlyInSubdirectories()
         throws Exception
  {
    final File schemaDir = createTempDir();

    final File subDir1 = new File(schemaDir, "subdirectory1");
    subDir1.mkdir();

    final File schemaFile1 = new File(subDir1, "first.ldif");
    StaticUtils.writeFile(schemaFile1, minimalSchemaLines);

    final File subDir2 = new File(schemaDir, "subdirectory2");
    subDir2.mkdir();

    final File schemaFile2 = new File(subDir2, "second.ldif");
    StaticUtils.writeFile(schemaFile2,
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "attributeTypes: ( 1.2.3.4 NAME 'test-at' " +
              "EQUALITY caseIgnoreMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )");


    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowSchemaFilesInSubDirectories());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNull(schema);

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowSchemaFilesInSubDirectories(true);
    assertTrue(schemaValidator.allowSchemaFilesInSubDirectories());

    errorMessages.clear();
    schema = schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("test-at"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior with regard to ensuring that the schema entry is valid.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEnsureSchemaEntryIsValid()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute("description", "test description");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.ensureSchemaEntryIsValid());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setEnsureSchemaEntryIsValid(false);
    assertFalse(schemaValidator.ensureSchemaEntryIsValid());

    errorMessages.clear();
    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has attribute syntax definitions
   * when they are not allowed.
   */
  @Test()
  public void testAttributeSyntaxNotAllowed()
  {
    final SchemaValidator schemaValidator = new SchemaValidator();
    assertEquals(schemaValidator.getAllowedSchemaElementTypes(),
         EnumSet.allOf(SchemaElementType.class));

    final Set<SchemaElementType> allowedElementTypes =
         EnumSet.allOf(SchemaElementType.class);
    allowedElementTypes.remove(SchemaElementType.ATTRIBUTE_SYNTAX);

    schemaValidator.setAllowedSchemaElementTypes(allowedElementTypes);
    assertEquals(schemaValidator.getAllowedSchemaElementTypes(),
         allowedElementTypes);

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema =
         schemaValidator.validateSchema(minimalSchemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that a malformed attribute syntax
   * definition.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedAttributeSyntax()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_ATTRIBUTE_TYPE, "malformed");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    final SchemaValidator schemaValidator = new SchemaValidator();

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has an attribute syntax with a
   * numeric OID that passes lenient validation but not strict validation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeSyntaxWithOIDNotStrictlyValid()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_ATTRIBUTE_SYNTAX,
         "( 1 DESC 'Not a strictly valid OID' )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertTrue(schemaValidator.useStrictOIDValidation());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeSyntax("1"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setOIDValidation(false, false, false);
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertFalse(schemaValidator.useStrictOIDValidation());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeSyntax("1"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an attribute syntax with a
   * non-numeric OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeSyntaxWithNonNumericOID()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_ATTRIBUTE_SYNTAX,
         "( non-numeric DESC 'Non-numeric OID' )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertTrue(schemaValidator.useStrictOIDValidation());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeSyntax("non-numeric"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setOIDValidation(false, true, false);
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertTrue(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertFalse(schemaValidator.useStrictOIDValidation());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeSyntax("non-numeric"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an attribute syntax with an
   * empty description.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeSyntaxWithEmptyDescription()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_ATTRIBUTE_SYNTAX,
         "( 1.2.3.4 DESC '' )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowEmptyDescription());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeSyntax("1.2.3.4"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowEmptyDescription(true);
    assertTrue(schemaValidator.allowEmptyDescription());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeSyntax("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a duplicate attribute syntax definition.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRedefinedAttributeSyntax()
         throws Exception
  {
    final File schemaDir = createTempDir();

    final File schemaFile1 = new File(schemaDir, "01-first.ldif");
    StaticUtils.writeFile(schemaFile1, minimalSchemaLines);

    final File schemaFile2 = new File(schemaDir, "second.ldif");
    StaticUtils.writeFile(schemaFile2,
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.3 DESC 'Attribute Type " +
              "Description' )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowRedefiningElements());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeSyntax("1.3.6.1.4.1.1466.115.121.1.3"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowRedefiningElements(true);
    assertTrue(schemaValidator.allowRedefiningElements());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeSyntax("1.3.6.1.4.1.1466.115.121.1.3"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has matching rule definitions
   * when they are not allowed.
   */
  @Test()
  public void testMatchingRuleNotAllowed()
  {
    final SchemaValidator schemaValidator = new SchemaValidator();
    assertEquals(schemaValidator.getAllowedSchemaElementTypes(),
         EnumSet.allOf(SchemaElementType.class));

    final Set<SchemaElementType> allowedElementTypes =
         EnumSet.allOf(SchemaElementType.class);
    allowedElementTypes.remove(SchemaElementType.MATCHING_RULE);

    schemaValidator.setAllowedSchemaElementTypes(allowedElementTypes);
    assertEquals(schemaValidator.getAllowedSchemaElementTypes(),
         allowedElementTypes);

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema =
         schemaValidator.validateSchema(minimalSchemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that a malformed matching rule
   * definition.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedMatchingRule()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_MATCHING_RULE, "malformed");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    final SchemaValidator schemaValidator = new SchemaValidator();

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has a matching rule with a
   * numeric OID that passes lenient validation but not strict validation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleWithOIDNotStrictlyValid()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_MATCHING_RULE,
         "( 1 NAME 'test-mr' " +
           "SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertTrue(schemaValidator.useStrictOIDValidation());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("1"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setOIDValidation(false, false, false);
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertFalse(schemaValidator.useStrictOIDValidation());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("1"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a matching rule with a
   * non-numeric OID that is its name followed by "-oid".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleWithNonNumericOIDUsingName()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_MATCHING_RULE,
         "( test-mr-oid NAME 'test-mr' " +
           "SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertTrue(schemaValidator.useStrictOIDValidation());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("test-mr-oid"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setOIDValidation(true, false, false);
    assertTrue(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertFalse(schemaValidator.useStrictOIDValidation());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("test-mr-oid"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a matching rule with a
   * non-numeric OID that is something other than its name followed by "-oid".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleWithNonNumericOIDNotUsingName()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_MATCHING_RULE,
         "( non-numeric-oid NAME 'test-mr' " +
           "SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertTrue(schemaValidator.useStrictOIDValidation());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("non-numeric-oid"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setOIDValidation(false, true, false);
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertTrue(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertFalse(schemaValidator.useStrictOIDValidation());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("non-numeric-oid"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a matching rule without a
   * name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleWithoutName()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_MATCHING_RULE,
         "( 1.2.3.4 SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.allowElementsWithoutNames());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowElementsWithoutNames(false);
    assertFalse(schemaValidator.allowElementsWithoutNames());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("1.2.3.4"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has a matching rule with a name
   * that starts with a digit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleNameStartsWithDigit()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_MATCHING_RULE,
         "( 1.2.3.4 NAME '1test-mr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNamesWithInitialDigit());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("1.2.3.4"));
    assertNotNull(schema.getMatchingRule("1test-mr"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowNamesWithInitialDigit(true);
    assertTrue(schemaValidator.allowNamesWithInitialDigit());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("1.2.3.4"));
    assertNotNull(schema.getMatchingRule("1test-mr"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a matching rule with a name
   * that starts with a hyphen.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleNameStartsWithHyphen()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_MATCHING_RULE,
         "( 1.2.3.4 NAME '-test-mr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNamesWithInitialHyphen());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("1.2.3.4"));
    assertNotNull(schema.getMatchingRule("-test-mr"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowNamesWithInitialHyphen(true);
    assertTrue(schemaValidator.allowNamesWithInitialHyphen());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("1.2.3.4"));
    assertNotNull(schema.getMatchingRule("-test-mr"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a matching rule with a name
   * that contains underscore characters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleNameContainsUnderscore()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_MATCHING_RULE,
         "( 1.2.3.4 NAME '_test_mr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNamesWithUnderscore());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("1.2.3.4"));
    assertNotNull(schema.getMatchingRule("_test_mr"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowNamesWithUnderscore(true);
    assertTrue(schemaValidator.allowNamesWithUnderscore());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("1.2.3.4"));
    assertNotNull(schema.getMatchingRule("_test_mr"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a matching rule with an
   * empty description.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleWithEmptyDescription()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_MATCHING_RULE,
         "( 1.2.3.4 NAME 'test-mr' DESC '' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowEmptyDescription());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("1.2.3.4"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowEmptyDescription(true);
    assertTrue(schemaValidator.allowEmptyDescription());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a matching rule that is
   * declared OBSOLETE.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleObsolete()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_MATCHING_RULE,
         "( 1.2.3.4 NAME 'test-mr' OBSOLETE " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.allowObsoleteElements());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowObsoleteElements(false);
    assertFalse(schemaValidator.allowObsoleteElements());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("1.2.3.4"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has a matching rule that has a
   * syntax OID that has a non-numeric OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleNonNumericSyntaxOID()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_ATTRIBUTE_SYNTAX,
         "( non-numeric-syntax-oid DESC 'Syntax with non-numeric OID' )");
    schemaEntry.addAttribute(Schema.ATTR_MATCHING_RULE,
         "( 1.2.3.4 NAME 'test-mr' " +
              "SYNTAX non-numeric-syntax-oid )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("1.2.3.4"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setOIDValidation(false, true, false);
    assertTrue(schemaValidator.allowNonNumericOIDsNotUsingName());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a matching rule that
   * references an undefined syntax.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleReferencingUndefinedSyntax()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "matchingRules: ( 1.2.3.4 NAME 'test-mr' SYNTAX 1.2.3.5 )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("1.2.3.4"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowReferencesToUndefinedElementTypes(
         SchemaElementType.ATTRIBUTE_SYNTAX);
    assertEquals(schemaValidator.getAllowReferencesToUndefinedElementTypes(),
         EnumSet.of(SchemaElementType.ATTRIBUTE_SYNTAX));

    errorMessages.clear();

    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a duplicate matching rule definition that has the
   * same OID but a different name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRedefinedMatchingRuleWithOID()
         throws Exception
  {
    final File schemaDir = createTempDir();

    final File schemaFile1 = new File(schemaDir, "01-first.ldif");
    StaticUtils.writeFile(schemaFile1, minimalSchemaLines);

    final File schemaFile2 = new File(schemaDir, "second.ldif");
    StaticUtils.writeFile(schemaFile2,
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "matchingRules: ( 1.3.6.1.4.1.1466.109.114.2 " +
              "NAME 'test-mr' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )");


    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowRedefiningElements());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("1.3.6.1.4.1.1466.109.114.2"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowRedefiningElements(true);
    assertTrue(schemaValidator.allowRedefiningElements());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("1.3.6.1.4.1.1466.109.114.2"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a duplicate matching rule definition that has a
   * different name but the same OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRedefinedMatchingRuleWithName()
         throws Exception
  {
    final File schemaDir = createTempDir();

    final File schemaFile1 = new File(schemaDir, "01-first.ldif");
    StaticUtils.writeFile(schemaFile1, minimalSchemaLines);

    final File schemaFile2 = new File(schemaDir, "second.ldif");
    StaticUtils.writeFile(schemaFile2,
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "matchingRules: ( 1.2.3.4 NAME 'caseIgnoreIA5Match' " +
               "SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowRedefiningElements());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("1.3.6.1.4.1.1466.109.114.2"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowRedefiningElements(true);
    assertTrue(schemaValidator.allowRedefiningElements());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("1.3.6.1.4.1.1466.109.114.2"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has attribute type definitions
   * when they are not allowed.
   */
  @Test()
  public void testAttributeTypeNotAllowed()
  {
    final SchemaValidator schemaValidator = new SchemaValidator();
    assertEquals(schemaValidator.getAllowedSchemaElementTypes(),
         EnumSet.allOf(SchemaElementType.class));

    final Set<SchemaElementType> allowedElementTypes =
         EnumSet.allOf(SchemaElementType.class);
    allowedElementTypes.remove(SchemaElementType.ATTRIBUTE_TYPE);

    schemaValidator.setAllowedSchemaElementTypes(allowedElementTypes);
    assertEquals(schemaValidator.getAllowedSchemaElementTypes(),
         allowedElementTypes);

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema =
         schemaValidator.validateSchema(minimalSchemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that a malformed attribute type
   * definition.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedAttributeType()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_ATTRIBUTE_SYNTAX, "malformed");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    final SchemaValidator schemaValidator = new SchemaValidator();

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has an attribute type with a
   * numeric OID that passes lenient validation but not strict validation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeWithOIDNotStrictlyValid()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_ATTRIBUTE_TYPE,
         "( 1 NAME 'test-at' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertTrue(schemaValidator.useStrictOIDValidation());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setOIDValidation(false, false, false);
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertFalse(schemaValidator.useStrictOIDValidation());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an attribute type with a
   * non-numeric OID that is its name followed by "-oid".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeWithNonNumericOIDUsingName()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_ATTRIBUTE_TYPE,
         "( test-at-oid NAME 'test-at' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertTrue(schemaValidator.useStrictOIDValidation());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("test-at-oid"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setOIDValidation(true, false, false);
    assertTrue(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertFalse(schemaValidator.useStrictOIDValidation());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("test-at-oid"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an attribute type with a
   * non-numeric OID that is something other than its name followed by "-oid".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeWithNonNumericOIDNotUsingName()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_ATTRIBUTE_TYPE,
         "( non-numeric-oid NAME 'test-at' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertTrue(schemaValidator.useStrictOIDValidation());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("non-numeric-oid"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setOIDValidation(false, true, false);
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertTrue(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertFalse(schemaValidator.useStrictOIDValidation());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("non-numeric-oid"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an attribute type without a
   * name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeWithoutName()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_ATTRIBUTE_TYPE,
         "( 1.2.3.4 SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.allowElementsWithoutNames());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowElementsWithoutNames(false);
    assertFalse(schemaValidator.allowElementsWithoutNames());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has an attribute type with a
   * name that starts with a digit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeNameStartsWithDigit()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_ATTRIBUTE_TYPE,
         "( 1.2.3.4 NAME '1test-at' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNamesWithInitialDigit());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));
    assertNotNull(schema.getAttributeType("1test-at"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowNamesWithInitialDigit(true);
    assertTrue(schemaValidator.allowNamesWithInitialDigit());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));
    assertNotNull(schema.getAttributeType("1test-at"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an attribute type with a
   * name that starts with a hyphen.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeNameStartsWithHyphen()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_ATTRIBUTE_TYPE,
         "( 1.2.3.4 NAME '-test-at' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNamesWithInitialHyphen());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));
    assertNotNull(schema.getAttributeType("-test-at"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowNamesWithInitialHyphen(true);
    assertTrue(schemaValidator.allowNamesWithInitialHyphen());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));
    assertNotNull(schema.getAttributeType("-test-at"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an attribute type with a
   * name that contains underscore characters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeNameContainsUnderscore()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_ATTRIBUTE_TYPE,
         "( 1.2.3.4 NAME '_test_at' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNamesWithUnderscore());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));
    assertNotNull(schema.getAttributeType("_test_at"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowNamesWithUnderscore(true);
    assertTrue(schemaValidator.allowNamesWithUnderscore());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));
    assertNotNull(schema.getAttributeType("_test_at"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an attribute type with an
   * empty description.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeWithEmptyDescription()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_ATTRIBUTE_TYPE,
         "( 1.2.3.4 NAME 'test-at' DESC '' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowEmptyDescription());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowEmptyDescription(true);
    assertTrue(schemaValidator.allowEmptyDescription());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an attribute type that is
   * declared OBSOLETE.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeObsolete()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_ATTRIBUTE_TYPE,
         "( 1.2.3.4 NAME 'test-at' OBSOLETE " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.allowObsoleteElements());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowObsoleteElements(false);
    assertFalse(schemaValidator.allowObsoleteElements());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has an attribute type that
   * references an undefined superior type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeUndefinedSuperior()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "attributeTypes: ( 1.2.3.4 NAME 'test-at' SUP undefined-at " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowReferencesToUndefinedElementTypes(
         SchemaElementType.ATTRIBUTE_TYPE);
    assertFalse(
         schemaValidator.getAllowReferencesToUndefinedElementTypes().isEmpty());
    assertEquals(schemaValidator.getAllowReferencesToUndefinedElementTypes(),
         EnumSet.of(SchemaElementType.ATTRIBUTE_TYPE));

    errorMessages.clear();

    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that is missing an equality matching
   * rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeWithoutEqualityMatchingRule()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_ATTRIBUTE_TYPE,
         "( 1.2.3.4 NAME 'test-at' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(
         schemaValidator.allowAttributeTypesWithoutEqualityMatchingRule());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowAttributeTypesWithoutEqualityMatchingRule(false);
    assertFalse(
         schemaValidator.allowAttributeTypesWithoutEqualityMatchingRule());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has an attribute type that has
   * an undefined equality matching rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeUndefinedEqualityMatchingRule()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "attributeTypes: ( 1.2.3.4 NAME 'test-at' EQUALITY undefined-mr " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowReferencesToUndefinedElementTypes(
         SchemaElementType.MATCHING_RULE);
    assertFalse(
         schemaValidator.getAllowReferencesToUndefinedElementTypes().isEmpty());
    assertEquals(schemaValidator.getAllowReferencesToUndefinedElementTypes(),
         EnumSet.of(SchemaElementType.MATCHING_RULE));

    errorMessages.clear();

    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an attribute type that has
   * an undefined ordering matching rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeUndefinedOrderingMatchingRule()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "attributeTypes: ( 1.2.3.4 NAME 'test-at' ORDERING undefined-mr " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowReferencesToUndefinedElementTypes(
         SchemaElementType.MATCHING_RULE);
    assertFalse(
         schemaValidator.getAllowReferencesToUndefinedElementTypes().isEmpty());
    assertEquals(schemaValidator.getAllowReferencesToUndefinedElementTypes(),
         EnumSet.of(SchemaElementType.MATCHING_RULE));

    errorMessages.clear();

    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an attribute type that has
   * an undefined substring matching rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeUndefinedSubstringMatchingRule()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "attributeTypes: ( 1.2.3.4 NAME 'test-at' SUBSTR undefined-mr " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowReferencesToUndefinedElementTypes(
         SchemaElementType.MATCHING_RULE);
    assertFalse(
         schemaValidator.getAllowReferencesToUndefinedElementTypes().isEmpty());
    assertEquals(schemaValidator.getAllowReferencesToUndefinedElementTypes(),
         EnumSet.of(SchemaElementType.MATCHING_RULE));

    errorMessages.clear();

    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an attribute type that has a
   * syntax OID that has a non-numeric OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeNonNumericSyntaxOID()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_ATTRIBUTE_SYNTAX,
         "( non-numeric-syntax-oid DESC 'Syntax with non-numeric OID' )");
    schemaEntry.addAttribute(Schema.ATTR_ATTRIBUTE_TYPE,
         "( 1.2.3.4 NAME 'test-at' " +
              "SYNTAX non-numeric-syntax-oid )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setOIDValidation(false, true, false);
    assertTrue(schemaValidator.allowNonNumericOIDsNotUsingName());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an attribute type that
   * references an undefined syntax.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeReferencingUndefinedSyntax()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "attributeTypes: ( 1.2.3.4 NAME 'test-at' SYNTAX 1.2.3.5 )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowReferencesToUndefinedElementTypes(
         SchemaElementType.ATTRIBUTE_SYNTAX);
    assertEquals(schemaValidator.getAllowReferencesToUndefinedElementTypes(),
         EnumSet.of(SchemaElementType.ATTRIBUTE_SYNTAX));

    errorMessages.clear();

    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an attribute type that does
   * not declare a syntax and does not have a superior type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeWithoutSyntaxOrSuperior()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_ATTRIBUTE_TYPE,
         "( 1.2.3.4 NAME 'test-at' )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowAttributeTypesWithoutSyntax());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowAttributeTypesWithoutSyntax(true);
    assertTrue(schemaValidator.allowAttributeTypesWithoutSyntax());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an attribute type that is
   * declared COLLECTIVE.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCollectiveAttributeType()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_ATTRIBUTE_TYPE,
         "( 1.2.3.4 NAME 'test-at' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 " +
              "COLLECTIVE )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.allowCollectiveAttributes());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowCollectiveAttributes(false);
    assertFalse(schemaValidator.allowCollectiveAttributes());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has an attribute type that is
   * declared NO-USER-MODIFICATION without an operational usage.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonOperationalAttributeTypeWithNoUserModification()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_ATTRIBUTE_TYPE,
         "( 1.2.3.4 NAME 'test-at' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 " +
              "NO-USER-MODIFICATION )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    final SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.allowCollectiveAttributes());

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getAttributeType("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a duplicate attribute type definition that has the
   * same OID but a different name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRedefinedAttributeTypeWithOID()
         throws Exception
  {
    final File schemaDir = createTempDir();

    final File schemaFile1 = new File(schemaDir, "01-first.ldif");
    StaticUtils.writeFile(schemaFile1, minimalSchemaLines);

    final File schemaFile2 = new File(schemaDir, "second.ldif");
    StaticUtils.writeFile(schemaFile2,
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "attributeTypes: ( 0.9.2342.19200300.100.1.25 NAME 'test-at' " +
              "EQUALITY caseIgnoreIA5Match " +
              "SUBSTR caseIgnoreIA5SubstringsMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowRedefiningElements());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("0.9.2342.19200300.100.1.25"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowRedefiningElements(true);
    assertTrue(schemaValidator.allowRedefiningElements());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("0.9.2342.19200300.100.1.25"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a duplicate attribute type definition that has a
   * different name but the same OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRedefinedAttributeTypeWithName()
         throws Exception
  {
    final File schemaDir = createTempDir();

    final File schemaFile1 = new File(schemaDir, "01-first.ldif");
    StaticUtils.writeFile(schemaFile1, minimalSchemaLines);

    final File schemaFile2 = new File(schemaDir, "second.ldif");
    StaticUtils.writeFile(schemaFile2,
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "attributeTypes: ( 1.2.3.4 NAME 'dc' " +
              "EQUALITY caseIgnoreIA5Match " +
              "SUBSTR caseIgnoreIA5SubstringsMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowRedefiningElements());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("1.2.3.4"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowRedefiningElements(true);
    assertTrue(schemaValidator.allowRedefiningElements());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has object class definitions
   * when they are not allowed.
   */
  @Test()
  public void testObjectClassNotAllowed()
  {
    final SchemaValidator schemaValidator = new SchemaValidator();
    assertEquals(schemaValidator.getAllowedSchemaElementTypes(),
         EnumSet.allOf(SchemaElementType.class));

    final Set<SchemaElementType> allowedElementTypes =
         EnumSet.allOf(SchemaElementType.class);
    allowedElementTypes.remove(SchemaElementType.OBJECT_CLASS);

    schemaValidator.setAllowedSchemaElementTypes(allowedElementTypes);
    assertEquals(schemaValidator.getAllowedSchemaElementTypes(),
         allowedElementTypes);

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema =
         schemaValidator.validateSchema(minimalSchemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that a malformed object class
   * definition.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedObjectClass()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_OBJECT_CLASS, "malformed");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    final SchemaValidator schemaValidator = new SchemaValidator();

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has an object class with a
   * numeric OID that passes lenient validation but not strict validation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassWithOIDNotStrictlyValid()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_OBJECT_CLASS,
         "( 1 NAME 'test-oc' SUP top MAY cn )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertTrue(schemaValidator.useStrictOIDValidation());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setOIDValidation(false, false, false);
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertFalse(schemaValidator.useStrictOIDValidation());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an object class with a
   * non-numeric OID that is its name followed by "-oid".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassWithNonNumericOIDUsingName()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_OBJECT_CLASS,
         "( test-oc-oid NAME 'test-oc' SUP top MAY cn )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertTrue(schemaValidator.useStrictOIDValidation());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("test-oc-oid"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setOIDValidation(true, false, false);
    assertTrue(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertFalse(schemaValidator.useStrictOIDValidation());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("test-oc-oid"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an object class with a
   * non-numeric OID that is something other than its name followed by "-oid".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassWithNonNumericOIDNotUsingName()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_OBJECT_CLASS,
         "( non-numeric-oid NAME 'test-oc' SUP top MAY cn )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertTrue(schemaValidator.useStrictOIDValidation());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("non-numeric-oid"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setOIDValidation(false, true, false);
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertTrue(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertFalse(schemaValidator.useStrictOIDValidation());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("non-numeric-oid"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an object class without a
   * name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassWithoutName()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_OBJECT_CLASS,
         "( 1.2.3.4 SUP top MAY cn )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.allowElementsWithoutNames());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowElementsWithoutNames(false);
    assertFalse(schemaValidator.allowElementsWithoutNames());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has an object class with a
   * name that starts with a digit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassNameStartsWithDigit()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_OBJECT_CLASS,
         "( 1.2.3.4 NAME '1test-oc' SUP top MAY cn )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNamesWithInitialDigit());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));
    assertNotNull(schema.getObjectClass("1test-oc"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowNamesWithInitialDigit(true);
    assertTrue(schemaValidator.allowNamesWithInitialDigit());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));
    assertNotNull(schema.getObjectClass("1test-oc"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an object class with a
   * name that starts with a hyphen.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassNameStartsWithHyphen()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_OBJECT_CLASS,
         "( 1.2.3.4 NAME '-test-oc' SUP top MAY cn )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNamesWithInitialHyphen());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));
    assertNotNull(schema.getObjectClass("-test-oc"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowNamesWithInitialHyphen(true);
    assertTrue(schemaValidator.allowNamesWithInitialHyphen());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));
    assertNotNull(schema.getObjectClass("-test-oc"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an object class with a
   * name that contains underscore characters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassNameContainsUnderscore()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_OBJECT_CLASS,
         "( 1.2.3.4 NAME '_test_oc' SUP top MAY cn )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNamesWithUnderscore());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));
    assertNotNull(schema.getObjectClass("_test_oc"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowNamesWithUnderscore(true);
    assertTrue(schemaValidator.allowNamesWithUnderscore());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));
    assertNotNull(schema.getObjectClass("_test_oc"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an object class with an
   * empty description.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassWithEmptyDescription()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_OBJECT_CLASS,
         "( 1.2.3.4 NAME 'test-oc' DESC '' SUP top MAY cn )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowEmptyDescription());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowEmptyDescription(true);
    assertTrue(schemaValidator.allowEmptyDescription());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an object class that is
   * declared OBSOLETE.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassObsolete()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_OBJECT_CLASS,
         "( 1.2.3.4 NAME 'test-oc' OBSOLETE SUP top MAY cn )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.allowObsoleteElements());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowObsoleteElements(false);
    assertFalse(schemaValidator.allowObsoleteElements());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has an object class that
   * references an undefined superior class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassUndefinedSuperior()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "objectClasses: ( 1.2.3.4 NAME 'test-oc' SUP undefined-oc MAY cn )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowReferencesToUndefinedElementTypes(
         SchemaElementType.OBJECT_CLASS);
    assertFalse(
         schemaValidator.getAllowReferencesToUndefinedElementTypes().isEmpty());
    assertEquals(schemaValidator.getAllowReferencesToUndefinedElementTypes(),
         EnumSet.of(SchemaElementType.OBJECT_CLASS));

    errorMessages.clear();

    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an object class with
   * multiple superior classes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassWithMultipleSuperiors()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_OBJECT_CLASS,
         "( 1.2.3.4 NAME 'test-oc' OBSOLETE SUP ( top $ domain ) MAY cn )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.allowMultipleSuperiorObjectClasses());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowMultipleSuperiorObjectClasses(false);
    assertFalse(schemaValidator.allowMultipleSuperiorObjectClasses());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has an implicitly structural
   * object class that inherits from an auxiliary class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassImplicitStructuralInheritsFromAuxiliary()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "objectClasses: ( 1.2.3.4 NAME 'test-oc' SUP subschema MAY cn )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowInvalidObjectClassInheritance());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowInvalidObjectClassInheritance(true);
    assertTrue(schemaValidator.allowInvalidObjectClassInheritance());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an explicitly structural
   * object class that inherits from an auxiliary class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassExplicitStructuralInheritsFromAuxiliary()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "objectClasses: ( 1.2.3.4 NAME 'test-oc' SUP subschema STRUCTURAL " +
              "MAY cn )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowInvalidObjectClassInheritance());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowInvalidObjectClassInheritance(true);
    assertTrue(schemaValidator.allowInvalidObjectClassInheritance());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an auxiliary object class
   * that inherits from a structural class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassAuxiliaryInheritsFromStructural()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "objectClasses: ( 1.2.3.4 NAME 'test-oc' SUP domain AUXILIARY " +
              "MAY cn )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowInvalidObjectClassInheritance());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowInvalidObjectClassInheritance(true);
    assertTrue(schemaValidator.allowInvalidObjectClassInheritance());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an abstract object class
   * that inherits from a structural class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassAbstractInheritsFromStructural()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "objectClasses: ( 1.2.3.4 NAME 'test-oc' SUP domain ABSTRACT " +
              "MAY cn )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowInvalidObjectClassInheritance());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowInvalidObjectClassInheritance(true);
    assertTrue(schemaValidator.allowInvalidObjectClassInheritance());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an abstract object class
   * that inherits from an auxiliary class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassAbstractInheritsFromAuxiliary()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "objectClasses: ( 1.2.3.4 NAME 'test-oc' SUP subschema ABSTRACT " +
              "MAY cn )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowInvalidObjectClassInheritance());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowInvalidObjectClassInheritance(true);
    assertTrue(schemaValidator.allowInvalidObjectClassInheritance());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an implicitly structural
   * object class that does not reference a superior class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassImplicitStructuralMissingSuperior()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "objectClasses: ( 1.2.3.4 NAME 'test-oc' MAY cn )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowStructuralObjectClassWithoutSuperior());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowStructuralObjectClassWithoutSuperior(true);
    assertTrue(schemaValidator.allowStructuralObjectClassWithoutSuperior());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an explicitly structural
   * object class that does not reference a superior class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassExplicitStructuralMissingSuperior()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "objectClasses: ( 1.2.3.4 NAME 'test-oc' STRUCTURAL MAY cn )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowStructuralObjectClassWithoutSuperior());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowStructuralObjectClassWithoutSuperior(true);
    assertTrue(schemaValidator.allowStructuralObjectClassWithoutSuperior());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an object class that
   * references an undefined required attribute type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassUndefinedRequiredAttribute()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "objectClasses: ( 1.2.3.4 NAME 'test-oc' SUP top MUST undefined-at )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowReferencesToUndefinedElementTypes(
         SchemaElementType.ATTRIBUTE_TYPE);
    assertFalse(
         schemaValidator.getAllowReferencesToUndefinedElementTypes().isEmpty());
    assertEquals(schemaValidator.getAllowReferencesToUndefinedElementTypes(),
         EnumSet.of(SchemaElementType.ATTRIBUTE_TYPE));

    errorMessages.clear();

    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an object class that
   * references an undefined optional attribute type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassUndefinedOptionalAttribute()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "objectClasses: ( 1.2.3.4 NAME 'test-oc' SUP top MAY undefined-at )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowReferencesToUndefinedElementTypes(
         SchemaElementType.ATTRIBUTE_TYPE);
    assertFalse(
         schemaValidator.getAllowReferencesToUndefinedElementTypes().isEmpty());
    assertEquals(schemaValidator.getAllowReferencesToUndefinedElementTypes(),
         EnumSet.of(SchemaElementType.ATTRIBUTE_TYPE));

    errorMessages.clear();

    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has an object class that
   * includes the same attribute type in both the required and optional sets.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassAttributeBothRequiredAndOptional()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "objectClasses: ( 1.2.3.4 NAME 'test-oc' SUP top MUST cn MAY cn )");

    final SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a duplicate object class definition that has the
   * same OID but a different name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRedefinedObjectClassWithOID()
         throws Exception
  {
    final File schemaDir = createTempDir();

    final File schemaFile1 = new File(schemaDir, "01-first.ldif");
    StaticUtils.writeFile(schemaFile1, minimalSchemaLines);

    final File schemaFile2 = new File(schemaDir, "second.ldif");
    StaticUtils.writeFile(schemaFile2,
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "objectClasses: ( 0.9.2342.19200300.100.4.13 NAME 'test-oc' SUP top " +
              "STRUCTURAL MUST dc )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowRedefiningElements());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getObjectClass("0.9.2342.19200300.100.4.13"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowRedefiningElements(true);
    assertTrue(schemaValidator.allowRedefiningElements());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getObjectClass("0.9.2342.19200300.100.4.13"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a duplicate object class definition that has a
   * different name but the same OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRedefinedObjectClassWithName()
         throws Exception
  {
    final File schemaDir = createTempDir();

    final File schemaFile1 = new File(schemaDir, "01-first.ldif");
    StaticUtils.writeFile(schemaFile1, minimalSchemaLines);

    final File schemaFile2 = new File(schemaDir, "second.ldif");
    StaticUtils.writeFile(schemaFile2,
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "objectClasses: ( 1.2.3.4 NAME 'domain' SUP top " +
              "STRUCTURAL MUST dc )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowRedefiningElements());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowRedefiningElements(true);
    assertTrue(schemaValidator.allowRedefiningElements());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getObjectClass("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has name form definitions
   * when they are not allowed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormNotAllowed()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM,
         "( 1.2.3.4 NAME 'test-nf' OC domain MUST dc )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    final SchemaValidator schemaValidator = new SchemaValidator();
    assertEquals(schemaValidator.getAllowedSchemaElementTypes(),
         EnumSet.allOf(SchemaElementType.class));

    final Set<SchemaElementType> allowedElementTypes =
         EnumSet.allOf(SchemaElementType.class);
    allowedElementTypes.remove(SchemaElementType.NAME_FORM);

    schemaValidator.setAllowedSchemaElementTypes(allowedElementTypes);
    assertEquals(schemaValidator.getAllowedSchemaElementTypes(),
         allowedElementTypes);

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that a malformed name form
   * definition.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedNameForm()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM, "malformed");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    final SchemaValidator schemaValidator = new SchemaValidator();

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has a name form with a numeric
   * OID that passes lenient validation but not strict validation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormWithOIDNotStrictlyValid()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM,
         "( 1 NAME 'test-nf' OC domain MUST dc )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertTrue(schemaValidator.useStrictOIDValidation());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getNameFormByName("1"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setOIDValidation(false, false, false);
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertFalse(schemaValidator.useStrictOIDValidation());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getNameFormByName("1"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a name form with a
   * non-numeric OID that is its name followed by "-oid".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormWithNonNumericOIDUsingName()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM,
         "( test-nf-oid NAME 'test-nf' OC domain MUST dc )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertTrue(schemaValidator.useStrictOIDValidation());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getNameFormByName("test-nf-oid"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setOIDValidation(true, false, false);
    assertTrue(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertFalse(schemaValidator.useStrictOIDValidation());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getNameFormByName("test-nf-oid"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a name form with a
   * non-numeric OID that is something other than its name followed by "-oid".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormWithNonNumericOIDNotUsingName()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM,
         "( non-numeric-oid NAME 'test-nf' OC domain MUST dc )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertTrue(schemaValidator.useStrictOIDValidation());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getNameFormByName("non-numeric-oid"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setOIDValidation(false, true, false);
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertTrue(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertFalse(schemaValidator.useStrictOIDValidation());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getNameFormByName("non-numeric-oid"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a name form without a name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormWithoutName()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM,
         "( 1.2.3.4 OC domain MUST dc )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.allowElementsWithoutNames());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getNameFormByName("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowElementsWithoutNames(false);
    assertFalse(schemaValidator.allowElementsWithoutNames());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getNameFormByName("1.2.3.4"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has a name form with a
   * name that starts with a digit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormNameStartsWithDigit()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM,
         "( 1.2.3.4 NAME '1test-nf' OC domain MUST dc )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNamesWithInitialDigit());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getNameFormByName("1.2.3.4"));
    assertNotNull(schema.getNameFormByName("1test-nf"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowNamesWithInitialDigit(true);
    assertTrue(schemaValidator.allowNamesWithInitialDigit());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getNameFormByName("1.2.3.4"));
    assertNotNull(schema.getNameFormByName("1test-nf"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a name form with a
   * name that starts with a hyphen.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormNameStartsWithHyphen()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM,
         "( 1.2.3.4 NAME '-test-nf' OC domain MUST dc )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNamesWithInitialHyphen());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getNameFormByName("1.2.3.4"));
    assertNotNull(schema.getNameFormByName("-test-nf"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowNamesWithInitialHyphen(true);
    assertTrue(schemaValidator.allowNamesWithInitialHyphen());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getNameFormByName("1.2.3.4"));
    assertNotNull(schema.getNameFormByName("-test-nf"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a name form with a
   * name that contains underscore characters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormNameContainsUnderscore()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM,
         "( 1.2.3.4 NAME '_test_nf' OC domain MUST dc )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNamesWithUnderscore());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getNameFormByName("1.2.3.4"));
    assertNotNull(schema.getNameFormByName("_test_nf"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowNamesWithUnderscore(true);
    assertTrue(schemaValidator.allowNamesWithUnderscore());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getNameFormByName("1.2.3.4"));
    assertNotNull(schema.getNameFormByName("_test_nf"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a name form with an
   * empty description.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormWithEmptyDescription()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM,
         "( 1.2.3.4 NAME 'test-nf' DESC '' OC domain MUST dc )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowEmptyDescription());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getNameFormByName("1.2.3.4"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowEmptyDescription(true);
    assertTrue(schemaValidator.allowEmptyDescription());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getNameFormByName("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a name form that is
   * declared OBSOLETE.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormObsolete()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM,
         "( 1.2.3.4 NAME 'test-nf' OBSOLETE OC domain MUST dc )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.allowObsoleteElements());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getNameFormByName("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowObsoleteElements(false);
    assertFalse(schemaValidator.allowObsoleteElements());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getNameFormByName("1.2.3.4"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has a name form that references
   * an undefined structural object class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormUndefinedStructuralClass()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "nameForms: ( 1.2.3.4 NAME 'test-nf' OC undefined MUST cn )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getNameFormByName("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowReferencesToUndefinedElementTypes(
         SchemaElementType.OBJECT_CLASS);
    assertFalse(
         schemaValidator.getAllowReferencesToUndefinedElementTypes().isEmpty());
    assertEquals(schemaValidator.getAllowReferencesToUndefinedElementTypes(),
         EnumSet.of(SchemaElementType.OBJECT_CLASS));

    errorMessages.clear();

    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getNameFormByName("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a name form that references
   * an object class that is not structural.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormObjectClassNotStructural()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "nameForms: ( 1.2.3.4 NAME 'test-nf' OC subschema MUST cn )");

    final SchemaValidator schemaValidator = new SchemaValidator();
    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getNameFormByName("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a name form that references
   * an undefined required attribute type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormReferencesUndefinedRequiredAttribute()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "nameForms: ( 1.2.3.4 NAME 'test-nf' OC domain MUST undefined )");


    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getNameFormByName("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowReferencesToUndefinedElementTypes(
         SchemaElementType.ATTRIBUTE_TYPE);
    assertFalse(
         schemaValidator.getAllowReferencesToUndefinedElementTypes().isEmpty());
    assertEquals(schemaValidator.getAllowReferencesToUndefinedElementTypes(),
         EnumSet.of(SchemaElementType.ATTRIBUTE_TYPE));

    errorMessages.clear();

    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getNameFormByName("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a name form that references
   * a required attribute type this is not permitted by the structural class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormReferencesRequiredAttributeNotPermittedByOC()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "nameForms: ( 1.2.3.4 NAME 'test-nf' OC domain MUST cn )");


    final SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getNameFormByName("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a name form that references
   * an undefined optional attribute type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormReferencesUndefinedOptionalAttribute()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "nameForms: ( 1.2.3.4 NAME 'test-nf' OC domain MUST dc " +
              "MAY undefined )");


    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getNameFormByName("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowReferencesToUndefinedElementTypes(
         SchemaElementType.ATTRIBUTE_TYPE);
    assertFalse(
         schemaValidator.getAllowReferencesToUndefinedElementTypes().isEmpty());
    assertEquals(schemaValidator.getAllowReferencesToUndefinedElementTypes(),
         EnumSet.of(SchemaElementType.ATTRIBUTE_TYPE));

    errorMessages.clear();

    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getNameFormByName("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a name form that includes
   * the same attribute in both the required and optional sets.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormAttrBothRequiredAndOptional()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "nameForms: ( 1.2.3.4 NAME 'test-nf' OC domain MUST dc MAY dc )");


    final SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getNameFormByName("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a duplicate name form definition that has the
   * same OID but a different name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRedefinedNameFormWithOID()
         throws Exception
  {
    final File schemaDir = createTempDir();

    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM,
         "( 1.2.3.4 NAME 'test-nf-1' OC domain MUST dc )");

    final File schemaFile1 = new File(schemaDir, "01-first.ldif");
    StaticUtils.writeFile(schemaFile1, schemaEntry.toLDIF());

    final File schemaFile2 = new File(schemaDir, "second.ldif");
    StaticUtils.writeFile(schemaFile2,
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "nameForms: ( 1.2.3.4 NAME 'test-nf-2' OC ldapSubEntry MUST cn )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowRedefiningElements());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getNameFormByName("1.2.3.4"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowRedefiningElements(true);
    assertTrue(schemaValidator.allowRedefiningElements());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getNameFormByName("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a duplicate name form definition that has the
   * same name but a different OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRedefinedNameFormWithName()
         throws Exception
  {
    final File schemaDir = createTempDir();

    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM,
         "( 1.2.3.4 NAME 'test-nf' OC domain MUST dc )");

    final File schemaFile1 = new File(schemaDir, "01-first.ldif");
    StaticUtils.writeFile(schemaFile1, schemaEntry.toLDIF());

    final File schemaFile2 = new File(schemaDir, "second.ldif");
    StaticUtils.writeFile(schemaFile2,
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "nameForms: ( 1.2.3.5 NAME 'test-nf' OC ldapSubEntry MUST cn )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowRedefiningElements());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getNameFormByName("1.2.3.4"));
    assertNotNull(schema.getNameFormByName("1.2.3.5"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowRedefiningElements(true);
    assertTrue(schemaValidator.allowRedefiningElements());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getNameFormByName("1.2.3.4"));
    assertNotNull(schema.getNameFormByName("1.2.3.5"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a duplicate name form definition that has the
   * same structural class but different names and OIDs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRedefinedNameFormWithStructuralClass()
         throws Exception
  {
    final File schemaDir = createTempDir();

    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM,
         "( 1.2.3.4 NAME 'test-nf-1' OC domain MUST dc )");

    final File schemaFile1 = new File(schemaDir, "01-first.ldif");
    StaticUtils.writeFile(schemaFile1, schemaEntry.toLDIF());

    final File schemaFile2 = new File(schemaDir, "second.ldif");
    StaticUtils.writeFile(schemaFile2,
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "nameForms: ( 1.2.3.5 NAME 'test-nf-2' OC domain MUST dc )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowRedefiningElements());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getNameFormByName("1.2.3.4"));
    assertNotNull(schema.getNameFormByName("1.2.3.5"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowRedefiningElements(true);
    assertTrue(schemaValidator.allowRedefiningElements());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getNameFormByName("1.2.3.4"));
    assertNotNull(schema.getNameFormByName("1.2.3.5"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has DIT content rule definitions
   * when they are not allowed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleNotAllowed()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_DIT_CONTENT_RULE,
         "( 0.9.2342.19200300.100.4.13 NAME 'test-dcr' MAY cn )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    final SchemaValidator schemaValidator = new SchemaValidator();
    assertEquals(schemaValidator.getAllowedSchemaElementTypes(),
         EnumSet.allOf(SchemaElementType.class));

    final Set<SchemaElementType> allowedElementTypes =
         EnumSet.allOf(SchemaElementType.class);
    allowedElementTypes.remove(SchemaElementType.DIT_CONTENT_RULE);

    schemaValidator.setAllowedSchemaElementTypes(allowedElementTypes);
    assertEquals(schemaValidator.getAllowedSchemaElementTypes(),
         allowedElementTypes);

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that a malformed DIT content rule
   * definition.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedDITContentRule()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_DIT_CONTENT_RULE, "malformed");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    final SchemaValidator schemaValidator = new SchemaValidator();

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has a DIT content rule with a
   * numeric OID that passes lenient validation but not strict validation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleWithOIDNotStrictlyValid()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_OBJECT_CLASS,
         "( 1 NAME 'test-oc' SUP top MAY cn )");
    schemaEntry.addAttribute(Schema.ATTR_DIT_CONTENT_RULE,
         "( 1 NAME 'test-dcr' MAY cn )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertTrue(schemaValidator.useStrictOIDValidation());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1"));
    assertNotNull(schema.getDITContentRule("1"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setOIDValidation(false, false, false);
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertFalse(schemaValidator.useStrictOIDValidation());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1"));
    assertNotNull(schema.getDITContentRule("1"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a DIT content rule with a
   * non-numeric OID that is its name followed by "-oid".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleWithNonNumericOIDUsingName()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_OBJECT_CLASS,
         "( test-oc-oid NAME 'test-oc' SUP top MAY cn )");
    schemaEntry.addAttribute(Schema.ATTR_DIT_CONTENT_RULE,
         "( test-oc-oid NAME 'test-oc' MAY cn )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertTrue(schemaValidator.useStrictOIDValidation());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("test-oc-oid"));
    assertNotNull(schema.getDITContentRule("test-oc-oid"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setOIDValidation(true, false, false);
    assertTrue(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertFalse(schemaValidator.useStrictOIDValidation());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("test-oc-oid"));
    assertNotNull(schema.getDITContentRule("test-oc-oid"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a DIT content rule with a
   * non-numeric OID that is something other than its name followed by "-oid".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleWithNonNumericOIDNotUsingName()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_OBJECT_CLASS,
         "( non-numeric-oid NAME 'test-oc' SUP top MAY cn )");
    schemaEntry.addAttribute(Schema.ATTR_DIT_CONTENT_RULE,
         "( non-numeric-oid NAME 'test-dcr' MAY cn )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertTrue(schemaValidator.useStrictOIDValidation());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("non-numeric-oid"));
    assertNotNull(schema.getDITContentRule("non-numeric-oid"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setOIDValidation(false, true, false);
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertTrue(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertFalse(schemaValidator.useStrictOIDValidation());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("non-numeric-oid"));
    assertNotNull(schema.getDITContentRule("non-numeric-oid"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a DIT content rule
   * definitions whose OID references an unknown structural class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleWithUndefinedStructuralClass()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "ditContentRules: ( 1.2.3.4 NAME 'test-dcr' MAY cn )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITContentRule("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowReferencesToUndefinedElementTypes(
         SchemaElementType.OBJECT_CLASS);
    assertFalse(
         schemaValidator.getAllowReferencesToUndefinedElementTypes().isEmpty());
    assertEquals(schemaValidator.getAllowReferencesToUndefinedElementTypes(),
         EnumSet.of(SchemaElementType.OBJECT_CLASS));

    errorMessages.clear();

    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITContentRule("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a DIT content rule that
   * references an object class that is not structural.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleObjectClassNotStructural()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_DIT_CONTENT_RULE,
         "( 2.5.6.0 NAME 'test-dcr' MAY cn )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    final SchemaValidator schemaValidator = new SchemaValidator();

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("2.5.6.0"));
    assertNotNull(schema.getDITContentRule("2.5.6.0"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has a DIT content rule without a
   * name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleWithoutName()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_DIT_CONTENT_RULE,
           "( 0.9.2342.19200300.100.4.13 MAY cn )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.allowElementsWithoutNames());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITContentRule("0.9.2342.19200300.100.4.13"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowElementsWithoutNames(false);
    assertFalse(schemaValidator.allowElementsWithoutNames());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITContentRule("0.9.2342.19200300.100.4.13"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has a DIT content rule with a
   * name that starts with a digit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleNameStartsWithDigit()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_DIT_CONTENT_RULE,
         "( 0.9.2342.19200300.100.4.13 NAME '1test-dcr' MAY cn )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNamesWithInitialDigit());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITContentRule("1test-dcr"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowNamesWithInitialDigit(true);
    assertTrue(schemaValidator.allowNamesWithInitialDigit());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITContentRule("1test-dcr"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a DIT content rule with a
   * name that starts with a hyphen.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleNameStartsWithHyphen()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_DIT_CONTENT_RULE,
         "( 0.9.2342.19200300.100.4.13 NAME '-test-dcr' MAY cn )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNamesWithInitialHyphen());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITContentRule("-test-dcr"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowNamesWithInitialHyphen(true);
    assertTrue(schemaValidator.allowNamesWithInitialHyphen());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITContentRule("-test-dcr"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a DIT content rule with a
   * name that contains underscore characters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleNameContainsUnderscore()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_DIT_CONTENT_RULE,
         "( 0.9.2342.19200300.100.4.13 NAME '_test_dcr' MAY cn )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNamesWithUnderscore());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITContentRule("_test_dcr"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowNamesWithUnderscore(true);
    assertTrue(schemaValidator.allowNamesWithUnderscore());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITContentRule("_test_dcr"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a DIT content rule with an
   * empty description.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleWithEmptyDescription()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_DIT_CONTENT_RULE,
         "( 0.9.2342.19200300.100.4.13 NAME 'test-dcr' DESC '' MAY cn )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowEmptyDescription());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITContentRule("0.9.2342.19200300.100.4.13"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowEmptyDescription(true);
    assertTrue(schemaValidator.allowEmptyDescription());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITContentRule("0.9.2342.19200300.100.4.13"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a DIT content rule that is
   * declared OBSOLETE.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleObsolete()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_DIT_CONTENT_RULE,
         "( 0.9.2342.19200300.100.4.13 NAME 'test-dcr' OBSOLETE MAY cn )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.allowObsoleteElements());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITContentRule("0.9.2342.19200300.100.4.13"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowObsoleteElements(false);
    assertFalse(schemaValidator.allowObsoleteElements());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITContentRule("0.9.2342.19200300.100.4.13"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has a DIT content rule
   * definition with an undefined auxiliary class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleWithUndefinedAuxiliaryClass()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "ditContentRules: ( 0.9.2342.19200300.100.4.13 NAME 'test-dcr' " +
              "AUX undefined-oc MAY cn )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITContentRule("0.9.2342.19200300.100.4.13"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowReferencesToUndefinedElementTypes(
         SchemaElementType.OBJECT_CLASS);
    assertFalse(
         schemaValidator.getAllowReferencesToUndefinedElementTypes().isEmpty());
    assertEquals(schemaValidator.getAllowReferencesToUndefinedElementTypes(),
         EnumSet.of(SchemaElementType.OBJECT_CLASS));

    errorMessages.clear();

    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITContentRule("0.9.2342.19200300.100.4.13"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a DIT content rule
   * definition with an auxiliary class that is not auxiliary.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleWithAuxiliaryClassNotAuxiliary()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "ditContentRules: ( 0.9.2342.19200300.100.4.13 NAME 'test-dcr' " +
              "AUX top MAY cn )");

    final SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITContentRule("0.9.2342.19200300.100.4.13"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a DIT content rule
   * definition with an undefined required attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleWithUndefinedRequiredAttribute()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "ditContentRules: ( 0.9.2342.19200300.100.4.13 NAME 'test-dcr' " +
              "MUST undefined-at )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITContentRule("0.9.2342.19200300.100.4.13"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowReferencesToUndefinedElementTypes(
         SchemaElementType.ATTRIBUTE_TYPE);
    assertFalse(
         schemaValidator.getAllowReferencesToUndefinedElementTypes().isEmpty());
    assertEquals(schemaValidator.getAllowReferencesToUndefinedElementTypes(),
         EnumSet.of(SchemaElementType.ATTRIBUTE_TYPE));

    errorMessages.clear();

    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITContentRule("0.9.2342.19200300.100.4.13"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a DIT content rule
   * definition with an undefined optional attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleWithUndefinedOptionalAttribute()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "ditContentRules: ( 0.9.2342.19200300.100.4.13 NAME 'test-dcr' " +
              "MAY undefined-at )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITContentRule("0.9.2342.19200300.100.4.13"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowReferencesToUndefinedElementTypes(
         SchemaElementType.ATTRIBUTE_TYPE);
    assertFalse(
         schemaValidator.getAllowReferencesToUndefinedElementTypes().isEmpty());
    assertEquals(schemaValidator.getAllowReferencesToUndefinedElementTypes(),
         EnumSet.of(SchemaElementType.ATTRIBUTE_TYPE));

    errorMessages.clear();

    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITContentRule("0.9.2342.19200300.100.4.13"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a DIT content rule
   * definition with an undefined prohibited attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleWithUndefinedProhibitedAttribute()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "ditContentRules: ( 0.9.2342.19200300.100.4.13 NAME 'test-dcr' " +
              "NOT undefined-at )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITContentRule("0.9.2342.19200300.100.4.13"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowReferencesToUndefinedElementTypes(
         SchemaElementType.ATTRIBUTE_TYPE);
    assertFalse(
         schemaValidator.getAllowReferencesToUndefinedElementTypes().isEmpty());
    assertEquals(schemaValidator.getAllowReferencesToUndefinedElementTypes(),
         EnumSet.of(SchemaElementType.ATTRIBUTE_TYPE));

    errorMessages.clear();

    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITContentRule("0.9.2342.19200300.100.4.13"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a DIT content rule
   * definition with an attribute that is listed as both required and optional.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleWithAttrRequiredAndOptional()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "ditContentRules: ( 0.9.2342.19200300.100.4.13 NAME 'test-dcr' " +
              "MUST dc MAY dc )");

    final SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITContentRule("0.9.2342.19200300.100.4.13"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a DIT content rule
   * definition with an attribute that is listed as both required and
   * prohibited.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleWithAttrRequiredAndProhibited()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "objectClasses: ( 1.2.3.4 NAME 'test-oc' MAY cn )",
         "ditContentRules: ( 1.2.3.4 NAME 'test-dcr' MUST cn NOT cn )");

    final SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));
    assertNotNull(schema.getDITContentRule("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a DIT content rule
   * definition with an attribute that is listed as both optional and
   * prohibited.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleWithAttrOptionalAndProhibited()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "objectClasses: ( 1.2.3.4 NAME 'test-oc' MAY cn )",
         "ditContentRules: ( 1.2.3.4 NAME 'test-dcr' MAY cn NOT cn )");

    final SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));
    assertNotNull(schema.getDITContentRule("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a DIT content rule
   * definition with a prohibited attribute that is required by the structural
   * class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleWithProhibitedAttrRequiredByStructuralClass()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "objectClasses: ( 1.2.3.4 NAME 'test-oc' MUST cn )",
         "ditContentRules: ( 1.2.3.4 NAME 'test-dcr' NOT cn )");

    final SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));
    assertNotNull(schema.getDITContentRule("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a DIT content rule
   * definition with a prohibited attribute that is required by an auxiliary
   * class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleWithProhibitedAttrRequiredByAuxiliaryClass()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "objectClasses: ( 1.2.3.4 NAME 'test-oc' AUXILIARY MUST cn )",
         "ditContentRules: ( 0.9.2342.19200300.100.4.13 NAME 'test-dcr' " +
              "AUX test-oc NOT cn )");

    final SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getObjectClass("0.9.2342.19200300.100.4.13"));
    assertNotNull(schema.getObjectClass("1.2.3.4"));
    assertNotNull(schema.getDITContentRule("0.9.2342.19200300.100.4.13"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a duplicate DIT content rule definition that has the
   * same OID but a different name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRedefinedDITContentRuleWithOID()
         throws Exception
  {
    final File schemaDir = createTempDir();

    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_DIT_CONTENT_RULE,
           "( 0.9.2342.19200300.100.4.13 NAME 'test-dcr-1' MAY cn )");

    final File schemaFile1 = new File(schemaDir, "01-first.ldif");
    StaticUtils.writeFile(schemaFile1, schemaEntry.toLDIF());

    final File schemaFile2 = new File(schemaDir, "second.ldif");
    StaticUtils.writeFile(schemaFile2,
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "ditContentRules: ( 0.9.2342.19200300.100.4.13 NAME 'test-dcr-2' " +
              "MAY dc )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowRedefiningElements());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getDITContentRule("0.9.2342.19200300.100.4.13"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowRedefiningElements(true);
    assertTrue(schemaValidator.allowRedefiningElements());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getDITContentRule("0.9.2342.19200300.100.4.13"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a duplicate DIT content rule definition that has the
   * same name but a different OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRedefinedDITContentRuleWithName()
         throws Exception
  {
    final File schemaDir = createTempDir();

    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_DIT_CONTENT_RULE,
           "( 0.9.2342.19200300.100.4.13 NAME 'test-dcr' MAY cn )");

    final File schemaFile1 = new File(schemaDir, "01-first.ldif");
    StaticUtils.writeFile(schemaFile1, schemaEntry.toLDIF());

    final File schemaFile2 = new File(schemaDir, "second.ldif");
    StaticUtils.writeFile(schemaFile2,
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "objectClasses: ( 1.2.3.4 NAME 'test-oc' SUP top MUST cn )",
         "ditContentRules: ( 1.2.3.4 NAME 'test-dcr' MUST cn )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowRedefiningElements());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getDITContentRule("0.9.2342.19200300.100.4.13"));
    assertNotNull(schema.getDITContentRule("1.2.3.4"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowRedefiningElements(true);
    assertTrue(schemaValidator.allowRedefiningElements());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getDITContentRule("0.9.2342.19200300.100.4.13"));
    assertNotNull(schema.getDITContentRule("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a DIT structure rule
   * definition when they are not allowed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITStructureRuleNotAllowed()
         throws Exception
  {
    final Entry schemaEntry =
         Schema.getDefaultStandardSchema().getSchemaEntry().duplicate();
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM,
         "( 1.2.3.4 NAME 'test-domain-nf' OC domain MUST dc )");
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM,
         "( 1.2.3.5 NAME 'test-organizationalUnit-nf' OC organizationalUnit " +
              "MUST ou )");
    schemaEntry.addAttribute(Schema.ATTR_DIT_STRUCTURE_RULE,
         "( 1 NAME 'test-domain-dsr' FORM test-domain-nf )");
    schemaEntry.addAttribute(Schema.ATTR_DIT_STRUCTURE_RULE,
         "( 2 NAME 'test-organizationalUnit-dsr' " +
              "FORM test-organizationalUnit-nf SUP 1 )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    final SchemaValidator schemaValidator = new SchemaValidator();
    assertEquals(schemaValidator.getAllowedSchemaElementTypes(),
         EnumSet.allOf(SchemaElementType.class));

    final Set<SchemaElementType> allowedElementTypes =
         EnumSet.allOf(SchemaElementType.class);
    allowedElementTypes.remove(SchemaElementType.DIT_STRUCTURE_RULE);

    schemaValidator.setAllowedSchemaElementTypes(allowedElementTypes);
    assertEquals(schemaValidator.getAllowedSchemaElementTypes(),
         allowedElementTypes);

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has a DIT structure rule
   * definition that is malformed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITStructureRuleMalformed()
         throws Exception
  {
    final Entry schemaEntry =
         Schema.getDefaultStandardSchema().getSchemaEntry().duplicate();
    schemaEntry.addAttribute(Schema.ATTR_DIT_STRUCTURE_RULE, "malformed");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    final SchemaValidator schemaValidator = new SchemaValidator();

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has a DIT structure rule without
   * a name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITStructureRuleWithoutName()
         throws Exception
  {
    final Entry schemaEntry =
         Schema.getDefaultStandardSchema().getSchemaEntry().duplicate();
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM,
         "( 1.2.3.4 NAME 'test-domain-nf' OC domain MUST dc )");
    schemaEntry.addAttribute(Schema.ATTR_DIT_STRUCTURE_RULE,
         "( 1 FORM test-domain-nf )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.allowElementsWithoutNames());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITStructureRuleByID(1));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowElementsWithoutNames(false);
    assertFalse(schemaValidator.allowElementsWithoutNames());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITStructureRuleByID(1));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has a DIT structure rule with a
   * name that starts with a digit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITStructureRuleNameStartsWithDigit()
         throws Exception
  {
    final Entry schemaEntry =
         Schema.getDefaultStandardSchema().getSchemaEntry().duplicate();
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM,
         "( 1.2.3.4 NAME 'test-domain-nf' OC domain MUST dc )");
    schemaEntry.addAttribute(Schema.ATTR_DIT_STRUCTURE_RULE,
         "( 1 NAME '1test-domain-dsr' FORM test-domain-nf )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNamesWithInitialDigit());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITStructureRuleByID(1));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowNamesWithInitialDigit(true);
    assertTrue(schemaValidator.allowNamesWithInitialDigit());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITStructureRuleByID(1));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a DIT structure rule with a
   * name that starts with a hyphen.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITStructureRuleNameStartsWithHyphen()
         throws Exception
  {
    final Entry schemaEntry =
         Schema.getDefaultStandardSchema().getSchemaEntry().duplicate();
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM,
         "( 1.2.3.4 NAME 'test-domain-nf' OC domain MUST dc )");
    schemaEntry.addAttribute(Schema.ATTR_DIT_STRUCTURE_RULE,
         "( 1 NAME '-test-domain-dsr' FORM test-domain-nf )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNamesWithInitialHyphen());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITStructureRuleByID(1));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowNamesWithInitialHyphen(true);
    assertTrue(schemaValidator.allowNamesWithInitialHyphen());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITStructureRuleByID(1));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a DIT structure rule with a
   * name that contains underscore characters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITStructureRuleNameContainsUnderscore()
         throws Exception
  {
    final Entry schemaEntry =
         Schema.getDefaultStandardSchema().getSchemaEntry().duplicate();
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM,
         "( 1.2.3.4 NAME 'test-domain-nf' OC domain MUST dc )");
    schemaEntry.addAttribute(Schema.ATTR_DIT_STRUCTURE_RULE,
         "( 1 NAME '_test_domain_dsr' FORM test-domain-nf )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNamesWithUnderscore());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITStructureRuleByID(1));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowNamesWithUnderscore(true);
    assertTrue(schemaValidator.allowNamesWithUnderscore());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITStructureRuleByID(1));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a DIT structure rule with an
   * empty description.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITStructureRuleWithEmptyDescription()
         throws Exception
  {
    final Entry schemaEntry =
         Schema.getDefaultStandardSchema().getSchemaEntry().duplicate();
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM,
         "( 1.2.3.4 NAME 'test-domain-nf' OC domain MUST dc )");
    schemaEntry.addAttribute(Schema.ATTR_DIT_STRUCTURE_RULE,
         "( 1 NAME 'test-domain-dsr' DESC '' FORM test-domain-nf )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowEmptyDescription());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITStructureRuleByID(1));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowEmptyDescription(true);
    assertTrue(schemaValidator.allowEmptyDescription());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITStructureRuleByID(1));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a DIT structure rule that is
   * declared OBSOLETE.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITStructureRuleObsolete()
         throws Exception
  {
    final Entry schemaEntry =
         Schema.getDefaultStandardSchema().getSchemaEntry().duplicate();
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM,
         "( 1.2.3.4 NAME 'test-domain-nf' OC domain MUST dc )");
    schemaEntry.addAttribute(Schema.ATTR_DIT_STRUCTURE_RULE,
         "( 1 NAME 'test-domain-dsr' OBSOLETE FORM test-domain-nf )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.allowObsoleteElements());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITStructureRuleByID(1));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowObsoleteElements(false);
    assertFalse(schemaValidator.allowObsoleteElements());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITStructureRuleByID(1));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has a DIT structure rule
   * definition with an undefined required attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITStructureRuleWithUndefinedNameForm()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "ditStructureRules: ( 1 NAME 'test-domain-dsr' FORM test-domain-nf )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         Schema.getDefaultStandardSchema(), errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITStructureRuleByID(1));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowReferencesToUndefinedElementTypes(
         SchemaElementType.NAME_FORM);
    assertFalse(
         schemaValidator.getAllowReferencesToUndefinedElementTypes().isEmpty());
    assertEquals(schemaValidator.getAllowReferencesToUndefinedElementTypes(),
         EnumSet.of(SchemaElementType.NAME_FORM));

    errorMessages.clear();

    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITStructureRuleByID(1));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a DIT structure rule
   * definition with an undefined superior rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITStructureRuleWithUndefinedSuperiorRule()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "nameForms: ( 1.2.3.4 NAME 'test-domain-nf' OC domain MUST dc )",
         "ditStructureRules: ( 2 NAME 'test-domain-dsr' SUP 1 " +
              "FORM test-domain-nf )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         Schema.getDefaultStandardSchema(), errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITStructureRuleByID(2));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowReferencesToUndefinedElementTypes(
         SchemaElementType.DIT_STRUCTURE_RULE);
    assertFalse(
         schemaValidator.getAllowReferencesToUndefinedElementTypes().isEmpty());
    assertEquals(schemaValidator.getAllowReferencesToUndefinedElementTypes(),
         EnumSet.of(SchemaElementType.DIT_STRUCTURE_RULE));

    errorMessages.clear();

    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getDITStructureRuleByID(2));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a duplicate DIT structure rule definition that has
   * the same rule ID but a different name and name form.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRedefinedDITStructureRuleWithRuleID()
         throws Exception
  {
    final File schemaDir = createTempDir();

    final Entry schemaEntry =
         Schema.getDefaultStandardSchema().getSchemaEntry().duplicate();
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM,
         "( 1.2.3.4 NAME 'test-domain-nf' OC domain MUST dc )");
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM,
         "( 1.2.3.5 NAME 'test-organizationalUnit-nf' OC organizationalUnit " +
              "MUST ou )");
    schemaEntry.addAttribute(Schema.ATTR_DIT_STRUCTURE_RULE,
         "( 1 NAME 'test-domain-dsr' FORM test-domain-nf )");

    final File schemaFile1 = new File(schemaDir, "01-first.ldif");
    StaticUtils.writeFile(schemaFile1, schemaEntry.toLDIF());

    final File schemaFile2 = new File(schemaDir, "second.ldif");
    StaticUtils.writeFile(schemaFile2,
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "ditStructureRules: ( 1 NAME 'test-organizationalUnit-dsr' " +
              "FORM test-organizationalUnit-nf )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowRedefiningElements());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getDITStructureRuleByID(1));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowRedefiningElements(true);
    assertTrue(schemaValidator.allowRedefiningElements());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getDITStructureRuleByID(1));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a duplicate DIT structure rule definition that has
   * the same name but a different rule ID and name form.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRedefinedDITStructureRuleWithName()
         throws Exception
  {
    final File schemaDir = createTempDir();

    final Entry schemaEntry =
         Schema.getDefaultStandardSchema().getSchemaEntry().duplicate();
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM,
         "( 1.2.3.4 NAME 'test-domain-nf' OC domain MUST dc )");
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM,
         "( 1.2.3.5 NAME 'test-organizationalUnit-nf' OC organizationalUnit " +
              "MUST ou )");
    schemaEntry.addAttribute(Schema.ATTR_DIT_STRUCTURE_RULE,
         "( 1 NAME 'test-dsr' FORM test-domain-nf )");

    final File schemaFile1 = new File(schemaDir, "01-first.ldif");
    StaticUtils.writeFile(schemaFile1, schemaEntry.toLDIF());

    final File schemaFile2 = new File(schemaDir, "second.ldif");
    StaticUtils.writeFile(schemaFile2,
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "ditStructureRules: ( 2 NAME 'test-dsr' " +
              "FORM test-organizationalUnit-nf )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowRedefiningElements());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getDITStructureRuleByID(1));
    assertNotNull(schema.getDITStructureRuleByID(2));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowRedefiningElements(true);
    assertTrue(schemaValidator.allowRedefiningElements());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getDITStructureRuleByID(1));
    assertNotNull(schema.getDITStructureRuleByID(2));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a duplicate DIT structure rule definition that has
   * the same name form but a different rule ID and name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRedefinedDITStructureRuleWithNameForm()
         throws Exception
  {
    final File schemaDir = createTempDir();

    final Entry schemaEntry =
         Schema.getDefaultStandardSchema().getSchemaEntry().duplicate();
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM,
         "( 1.2.3.4 NAME 'test-domain-nf' OC domain MUST dc )");
    schemaEntry.addAttribute(Schema.ATTR_NAME_FORM,
         "( 1.2.3.5 NAME 'test-organizationalUnit-nf' OC organizationalUnit " +
              "MUST ou )");
    schemaEntry.addAttribute(Schema.ATTR_DIT_STRUCTURE_RULE,
         "( 1 NAME 'test-dsr-1' FORM test-domain-nf )");

    final File schemaFile1 = new File(schemaDir, "01-first.ldif");
    StaticUtils.writeFile(schemaFile1, schemaEntry.toLDIF());

    final File schemaFile2 = new File(schemaDir, "second.ldif");
    StaticUtils.writeFile(schemaFile2,
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "ditStructureRules: ( 2 NAME 'test-dsr-2' FORM test-domain-nf )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowRedefiningElements());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getDITStructureRuleByID(1));
    assertNotNull(schema.getDITStructureRuleByID(2));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowRedefiningElements(true);
    assertTrue(schemaValidator.allowRedefiningElements());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getDITStructureRuleByID(1));
    assertNotNull(schema.getDITStructureRuleByID(2));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a matching rule use
   * definition when it is not allowed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleUseNotAllowed()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_MATCHING_RULE_USE,
         "( 1.3.6.1.4.1.1466.109.114.2 NAME 'caseIgnoreIA5Match-mru' " +
              "APPLIES dc )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    final SchemaValidator schemaValidator = new SchemaValidator();
    assertEquals(schemaValidator.getAllowedSchemaElementTypes(),
         EnumSet.allOf(SchemaElementType.class));

    final Set<SchemaElementType> allowedElementTypes =
         EnumSet.allOf(SchemaElementType.class);
    allowedElementTypes.remove(SchemaElementType.MATCHING_RULE_USE);

    schemaValidator.setAllowedSchemaElementTypes(allowedElementTypes);
    assertEquals(schemaValidator.getAllowedSchemaElementTypes(),
         allowedElementTypes);

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that a malformed matching rule use
   * definition.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedMatchingRuleUse()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_MATCHING_RULE_USE, "malformed");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    final SchemaValidator schemaValidator = new SchemaValidator();

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has a matching rule use with a
   * numeric OID that passes lenient validation but not strict validation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleUseWithOIDNotStrictlyValid()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_MATCHING_RULE,
         "( 1 NAME 'test-mr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )");
    schemaEntry.addAttribute(Schema.ATTR_MATCHING_RULE_USE,
         "( 1 NAME 'test-mru' APPLIES dc )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertTrue(schemaValidator.useStrictOIDValidation());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("1"));
    assertNotNull(schema.getMatchingRuleUse("1"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setOIDValidation(false, false, false);
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertFalse(schemaValidator.useStrictOIDValidation());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("1"));
    assertNotNull(schema.getMatchingRuleUse("1"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a matching rule use with a
   * non-numeric OID that is its name followed by "-oid".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleUseWithNonNumericOIDUsingName()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_MATCHING_RULE,
         "( test-mr-oid NAME 'test-mr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )");
    schemaEntry.addAttribute(Schema.ATTR_MATCHING_RULE_USE,
         "( test-mr-oid NAME 'test-mr' APPLIES dc )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertTrue(schemaValidator.useStrictOIDValidation());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("test-mr-oid"));
    assertNotNull(schema.getMatchingRuleUse("test-mr-oid"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setOIDValidation(true, false, false);
    assertTrue(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertFalse(schemaValidator.useStrictOIDValidation());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("test-mr-oid"));
    assertNotNull(schema.getMatchingRuleUse("test-mr-oid"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a matching rule use with a
   * non-numeric OID that is something other than its name followed by "-oid".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleUseWithNonNumericOIDNotUsingName()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_MATCHING_RULE,
         "( non-numeric-oid NAME 'test-mr' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )");
    schemaEntry.addAttribute(Schema.ATTR_MATCHING_RULE_USE,
         "( non-numeric-oid NAME 'test-mr' APPLIES dc )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertFalse(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertTrue(schemaValidator.useStrictOIDValidation());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("non-numeric-oid"));
    assertNotNull(schema.getMatchingRuleUse("non-numeric-oid"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setOIDValidation(false, true, false);
    assertFalse(schemaValidator.allowNonNumericOIDsUsingName());
    assertTrue(schemaValidator.allowNonNumericOIDsNotUsingName());
    assertFalse(schemaValidator.useStrictOIDValidation());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRule("non-numeric-oid"));
    assertNotNull(schema.getMatchingRuleUse("non-numeric-oid"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a matching rule use
   * definition whose OID does not reference a defined matching rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleUseWithUndefinedMatchingRule()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "matchingRuleUse: ( 1.2.3.4 NAME 'test-mru' APPLIES cn )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRuleUse("1.2.3.4"));

    assertFalse(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowReferencesToUndefinedElementTypes(
         SchemaElementType.MATCHING_RULE);
    assertFalse(
         schemaValidator.getAllowReferencesToUndefinedElementTypes().isEmpty());
    assertEquals(schemaValidator.getAllowReferencesToUndefinedElementTypes(),
         EnumSet.of(SchemaElementType.MATCHING_RULE));

    errorMessages.clear();

    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRuleUse("1.2.3.4"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a matching rule use without
   * a name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleUseWithoutName()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_MATCHING_RULE_USE,
         "( 1.3.6.1.4.1.1466.109.114.2 APPLIES dc )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.allowElementsWithoutNames());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRuleUse("1.3.6.1.4.1.1466.109.114.2"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowElementsWithoutNames(false);
    assertFalse(schemaValidator.allowElementsWithoutNames());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRuleUse("1.3.6.1.4.1.1466.109.114.2"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has a matching rule use with a
   * name that starts with a digit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleUseNameStartsWithDigit()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_MATCHING_RULE_USE,
         "( 1.3.6.1.4.1.1466.109.114.2 NAME '1test-mru' APPLIES dc )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNamesWithInitialDigit());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRuleUse("1test-mru"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowNamesWithInitialDigit(true);
    assertTrue(schemaValidator.allowNamesWithInitialDigit());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRuleUse("1test-mru"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a matching rule use with a
   * name that starts with a hyphen.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleUseNameStartsWithHyphen()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_MATCHING_RULE_USE,
         "( 1.3.6.1.4.1.1466.109.114.2 NAME '-test-mru' APPLIES dc )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNamesWithInitialHyphen());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRuleUse("-test-mru"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowNamesWithInitialHyphen(true);
    assertTrue(schemaValidator.allowNamesWithInitialHyphen());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRuleUse("-test-mru"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a matching rule use with a
   * name that contains underscore characters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleUseNameContainsUnderscore()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_MATCHING_RULE_USE,
         "( 1.3.6.1.4.1.1466.109.114.2 NAME '_test_mru' APPLIES dc )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowNamesWithUnderscore());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRuleUse("_test_mru"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowNamesWithUnderscore(true);
    assertTrue(schemaValidator.allowNamesWithUnderscore());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRuleUse("_test_mru"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a matching rule use with an
   * empty description.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleUseWithEmptyDescription()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_MATCHING_RULE_USE,
         "( 1.3.6.1.4.1.1466.109.114.2 NAME 'test-mru' DESC '' APPLIES dc )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowEmptyDescription());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRuleUse("test-mru"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowEmptyDescription(true);
    assertTrue(schemaValidator.allowEmptyDescription());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRuleUse("test-mru"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a matching rule use that is
   * declared OBSOLETE.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleUseObsolete()
         throws Exception
  {
    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_MATCHING_RULE_USE,
         "( 1.3.6.1.4.1.1466.109.114.2 NAME 'test-mru' OBSOLETE APPLIES dc )");

    final File schemaFile = createTempFile(schemaEntry.toLDIF());

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.allowObsoleteElements());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRuleUse("test-mru"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowObsoleteElements(false);
    assertFalse(schemaValidator.allowObsoleteElements());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaFile, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRuleUse("test-mru"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has a matching rule use
   * definition that references an undefined attribute type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleUseWithUndefinedAttributeType()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "matchingRules: ( 1.2.3.4 NAME 'test-mr' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
         "matchingRuleUse: ( 1.2.3.4 NAME 'test-mru' APPLIES undefined )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRuleUse("test-mru"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowReferencesToUndefinedElementTypes(
         SchemaElementType.ATTRIBUTE_TYPE);
    assertFalse(
         schemaValidator.getAllowReferencesToUndefinedElementTypes().isEmpty());
    assertEquals(schemaValidator.getAllowReferencesToUndefinedElementTypes(),
         EnumSet.of(SchemaElementType.ATTRIBUTE_TYPE));

    errorMessages.clear();
    schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getAttributeType("dc"));
    assertNotNull(schema.getMatchingRuleUse("test-mru"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a duplicate matching rule use definition that has
   * the same OID but a different name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRedefinedMatchingRuleUseWithOID()
         throws Exception
  {
    final File schemaDir = createTempDir();

    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_MATCHING_RULE_USE,
         "( 1.3.6.1.4.1.1466.109.114.2 NAME 'test-mru-1' APPLIES dc )");

    final File schemaFile1 = new File(schemaDir, "01-first.ldif");
    StaticUtils.writeFile(schemaFile1, schemaEntry.toLDIF());

    final File schemaFile2 = new File(schemaDir, "second.ldif");
    StaticUtils.writeFile(schemaFile2,
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "matchingRuleUse: ( 1.3.6.1.4.1.1466.109.114.2 NAME 'test-mru-2' " +
              "APPLIES dc )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowRedefiningElements());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getMatchingRuleUse("1.3.6.1.4.1.1466.109.114.2"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowRedefiningElements(true);
    assertTrue(schemaValidator.allowRedefiningElements());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getMatchingRuleUse("1.3.6.1.4.1.1466.109.114.2"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a duplicate matching rule use definition that has
   * the same name but a different OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRedefinedMatchingRuleUseWithName()
         throws Exception
  {
    final File schemaDir = createTempDir();

    final Entry schemaEntry = minimalSchemaEntry.duplicate();
    schemaEntry.addAttribute(Schema.ATTR_MATCHING_RULE_USE,
         "( 1.3.6.1.4.1.1466.109.114.2 NAME 'test-mru' APPLIES dc )");

    final File schemaFile1 = new File(schemaDir, "01-first.ldif");
    StaticUtils.writeFile(schemaFile1, schemaEntry.toLDIF());

    final File schemaFile2 = new File(schemaDir, "second.ldif");
    StaticUtils.writeFile(schemaFile2,
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "matchingRuleUse: ( 2.5.13.2 NAME 'test-mru' APPLIES ( name $ cn ) )");

    SchemaValidator schemaValidator = new SchemaValidator();
    assertFalse(schemaValidator.allowRedefiningElements());

    final List<String> errorMessages = new ArrayList<>(5);
    Schema schema =
         schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getMatchingRuleUse("test-mru"));

    assertFalse(errorMessages.isEmpty());


    schemaValidator = new SchemaValidator();
    schemaValidator.setAllowRedefiningElements(true);
    assertTrue(schemaValidator.allowRedefiningElements());

    errorMessages.clear();

    schema = schemaValidator.validateSchema(schemaDir, null, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getMatchingRuleUse("test-mru"));

    assertTrue(errorMessages.isEmpty(),
         StaticUtils.linesToString(errorMessages));
  }



  /**
   * Tests the behavior for a schema entry that has a matching rule use
   * that only allows a matching rule to be used for a given attribute type,
   * but another attribute type is defined with that matching rule as its
   * equality rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeEMRProhibitedByMRU()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "matchingRules: ( 1.2.3.4 NAME 'test-mr' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
         "attributeTypes: ( 1.2.3.5 NAME 'test-at' EQUALITY 1.2.3.4 " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
         "matchingRuleUse: ( 1.2.3.4 NAME 'test-mru' APPLIES cn )");

    final SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getMatchingRule("1.2.3.4"));
    assertNotNull(schema.getAttributeType("1.2.3.5"));
    assertNotNull(schema.getMatchingRuleUse("1.2.3.4"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has a matching rule use
   * that only allows a matching rule to be used for a given attribute type,
   * but another attribute type is defined with that matching rule as its
   * ordering rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeOMRProhibitedByMRU()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "matchingRules: ( 1.2.3.4 NAME 'test-mr' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
         "attributeTypes: ( 1.2.3.5 NAME 'test-at' ORDERING 1.2.3.4 " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
         "matchingRuleUse: ( 1.2.3.4 NAME 'test-mru' APPLIES cn )");

    final SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getMatchingRule("1.2.3.4"));
    assertNotNull(schema.getAttributeType("1.2.3.5"));
    assertNotNull(schema.getMatchingRuleUse("1.2.3.4"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior for a schema entry that has a matching rule use
   * that only allows a matching rule to be used for a given attribute type,
   * but another attribute type is defined with that matching rule as its
   * substring rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeSMRProhibitedByMRU()
         throws Exception
  {
    final File additionalSchemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "matchingRules: ( 1.2.3.4 NAME 'test-mr' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
         "attributeTypes: ( 1.2.3.5 NAME 'test-at' SUBSTR 1.2.3.4 " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
         "matchingRuleUse: ( 1.2.3.4 NAME 'test-mru' APPLIES cn )");

    final SchemaValidator schemaValidator = new SchemaValidator();
    assertTrue(schemaValidator.getAllowReferencesToUndefinedElementTypes().
         isEmpty());

    final Schema existingSchema = Schema.parseSchemaEntry(minimalSchemaEntry);

    final List<String> errorMessages = new ArrayList<>(5);
    final Schema schema = schemaValidator.validateSchema(additionalSchemaFile,
         existingSchema, errorMessages);

    assertNotNull(schema);
    assertNotNull(schema.getMatchingRule("1.2.3.4"));
    assertNotNull(schema.getAttributeType("1.2.3.5"));
    assertNotNull(schema.getMatchingRuleUse("1.2.3.4"));

    assertFalse(errorMessages.isEmpty());
  }



  /**
   * Tests the behavior of the {@code setAllowedSchemaElementTypes} method
   * variant that takes varargs.
   */
  @Test()
  public void testSetAllowedSchemaElementTypesWithVarArgs()
  {
    final SchemaValidator schemaValidator = new SchemaValidator();

    assertNotNull(schemaValidator.getAllowedSchemaElementTypes());
    assertFalse(schemaValidator.getAllowedSchemaElementTypes().isEmpty());
    assertEquals(schemaValidator.getAllowedSchemaElementTypes(),
         EnumSet.allOf(SchemaElementType.class));

    schemaValidator.setAllowedSchemaElementTypes(
         SchemaElementType.ATTRIBUTE_TYPE,
         SchemaElementType.OBJECT_CLASS);

    assertNotNull(schemaValidator.getAllowedSchemaElementTypes());
    assertFalse(schemaValidator.getAllowedSchemaElementTypes().isEmpty());
    assertEquals(schemaValidator.getAllowedSchemaElementTypes(),
         EnumSet.of(SchemaElementType.ATTRIBUTE_TYPE,
              SchemaElementType.OBJECT_CLASS));
  }



  /**
   * Tests the behavior of the {@code validateName} method when an empty name
   * was provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testValidateNameEmpty()
         throws Exception
  {
    final SchemaValidator schemaValidator = new SchemaValidator();
    schemaValidator.validateName("");
  }



  /**
   * Tests the behavior of the {@code validateName} method when the provided
   * name has a first character that is never allowed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testValidateNameFirstCharacterNeverAllowed()
         throws Exception
  {
    final SchemaValidator schemaValidator = new SchemaValidator();
    schemaValidator.validateName("!invalid");
  }



  /**
   * Tests the behavior of the {@code validateName} method when a subsequent
   * name is never allowed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testValidateNameSubsequentCharacterNeverAllowed()
         throws Exception
  {
    final SchemaValidator schemaValidator = new SchemaValidator();
    schemaValidator.validateName("invalid!");
  }
}
