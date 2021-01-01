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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONObjectReader;



/**
 * This class provides a set of tests for the oid-lookup tool.
 */
public final class OIDLookupTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for methods that can be called without running the
   * tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToolMethods()
         throws Exception
  {
    final OIDLookup tool = new OIDLookup(null, null);

    assertNotNull(tool.getToolName());
    assertEquals(tool.getToolName(), "oid-lookup");

    assertNotNull(tool.getToolDescription());
    assertFalse(tool.getToolDescription().isEmpty());

    assertNotNull(tool.getAdditionalDescriptionParagraphs());
    assertFalse(tool.getAdditionalDescriptionParagraphs().isEmpty());

    assertNotNull(tool.getToolVersion());
    assertEquals(tool.getToolVersion(), Version.NUMERIC_VERSION_STRING);

    assertEquals(tool.getMinTrailingArguments(), 0);

    assertEquals(tool.getMaxTrailingArguments(), 1);

    assertNotNull(tool.getTrailingArgumentsPlaceholder());
    assertFalse(tool.getTrailingArgumentsPlaceholder().isEmpty());

    assertTrue(tool.supportsInteractiveMode());

    assertFalse(tool.defaultsToInteractiveMode());

    assertTrue(tool.supportsPropertiesFile());

    assertTrue(tool.supportsOutputFile());

    assertFalse(tool.logToolInvocationByDefault());

    assertNotNull(tool.getExampleUsages());
    assertFalse(tool.getExampleUsages().isEmpty());
  }



  /**
   * Ensures that it is possible to obtain usage information for the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetUsage()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    assertEquals(OIDLookup.main(out, err, "--help"), ResultCode.SUCCESS);

    assertTrue(out.toByteArray().length > 0);

    assertEquals(err.toByteArray().length, 0);
  }



  /**
   * Tests the behavior when retrieving all elements when using the default
   * output format.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAllDefaultOutputFormat()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    assertEquals(OIDLookup.main(out, err), ResultCode.SUCCESS);

    assertTrue(out.toByteArray().length > 0);

    assertEquals(err.toByteArray().length, 0);
  }



  /**
   * Tests the behavior when retrieving all elements in a specified output
   * format.
   *
   * @param  outputFormat  The output format to use for the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "outputFormats")
  public void testGetAllSpecifiedOutputFormat(final String outputFormat)
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    assertEquals(OIDLookup.main(out, err, "--output-format", outputFormat),
         ResultCode.SUCCESS);

    assertTrue(out.toByteArray().length > 0);

    assertEquals(err.toByteArray().length, 0);
  }



  /**
   * Retrieves the output formats that may be used for testing.
   *
   * @return  The output formats that may be used for testing.
   */
  @DataProvider(name = "outputFormats")
  public Object[][] getOutputFormats()
  {
    return new Object[][]
    {
      new Object[]
      {
        "csv"
      },
      new Object[]
      {
        "json"
      },
      new Object[]
      {
        "multi-line"
      },
      new Object[]
      {
        "tab-delimited"
      }
    };
  }



  /**
   * Tests the behavior for a search that does not match any items.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchNoMatches()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    assertEquals(OIDLookup.main(out, err, "does-not-match-anything"),
         ResultCode.NO_RESULTS_RETURNED);

    assertTrue(out.toByteArray().length > 0);

    assertEquals(err.toByteArray().length, 0);
  }



  /**
   * Tests the behavior for a search that matches am item by OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOneMatchByOID()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    assertEquals(OIDLookup.main(out, err, "0.9.2342.19200300.100.1.1"),
         ResultCode.SUCCESS);

    assertTrue(out.toByteArray().length > 0);

    assertEquals(err.toByteArray().length, 0);
  }



  /**
   * Tests the behavior for a search that matches an item by name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOneMatch()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    assertEquals(OIDLookup.main(out, err, "extensibleObject"),
         ResultCode.SUCCESS);

    assertTrue(out.toByteArray().length > 0);

    assertEquals(err.toByteArray().length, 0);
  }



  /**
   * Tests the behavior for a search that matches items by type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchByType()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    assertEquals(OIDLookup.main(out, err, "Attribute Type"),
         ResultCode.SUCCESS);

    assertTrue(out.toByteArray().length > 0);

    assertEquals(err.toByteArray().length, 0);
  }



  /**
   * Tests the behavior for a search that matches items by origin.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchByOrigin()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    assertEquals(OIDLookup.main(out, err, "RFC 4519"),
         ResultCode.SUCCESS);

    assertTrue(out.toByteArray().length > 0);

    assertEquals(err.toByteArray().length, 0);
  }



  /**
   * Tests the behavior for a search that matches items by URL.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchByURL()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    assertEquals(
         OIDLookup.main(out, err, "https://docs.ldap.com/specs/rfc4519.txt"),
         ResultCode.SUCCESS);

    assertTrue(out.toByteArray().length > 0);

    assertEquals(err.toByteArray().length, 0);
  }



  /**
   * Tests the behavior when augmenting the default OID registry with schema
   * from a file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAugmentWithSchemaFromFile()
         throws Exception
  {
    final File schemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubentry",
         "objectClass: subschema",
         "cn: schema",
         "ldapSyntaxes: ( 1.2.3.4.1 DESC 'test-syntax' " +
              "X-ORIGIN 'test-origin' )",
         "matchingRules: ( 1.2.3.4.2 NAME 'testMatch' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
         "attributeTypes: ( 1.2.3.4.3 NAME 'test-attr' " +
              "EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 " +
              "X-ORIGIN 'another-origin' )",
         "objectClasses: ( 1.2.3.4.4 NAME 'test-oc' SUP top STRUCTURAL " +
              "MUST cn )",
         "nameForms: ( 1.2.3.4.5 NAME 'test-nf' OC person MUST uid )");

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    assertEquals(
         OIDLookup.main(out, err,
              "--schema-path", schemaFile.getAbsolutePath(),
              "1.2.3.4.1"),
         ResultCode.SUCCESS);

    assertTrue(out.toByteArray().length > 0);

    assertEquals(err.toByteArray().length, 0);
  }



  /**
   * Tests the behavior when augmenting the default OID registry with schema
   * from a directory containing schema files.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAugmentWithSchemaFromDirectory()
         throws Exception
  {
    final File schemaDir = createTempDir();
    final File schemaFile = new File(schemaDir, "test-schema.ldif");
    StaticUtils.writeFile(schemaFile,
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubentry",
         "objectClass: subschema",
         "cn: schema",
         "ldapSyntaxes: ( 1.2.3.4.1 DESC 'test-syntax' " +
              "X-ORIGIN 'test-origin' )",
         "matchingRules: ( 1.2.3.4.2 NAME 'testMatch' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
         "attributeTypes: ( 1.2.3.4.3 NAME 'test-attr' " +
              "EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 " +
              "X-ORIGIN 'another-origin' )",
         "objectClasses: ( 1.2.3.4.4 NAME 'test-oc' SUP top STRUCTURAL " +
              "MUST cn )",
         "nameForms: ( 1.2.3.4.5 NAME 'test-nf' OC person MUST uid )");

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    assertEquals(
         OIDLookup.main(out, err,
              "--schema-path", schemaDir.getAbsolutePath(),
              "1.2.3.4.1"),
         ResultCode.SUCCESS);

    assertTrue(out.toByteArray().length > 0);

    assertEquals(err.toByteArray().length, 0);
  }



  /**
   * Tests the behavior of the tool when using exact versus substring matching.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExactMatch()
         throws Exception
  {
    // First, test with the default substring matching for the string "30221",
    // which is present in the base OID for all identifiers associated with the
    // Ping Identity Directory Server.  This should return multiple matches.
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         OIDLookup.main(out, out,
              "--output-format", "json",
              "30221"),
         ResultCode.SUCCESS);

    final List<JSONObject> substringMatches = getJSONObjects(out.toByteArray());
    assertTrue(substringMatches.size() > 1);


    // Next, test with the --exact-match argument.  No matches should be
    // returned.
    out.reset();
    assertEquals(
         OIDLookup.main(out, out,
              "--output-format", "json",
              "--exact-match",
              "30221"),
         ResultCode.NO_RESULTS_RETURNED);

    assertTrue(getJSONObjects(out.toByteArray()).isEmpty());


    // Finally, test with the "--exact-match" argument when using a search
    // string that exactly matches all of the OIDs from the objects that are
    // returned.
    for (final JSONObject o : substringMatches)
    {
      final String oid = o.getFieldAsString("oid");
      assertNotNull(oid);

      out.reset();
      assertEquals(
           OIDLookup.main(out, out,
                "--output-format", "json",
                "--exact-match",
                oid),
           ResultCode.SUCCESS);

      final List<JSONObject> exactMatches = getJSONObjects(out.toByteArray());
      assertEquals(exactMatches.size(), 1);
      assertEquals(exactMatches.get(0).getFieldAsString("oid"), oid);
    }
  }



  /**
   * Parses the provided output to extract all of the JSON objects that it
   * contains.
   *
   * @param  output  The raw output generated by the tool.
   *
   * @return  A list of the JSON objects included in the output.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static List<JSONObject> getJSONObjects(final byte[] output)
          throws Exception
  {
    try (ByteArrayInputStream in = new ByteArrayInputStream(output);
         JSONObjectReader reader = new JSONObjectReader(in))
    {
      List<JSONObject> objects = new ArrayList<>();
      while (true)
      {
        final JSONObject o = reader.readObject();
        if (o == null)
        {
          return objects;
        }

        objects.add(o);
      }
    }
  }
}
