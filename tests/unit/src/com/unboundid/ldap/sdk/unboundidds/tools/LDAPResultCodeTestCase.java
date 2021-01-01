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



import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONObjectReader;



/**
 * This class provides a set of tests for the ldap-result-code tool.
 */
public final class LDAPResultCodeTestCase
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
    final LDAPResultCode tool = new LDAPResultCode(null, null);

    assertNotNull(tool.getToolName());
    assertEquals(tool.getToolName(), "ldap-result-code");

    assertNotNull(tool.getToolDescription());
    assertFalse(tool.getToolDescription().isEmpty());

    assertNotNull(tool.getAdditionalDescriptionParagraphs());
    assertFalse(tool.getAdditionalDescriptionParagraphs().isEmpty());

    assertNotNull(tool.getToolVersion());
    assertEquals(tool.getToolVersion(), Version.NUMERIC_VERSION_STRING);

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

    assertEquals(LDAPResultCode.main(out, err, "--help"), ResultCode.SUCCESS);

    assertTrue(out.toByteArray().length > 0);

    assertEquals(err.toByteArray().length, 0);
  }



  /**
   * Tests the default behavior for the tool when no arguments are provided,
   * which is to list all defined result codes in a table.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testListDefault()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    assertEquals(LDAPResultCode.main(out, err), ResultCode.SUCCESS);

    assertTrue(out.toByteArray().length > 0);
    assertEquals(err.toByteArray().length, 0);
  }



  /**
   * Tests the default behavior for the tool when listing all result codes in
   * alphabetical order.  Script-friendly mode will be used to make the output
   * more parseable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExplicitListAlphabetical()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    assertEquals(
         LDAPResultCode.main(out, err,
              "--list",
              "--alphabetic",
              "--script-friendly"),
         ResultCode.SUCCESS);

    final byte[] outputBytes = out.toByteArray();
    assertTrue(outputBytes.length > 0);

    assertTrue(out.toByteArray().length > 0);

    try (ByteArrayInputStream byteArrayInputStream =
              new ByteArrayInputStream(outputBytes);
         InputStreamReader inputStreamReader =
              new InputStreamReader(byteArrayInputStream);
         BufferedReader bufferedReader = new BufferedReader(inputStreamReader))
    {
      String line = bufferedReader.readLine();
      assertNotNull(line);

      int numResultCodes = 0;
      String lastName = "";
      while (line != null)
      {
        numResultCodes++;
        assertFalse(line.isEmpty());

        final int tabPos = line.indexOf('\t');
        assertTrue(tabPos > 0);

        final String name = StaticUtils.toLowerCase(line.substring(0, tabPos));
        final int intValue = Integer.parseInt(line.substring(tabPos+1));

        final ResultCode rc = ResultCode.valueOf(intValue);
        assertNotNull(rc);
        assertTrue(name.equalsIgnoreCase(rc.getName()));

        assertTrue(name.compareTo(lastName) > 0);

        lastName = name;
        line = bufferedReader.readLine();
      }

      assertEquals(numResultCodes, ResultCode.values().length);
    }
  }



  /**
   * Tests the behavior when looking up result codes by integer value.
   *
   * @throws  Exception   If an unexpected problem occurs.
   */
  @Test()
  public void testIntValue()
         throws Exception
  {
    for (final ResultCode rc : ResultCode.values())
    {
      final ByteArrayOutputStream out = new ByteArrayOutputStream();
      final ByteArrayOutputStream err = new ByteArrayOutputStream();

      assertEquals(
           LDAPResultCode.main(out, err,
                "--int-value", String.valueOf(rc.intValue()),
                "--script-friendly"),
           ResultCode.SUCCESS);

      final byte[] outputBytes = out.toByteArray();
      assertTrue(outputBytes.length > 0);

      assertTrue(out.toByteArray().length > 0);

      try (ByteArrayInputStream byteArrayInputStream =
                new ByteArrayInputStream(outputBytes);
           InputStreamReader inputStreamReader =
                new InputStreamReader(byteArrayInputStream);
           BufferedReader bufferedReader =
                new BufferedReader(inputStreamReader))
      {
        final String line = bufferedReader.readLine();
        assertNotNull(line);

        assertNull(bufferedReader.readLine());

        final int tabPos = line.indexOf('\t');
        assertTrue(tabPos > 0);

        final String name = line.substring(0, tabPos);
        assertEquals(name, rc.getName());

        final int intValue = Integer.parseInt(line.substring(tabPos+1));
        assertEquals(intValue, rc.intValue());
      }
    }
  }



  /**
   * Tests the behavior when looking up result codes by name.
   *
   * @throws  Exception   If an unexpected problem occurs.
   */
  @Test()
  public void testSearch()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    assertEquals(
         LDAPResultCode.main(out, err,
              "--search", "attribute",
              "--output-format", "table"),
         ResultCode.SUCCESS);

    final byte[] outputBytes = out.toByteArray();
    assertTrue(outputBytes.length > 0);

    assertTrue(out.toByteArray().length > 0);

    final String outputStream = StaticUtils.toUTF8String(outputBytes);

    for (final ResultCode rc :
         Arrays.asList(ResultCode.NO_SUCH_ATTRIBUTE,
              ResultCode.UNDEFINED_ATTRIBUTE_TYPE,
              ResultCode.ATTRIBUTE_OR_VALUE_EXISTS,
              ResultCode.INVALID_ATTRIBUTE_SYNTAX))
    {
      assertTrue(outputStream.contains(rc.getName()));
      assertTrue(outputStream.contains(String.valueOf(rc.intValue())));
    }
  }



  /**
   * Tests the behavior when searching for result codes when there are no
   * matches.
   *
   *
   * Tests the behavior when looking up result codes by name.
   *
   * @throws  Exception   If an unexpected problem occurs.
   */
  @Test()
  public void testNoMatches()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    assertEquals(
         LDAPResultCode.main(out, err,
              "--search", "does-not-match-anything"),
         ResultCode.NO_RESULTS_RETURNED);

    assertEquals(out.toByteArray().length, 0);
    assertTrue(err.toByteArray().length > 0);

    out.reset();
    err.reset();

    assertEquals(
         LDAPResultCode.main(out, err,
              "--int-value", "1234567890"),
         ResultCode.NO_RESULTS_RETURNED);

    assertEquals(out.toByteArray().length, 0);
    assertTrue(err.toByteArray().length > 0);
  }



  /**
   * Tests the behavior when using the CSV output format.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCSV()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    assertEquals(
         LDAPResultCode.main(out, err,
              "--list",
              "--output-format", "csv"),
         ResultCode.SUCCESS);

    final byte[] outputBytes = out.toByteArray();
    assertTrue(outputBytes.length > 0);

    assertTrue(out.toByteArray().length > 0);

    try (ByteArrayInputStream byteArrayInputStream =
              new ByteArrayInputStream(outputBytes);
         InputStreamReader inputStreamReader =
              new InputStreamReader(byteArrayInputStream);
         BufferedReader bufferedReader = new BufferedReader(inputStreamReader))
    {
      String line = bufferedReader.readLine();
      assertNotNull(line);

      int numResultCodes = 0;
      while (line != null)
      {
        assertFalse(line.isEmpty());
        numResultCodes++;

        final int commaPos = line.indexOf(',');
        assertTrue(commaPos > 0);

        final String name = line.substring(0, commaPos);
        final int intValue = Integer.parseInt(line.substring(commaPos+1));

        final ResultCode rc = ResultCode.valueOf(intValue);
        assertNotNull(rc);
        assertTrue(name.equalsIgnoreCase(rc.getName()));
        line = bufferedReader.readLine();
      }

      assertEquals(numResultCodes, ResultCode.values().length);
    }
  }



  /**
   * Tests the behavior when using the JSON output format.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testJSON()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    assertEquals(
         LDAPResultCode.main(out, err,
              "--list",
              "--output-format", "json"),
         ResultCode.SUCCESS);

    final byte[] outputBytes = out.toByteArray();
    assertTrue(outputBytes.length > 0);

    assertTrue(out.toByteArray().length > 0);

    try (ByteArrayInputStream byteArrayInputStream =
              new ByteArrayInputStream(outputBytes);
         JSONObjectReader jsonObjectReader =
              new JSONObjectReader(byteArrayInputStream))
    {
      int numResultCodes = 0;
      while (true)
      {
        final JSONObject o = jsonObjectReader.readObject();
        if (o == null)
        {
          break;
        }

        numResultCodes++;

        final String name = o.getFieldAsString("name");
        assertNotNull(name);

        final int intValue = o.getFieldAsInteger("int-value");

        final ResultCode rc = ResultCode.valueOf(intValue);
        assertNotNull(rc);
        assertTrue(name.equalsIgnoreCase(rc.getName()));
      }

      assertEquals(numResultCodes, ResultCode.values().length);
    }
  }



  /**
   * Tests the behavior when using the tab-delimited output format.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTabDelimited()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    assertEquals(
         LDAPResultCode.main(out, err,
              "--list",
              "--output-format", "tab-delimited"),
         ResultCode.SUCCESS);

    final byte[] outputBytes = out.toByteArray();
    assertTrue(outputBytes.length > 0);

    assertTrue(out.toByteArray().length > 0);

    try (ByteArrayInputStream byteArrayInputStream =
              new ByteArrayInputStream(outputBytes);
         InputStreamReader inputStreamReader =
              new InputStreamReader(byteArrayInputStream);
         BufferedReader bufferedReader = new BufferedReader(inputStreamReader))
    {
      String line = bufferedReader.readLine();
      assertNotNull(line);

      int numResultCodes = 0;
      while (line != null)
      {
        assertFalse(line.isEmpty());
        numResultCodes++;

        final int commaPos = line.indexOf('\t');
        assertTrue(commaPos > 0);

        final String name = line.substring(0, commaPos);
        final int intValue = Integer.parseInt(line.substring(commaPos+1));

        final ResultCode rc = ResultCode.valueOf(intValue);
        assertNotNull(rc);
        assertTrue(name.equalsIgnoreCase(rc.getName()));
        line = bufferedReader.readLine();
      }

      assertEquals(numResultCodes, ResultCode.values().length);
    }
  }
}
