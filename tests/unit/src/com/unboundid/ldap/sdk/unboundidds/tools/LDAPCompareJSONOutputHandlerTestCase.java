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



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.CompareRequest;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;



/**
 * This class provides a set of test cases for the {@code LDAPCompare} output
 * handler that formats messages as JSON objects.
 */
public final class LDAPCompareJSONOutputHandlerTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the output handler for a compare operation in which
   * the assertion matched.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareTrueResult()
         throws Exception
  {
    final CompareRequest compareRequest =
         new CompareRequest("dc=example,dc=com", "objectClass", "top");
    final LDAPResult compareResult =
         new LDAPResult(-1, ResultCode.COMPARE_TRUE);

    final LDAPCompareJSONOutputHandler outputHandler =
         new LDAPCompareJSONOutputHandler();

    assertNotNull(outputHandler.getHeaderLines());
    assertTrue(outputHandler.getHeaderLines().length == 0);

    final String formattedOutput =
         outputHandler.formatResult(compareRequest, compareResult);
    assertNotNull(formattedOutput);
    assertEquals(formattedOutput,
         new JSONObject(
              new JSONField("entry-dn", "dc=example,dc=com"),
              new JSONField("attribute-name", "objectClass"),
              new JSONField("assertion-value", "top"),
              new JSONField("result-code-value", 6),
              new JSONField("result-code-name", "compare true")).
              toSingleLineString());
  }



  /**
   * Tests the behavior of the output handler for a compare operation in which
   * the assertion did not match.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareFalseResult()
         throws Exception
  {
    final CompareRequest compareRequest =
         new CompareRequest("", "testAttr", "missingValue");
    final LDAPResult compareResult =
         new LDAPResult(-1, ResultCode.COMPARE_FALSE);

    final LDAPCompareJSONOutputHandler outputHandler =
         new LDAPCompareJSONOutputHandler();

    assertNotNull(outputHandler.getHeaderLines());
    assertTrue(outputHandler.getHeaderLines().length == 0);

    final String formattedOutput =
         outputHandler.formatResult(compareRequest, compareResult);
    assertNotNull(formattedOutput);
    assertEquals(formattedOutput,
         new JSONObject(
              new JSONField("entry-dn", ""),
              new JSONField("attribute-name", "testAttr"),
              new JSONField("assertion-value", "missingValue"),
              new JSONField("result-code-value", 5),
              new JSONField("result-code-name", "compare false")).
              toSingleLineString());
  }



  /**
   * Tests the behavior of the output handler for a compare operation in which
   * the assertion yielded an error result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testErrorResult()
         throws Exception
  {
    final CompareRequest compareRequest = new CompareRequest(
         "ou=missing,dc=example,dc=com", "testAttr", "irrelevant");

    final String[] referralURLs =
    {
      "ldap://ds1.example.com/",
      "ldap://ds2.example.com/"
    };

    final LDAPResult compareResult =
         new LDAPResult(-1, ResultCode.NO_SUCH_OBJECT,
              "Entry 'ou=missing,dc=example,dc=com' does not exist",
              "dc=example,dc=com", referralURLs, null);

    final LDAPCompareJSONOutputHandler outputHandler =
         new LDAPCompareJSONOutputHandler();

    assertNotNull(outputHandler.getHeaderLines());
    assertTrue(outputHandler.getHeaderLines().length == 0);

    final String formattedOutput =
         outputHandler.formatResult(compareRequest, compareResult);
    assertNotNull(formattedOutput);
    assertEquals(formattedOutput,
         new JSONObject(
              new JSONField("entry-dn", "ou=missing,dc=example,dc=com"),
              new JSONField("attribute-name", "testAttr"),
              new JSONField("assertion-value", "irrelevant"),
              new JSONField("result-code-value", 32),
              new JSONField("result-code-name", "no such object"),
              new JSONField("diagnostic-message",
                   "Entry 'ou=missing,dc=example,dc=com' does not exist"),
              new JSONField("matched-dn", "dc=example,dc=com"),
              new JSONField("referral-urls", new JSONArray(
                   new JSONString("ldap://ds1.example.com/"),
                   new JSONString("ldap://ds2.example.com/")))).
              toSingleLineString());
  }
}
