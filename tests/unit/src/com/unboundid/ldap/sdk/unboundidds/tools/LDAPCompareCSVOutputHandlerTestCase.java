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



/**
 * This class provides a set of test cases for the {@code LDAPCompare} output
 * handler that formats messages as comma-separated values.
 */
public final class LDAPCompareCSVOutputHandlerTestCase
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

    final LDAPCompareCSVOutputHandler outputHandler =
         new LDAPCompareCSVOutputHandler();

    assertNotNull(outputHandler.getHeaderLines());
    assertTrue(outputHandler.getHeaderLines().length == 1);
    assertEquals(outputHandler.getHeaderLines()[0],
         "Entry DN,Attribute Name,Assertion Value,Result Code Value," +
              "Result Code Name");

    final String formattedOutput =
         outputHandler.formatResult(compareRequest, compareResult);
    assertNotNull(formattedOutput);
    assertEquals(formattedOutput,
         "\"dc=example,dc=com\",objectClass,top,6,compare true");
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

    final LDAPCompareCSVOutputHandler outputHandler =
         new LDAPCompareCSVOutputHandler();

    assertNotNull(outputHandler.getHeaderLines());
    assertTrue(outputHandler.getHeaderLines().length == 1);
    assertEquals(outputHandler.getHeaderLines()[0],
         "Entry DN,Attribute Name,Assertion Value,Result Code Value," +
              "Result Code Name");

    final String formattedOutput =
         outputHandler.formatResult(compareRequest, compareResult);
    assertNotNull(formattedOutput);
    assertEquals(formattedOutput,
         ",testAttr,missingValue,5,compare false");
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

    final LDAPCompareCSVOutputHandler outputHandler =
         new LDAPCompareCSVOutputHandler();

    assertNotNull(outputHandler.getHeaderLines());
    assertTrue(outputHandler.getHeaderLines().length == 1);
    assertEquals(outputHandler.getHeaderLines()[0],
         "Entry DN,Attribute Name,Assertion Value,Result Code Value," +
              "Result Code Name");

    final String formattedOutput =
         outputHandler.formatResult(compareRequest, compareResult);
    assertNotNull(formattedOutput);
    assertEquals(formattedOutput,
         "\"ou=missing,dc=example,dc=com\",testAttr,irrelevant,32," +
              "no such object");
  }
}
