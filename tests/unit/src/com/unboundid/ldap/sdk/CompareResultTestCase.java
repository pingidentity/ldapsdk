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
package com.unboundid.ldap.sdk;



import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the CompareResult class.
 */
public class CompareResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with a "true" result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1True()
         throws Exception
  {
    LDAPResult result = new LDAPResult(1, ResultCode.COMPARE_TRUE, null, null,
         (String[]) null, (Control[]) null);

    CompareResult compareResult = new CompareResult(result);

    assertEquals(compareResult.getResultCode(), ResultCode.COMPARE_TRUE);
    assertTrue(compareResult.compareMatched());

    assertNull(compareResult.getDiagnosticMessage());

    assertNull(compareResult.getMatchedDN());

    assertNotNull(compareResult.getReferralURLs());
    assertEquals(compareResult.getReferralURLs().length, 0);

    assertNotNull(compareResult.getResponseControls());
    assertEquals(compareResult.getResponseControls().length, 0);

    assertEquals(compareResult.getMessageID(), 1);

    assertNotNull(compareResult.toString());
  }



  /**
   * Tests the first constructor with a "false" result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1False()
         throws Exception
  {
    LDAPResult result = new LDAPResult(1, ResultCode.COMPARE_FALSE, null, null,
         (String[]) null, (Control[]) null);

    CompareResult compareResult = new CompareResult(result);

    assertEquals(compareResult.getResultCode(), ResultCode.COMPARE_FALSE);
    assertFalse(compareResult.compareMatched());

    assertNull(compareResult.getDiagnosticMessage());

    assertNull(compareResult.getMatchedDN());

    assertNotNull(compareResult.getReferralURLs());
    assertEquals(compareResult.getReferralURLs().length, 0);

    assertNotNull(compareResult.getResponseControls());
    assertEquals(compareResult.getResponseControls().length, 0);

    assertEquals(compareResult.getMessageID(), 1);

    assertNotNull(compareResult.toString());
  }



  /**
   * Tests the first constructor with an error result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Error()
         throws Exception
  {
    String[] referralURLs =
    {
      "ldap://test1.example.com/dc=example,dc=com",
      "ldap://test2.example.com/dc=example,dc=com"
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    LDAPException exception = new LDAPException(ResultCode.NO_SUCH_OBJECT,
         "The target entry does not exist", "dc=example,dc=com", referralURLs,
         controls);

    CompareResult compareResult = new CompareResult(exception);

    assertEquals(compareResult.getResultCode(), ResultCode.NO_SUCH_OBJECT);
    assertFalse(compareResult.compareMatched());

    assertNotNull(compareResult.getDiagnosticMessage());

    assertNotNull(compareResult.getMatchedDN());

    assertNotNull(compareResult.getReferralURLs());
    assertEquals(compareResult.getReferralURLs().length, 2);

    assertNotNull(compareResult.getResponseControls());
    assertEquals(compareResult.getResponseControls().length, 2);

    assertNotNull(compareResult.toString());
  }



  /**
   * Tests the second constructor with a "true" result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2True()
         throws Exception
  {
    CompareResult compareResult =
         new CompareResult(1, ResultCode.COMPARE_TRUE, null, null, null, null);

    assertEquals(compareResult.getResultCode(), ResultCode.COMPARE_TRUE);
    assertTrue(compareResult.compareMatched());

    assertNull(compareResult.getDiagnosticMessage());

    assertNull(compareResult.getMatchedDN());

    assertNotNull(compareResult.getReferralURLs());
    assertEquals(compareResult.getReferralURLs().length, 0);

    assertNotNull(compareResult.getResponseControls());
    assertEquals(compareResult.getResponseControls().length, 0);

    assertEquals(compareResult.getMessageID(), 1);

    assertNotNull(compareResult.toString());
  }



  /**
   * Tests the second constructor with a "false" result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2False()
         throws Exception
  {
    CompareResult compareResult =
         new CompareResult(1, ResultCode.COMPARE_FALSE, null, null, null, null);

    assertEquals(compareResult.getResultCode(), ResultCode.COMPARE_FALSE);
    assertFalse(compareResult.compareMatched());

    assertNull(compareResult.getDiagnosticMessage());

    assertNull(compareResult.getMatchedDN());

    assertNotNull(compareResult.getReferralURLs());
    assertEquals(compareResult.getReferralURLs().length, 0);

    assertNotNull(compareResult.getResponseControls());
    assertEquals(compareResult.getResponseControls().length, 0);

    assertEquals(compareResult.getMessageID(), 1);

    assertNotNull(compareResult.toString());
  }



  /**
   * Tests the second constructor with an error result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Error()
         throws Exception
  {
    String[] referralURLs =
    {
      "ldap://test1.example.com/dc=example,dc=com",
      "ldap://test2.example.com/dc=example,dc=com"
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    CompareResult compareResult =
         new CompareResult(1, ResultCode.NO_SUCH_OBJECT,
                           "The target entry does not exist",
                           "dc=example,dc=com", referralURLs, controls);

    assertEquals(compareResult.getResultCode(), ResultCode.NO_SUCH_OBJECT);
    assertFalse(compareResult.compareMatched());

    assertNotNull(compareResult.getDiagnosticMessage());

    assertNotNull(compareResult.getMatchedDN());

    assertNotNull(compareResult.getReferralURLs());
    assertEquals(compareResult.getReferralURLs().length, 2);

    assertNotNull(compareResult.getResponseControls());
    assertEquals(compareResult.getResponseControls().length, 2);

    assertEquals(compareResult.getMessageID(), 1);

    assertNotNull(compareResult.toString());
  }
}
