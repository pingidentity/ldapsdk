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



import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the LDAPSearchException class.
 */
public class LDAPSearchExceptionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first LDAPSearchException constructor.
   *
   * @param  resultCode  The result code to use for the test exception.
   */
  @Test(dataProvider = "testResultCodes")
  public void testConstructor1(ResultCode resultCode)
  {
    LDAPSearchException searchException =
         new LDAPSearchException(resultCode, resultCode.getName());

    assertEquals(searchException.getResultCode(), resultCode);
    assertNotNull(searchException.getMessage());
    assertNull(searchException.getCause());
    assertNull(searchException.getMatchedDN());
    assertNotNull(searchException.getReferralURLs());
    assertEquals(searchException.getReferralURLs().length, 0);
    assertNotNull(searchException.getResponseControls());
    assertEquals(searchException.getResponseControls().length, 0);
    assertEquals(searchException.getEntryCount(), 0);
    assertEquals(searchException.getReferenceCount(), 0);
    assertNull(searchException.getSearchEntries());
    assertNull(searchException.getSearchReferences());
    assertNotNull(searchException.toString());
  }



  /**
   * Tests the second LDAPSearchException constructor.
   *
   * @param  resultCode  The result code to use for the test exception.
   */
  @Test(dataProvider = "testResultCodes")
  public void testConstructor2(ResultCode resultCode)
  {
    LDAPSearchException searchException =
         new LDAPSearchException(resultCode, resultCode.getName(),
                                 new Exception());

    assertEquals(searchException.getResultCode(), resultCode);
    assertNotNull(searchException.getMessage());
    assertNotNull(searchException.getCause());
    assertNull(searchException.getMatchedDN());
    assertNotNull(searchException.getReferralURLs());
    assertEquals(searchException.getReferralURLs().length, 0);
    assertNotNull(searchException.getResponseControls());
    assertEquals(searchException.getResponseControls().length, 0);
    assertEquals(searchException.getEntryCount(), 0);
    assertEquals(searchException.getReferenceCount(), 0);
    assertNull(searchException.getSearchEntries());
    assertNull(searchException.getSearchReferences());
    assertNotNull(searchException.toString());
  }



  /**
   * Tests the third LDAPSearchException constructor.
   *
   * @param  resultCode  The result code to use for the test exception.
   */
  @Test(dataProvider = "testResultCodes")
  public void testConstructor3(ResultCode resultCode)
  {
    String[] referralURLs =
    {
      "ldap://test1.example.com/dc=example,dc=com",
      "ldap://test2.example.com/dc=example,dc=com"
    };

    Control[] responseControls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    LDAPException le =
         new LDAPException(resultCode, "Error message", "dc=example,dc=com",
                           referralURLs, responseControls);

    LDAPSearchException searchException =
         new LDAPSearchException(le);

    assertEquals(searchException.getResultCode(), resultCode);
    assertNotNull(searchException.getMessage());
    assertNotNull(searchException.getCause());
    assertNotNull(searchException.getMatchedDN());
    assertNotNull(searchException.getReferralURLs());
    assertEquals(searchException.getReferralURLs().length, 2);
    assertNotNull(searchException.getResponseControls());
    assertEquals(searchException.getResponseControls().length, 2);
    assertEquals(searchException.getEntryCount(), 0);
    assertEquals(searchException.getReferenceCount(), 0);
    assertNull(searchException.getSearchEntries());
    assertNull(searchException.getSearchReferences());
    assertNotNull(searchException.toString());
  }



  /**
   * Tests the third LDAPSearchException constructor with an exception that is
   * already a search exception.
   *
   * @param  resultCode  The result code to use for the test exception.
   */
  @Test(dataProvider = "testResultCodes")
  public void testConstructor3WithSearchException(ResultCode resultCode)
  {
    String[] referralURLs =
    {
      "ldap://test1.example.com/dc=example,dc=com",
      "ldap://test2.example.com/dc=example,dc=com"
    };

    Control[] responseControls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    LDAPException le =
         new LDAPException(resultCode, "Error message", "dc=example,dc=com",
                           referralURLs, responseControls);
    LDAPSearchException lse = new LDAPSearchException(le);

    LDAPSearchException searchException =
         new LDAPSearchException(lse);

    assertEquals(searchException.getResultCode(), resultCode);
    assertNotNull(searchException.getMessage());
    assertNotNull(searchException.getCause());
    assertNotNull(searchException.getMatchedDN());
    assertNotNull(searchException.getReferralURLs());
    assertEquals(searchException.getReferralURLs().length, 2);
    assertNotNull(searchException.getResponseControls());
    assertEquals(searchException.getResponseControls().length, 2);
    assertEquals(searchException.getEntryCount(), 0);
    assertEquals(searchException.getReferenceCount(), 0);
    assertNull(searchException.getSearchEntries());
    assertNull(searchException.getSearchReferences());
    assertNotNull(searchException.toString());
  }



  /**
   * Tests the fourth LDAPSearchException constructor.
   *
   * @param  resultCode  The result code to use for the test exception.
   */
  @Test(dataProvider = "testResultCodes")
  public void testConstructor4(ResultCode resultCode)
  {
    SearchResult searchResult =
         new SearchResult(1, resultCode, "Error Message", "dc=example,dc=com",
                          null, 0, 0, null);

    LDAPSearchException searchException =
         new LDAPSearchException(searchResult);

    assertEquals(searchException.getResultCode(), resultCode);
    assertNotNull(searchException.getMessage());
    assertNull(searchException.getCause());
    assertNotNull(searchException.getMatchedDN());
    assertNotNull(searchException.getReferralURLs());
    assertEquals(searchException.getReferralURLs().length, 0);
    assertNotNull(searchException.getResponseControls());
    assertEquals(searchException.getResponseControls().length, 0);
    assertEquals(searchException.getEntryCount(), 0);
    assertEquals(searchException.getReferenceCount(), 0);
    assertNull(searchException.getSearchEntries());
    assertNull(searchException.getSearchReferences());
    assertNotNull(searchException.toString());
  }



  /**
   * Retrieves a set of result code values that may be used for testing
   * purposes.
   *
   * @return  A set of result code values that may be used for testing purposes.
   */
  @DataProvider(name = "testResultCodes")
  public Object[][] getTestResultCodes()
  {
    return new Object[][]
    {
      new Object[] { ResultCode.SUCCESS },
      new Object[] { ResultCode.OPERATIONS_ERROR },
      new Object[] { ResultCode.PROTOCOL_ERROR },
      new Object[] { ResultCode.TIME_LIMIT_EXCEEDED },
      new Object[] { ResultCode.SIZE_LIMIT_EXCEEDED },
      new Object[] { ResultCode.COMPARE_FALSE },
      new Object[] { ResultCode.COMPARE_TRUE },
      new Object[] { ResultCode.AUTH_METHOD_NOT_SUPPORTED },
      new Object[] { ResultCode.STRONG_AUTH_REQUIRED },
      new Object[] { ResultCode.REFERRAL },
      new Object[] { ResultCode.ADMIN_LIMIT_EXCEEDED },
      new Object[] { ResultCode.UNAVAILABLE_CRITICAL_EXTENSION },
      new Object[] { ResultCode.CONFIDENTIALITY_REQUIRED },
      new Object[] { ResultCode.SASL_BIND_IN_PROGRESS },
      new Object[] { ResultCode.NO_SUCH_ATTRIBUTE },
      new Object[] { ResultCode.UNDEFINED_ATTRIBUTE_TYPE },
      new Object[] { ResultCode.INAPPROPRIATE_MATCHING },
      new Object[] { ResultCode.CONSTRAINT_VIOLATION },
      new Object[] { ResultCode.ATTRIBUTE_OR_VALUE_EXISTS },
      new Object[] { ResultCode.INVALID_ATTRIBUTE_SYNTAX },
      new Object[] { ResultCode.NO_SUCH_OBJECT },
      new Object[] { ResultCode.ALIAS_PROBLEM },
      new Object[] { ResultCode.INVALID_DN_SYNTAX },
      new Object[] { ResultCode.ALIAS_DEREFERENCING_PROBLEM },
      new Object[] { ResultCode.INAPPROPRIATE_AUTHENTICATION },
      new Object[] { ResultCode.INVALID_CREDENTIALS },
      new Object[] { ResultCode.INSUFFICIENT_ACCESS_RIGHTS },
      new Object[] { ResultCode.BUSY },
      new Object[] { ResultCode.UNAVAILABLE },
      new Object[] { ResultCode.UNWILLING_TO_PERFORM },
      new Object[] { ResultCode.LOOP_DETECT },
      new Object[] { ResultCode.SORT_CONTROL_MISSING },
      new Object[] { ResultCode.OFFSET_RANGE_ERROR },
      new Object[] { ResultCode.NAMING_VIOLATION },
      new Object[] { ResultCode.OBJECT_CLASS_VIOLATION },
      new Object[] { ResultCode.NOT_ALLOWED_ON_NONLEAF },
      new Object[] { ResultCode.NOT_ALLOWED_ON_RDN },
      new Object[] { ResultCode.ENTRY_ALREADY_EXISTS },
      new Object[] { ResultCode.OBJECT_CLASS_MODS_PROHIBITED },
      new Object[] { ResultCode.AFFECTS_MULTIPLE_DSAS },
      new Object[] { ResultCode.VIRTUAL_LIST_VIEW_ERROR },
      new Object[] { ResultCode.OTHER },
      new Object[] { ResultCode.SERVER_DOWN },
      new Object[] { ResultCode.LOCAL_ERROR },
      new Object[] { ResultCode.ENCODING_ERROR },
      new Object[] { ResultCode.DECODING_ERROR },
      new Object[] { ResultCode.TIMEOUT },
      new Object[] { ResultCode.AUTH_UNKNOWN },
      new Object[] { ResultCode.FILTER_ERROR },
      new Object[] { ResultCode.USER_CANCELED },
      new Object[] { ResultCode.PARAM_ERROR },
      new Object[] { ResultCode.NO_MEMORY },
      new Object[] { ResultCode.CONNECT_ERROR },
      new Object[] { ResultCode.NOT_SUPPORTED },
      new Object[] { ResultCode.CONTROL_NOT_FOUND },
      new Object[] { ResultCode.NO_RESULTS_RETURNED },
      new Object[] { ResultCode.MORE_RESULTS_TO_RETURN },
      new Object[] { ResultCode.CLIENT_LOOP },
      new Object[] { ResultCode.REFERRAL_LIMIT_EXCEEDED },
      new Object[] { ResultCode.CANCELED },
      new Object[] { ResultCode.NO_SUCH_OPERATION },
      new Object[] { ResultCode.TOO_LATE },
      new Object[] { ResultCode.CANNOT_CANCEL },
      new Object[] { ResultCode.ASSERTION_FAILED },
      new Object[] { ResultCode.AUTHORIZATION_DENIED },
      new Object[] { ResultCode.NO_OPERATION },
      new Object[] { ResultCode.valueOf(999) }
    };
  }



  /**
   * Provides coverage for the {@code getExceptionMessage} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetExceptionMessage()
         throws Exception
  {
    final LDAPSearchException lse = new LDAPSearchException(
         ResultCode.OTHER, "The search failed",
         new NullPointerException("NPE"));

    final String defaultMessage = lse.getExceptionMessage(false, false);
    assertFalse(defaultMessage.contains("trace="));
    assertFalse(defaultMessage.contains("cause="));

    final String messageWithCause = lse.getExceptionMessage(true, false);
    assertFalse(messageWithCause.contains("trace="));
    assertTrue(messageWithCause.contains("cause="));

    final String messageWithTrace = lse.getExceptionMessage(false, true);
    assertTrue(messageWithTrace.contains("trace="));
    assertTrue(messageWithTrace.contains("cause="));
  }
}
