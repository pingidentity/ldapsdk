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



import java.net.ConnectException;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;



/**
 * This class provides a set of test cases for the LDAPException class.
 */
public class LDAPExceptionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first LDAPException constructor, which takes a result code.
   *
   * @param  resultCode  The result code to use for the test exception.
   */
  @Test(dataProvider = "testResultCodes")
  public void testConstructor1(ResultCode resultCode)
  {
    LDAPException ldapException = new LDAPException(resultCode);

    assertEquals(ldapException.getResultCode(), resultCode);
    assertNotNull(ldapException.getMessage());
    assertNull(ldapException.getCause());
    assertNull(ldapException.getMatchedDN());
    assertNotNull(ldapException.getReferralURLs());
    assertEquals(ldapException.getReferralURLs().length, 0);
    assertFalse(ldapException.hasResponseControl());
    assertFalse(ldapException.hasResponseControl("1.2.3.4"));
    assertFalse(ldapException.hasResponseControl("1.2.3.5"));
    assertNotNull(ldapException.getResponseControls());
    assertEquals(ldapException.getResponseControls().length, 0);

    LDAPResult r = ldapException.toLDAPResult();

    assertEquals(r.getResultCode(), resultCode);
    assertNotNull(r.getDiagnosticMessage());
    assertNull(r.getMatchedDN());
    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);
    assertFalse(r.hasResponseControl());
    assertFalse(r.hasResponseControl("1.2.3.4"));
    assertFalse(r.hasResponseControl("1.2.3.5"));
    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(ldapException.getResultString());

    assertNotNull(ldapException.toString());
  }



  /**
   * Tests the second LDAPException constructor, which takes a result code and a
   * cause.
   *
   * @param  resultCode  The result code to use for the test exception.
   */
  @Test(dataProvider = "testResultCodes")
  public void testConstructor2(ResultCode resultCode)
  {
    LDAPException ldapException =
         new LDAPException(resultCode, new Exception());

    assertEquals(ldapException.getResultCode(), resultCode);
    assertNotNull(ldapException.getMessage());
    assertNotNull(ldapException.getCause());
    assertNull(ldapException.getMatchedDN());
    assertNotNull(ldapException.getReferralURLs());
    assertEquals(ldapException.getReferralURLs().length, 0);
    assertFalse(ldapException.hasResponseControl());
    assertFalse(ldapException.hasResponseControl("1.2.3.4"));
    assertFalse(ldapException.hasResponseControl("1.2.3.5"));
    assertNotNull(ldapException.getResponseControls());
    assertEquals(ldapException.getResponseControls().length, 0);

    LDAPResult r = ldapException.toLDAPResult();

    assertEquals(r.getResultCode(), resultCode);
    assertNotNull(r.getDiagnosticMessage());
    assertNull(r.getMatchedDN());
    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);
    assertFalse(r.hasResponseControl());
    assertFalse(r.hasResponseControl("1.2.3.4"));
    assertFalse(r.hasResponseControl("1.2.3.5"));
    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(ldapException.getResultString());

    assertNotNull(ldapException.toString());
  }



  /**
   * Tests the third LDAPException constructor, which takes a result code and an
   * error message.
   *
   * @param  resultCode  The result code to use for the test exception.
   */
  @Test(dataProvider = "testResultCodes")
  public void testConstructor3(ResultCode resultCode)
  {
    LDAPException ldapException =
         new LDAPException(resultCode, "foo");

    assertEquals(ldapException.getResultCode(), resultCode);
    assertNotNull(ldapException.getMessage());
    assertEquals(ldapException.getMessage(), "foo");
    assertNull(ldapException.getCause());
    assertNull(ldapException.getMatchedDN());
    assertNotNull(ldapException.getReferralURLs());
    assertEquals(ldapException.getReferralURLs().length, 0);
    assertFalse(ldapException.hasResponseControl());
    assertFalse(ldapException.hasResponseControl("1.2.3.4"));
    assertFalse(ldapException.hasResponseControl("1.2.3.5"));
    assertNotNull(ldapException.getResponseControls());
    assertEquals(ldapException.getResponseControls().length, 0);

    LDAPResult r = ldapException.toLDAPResult();

    assertEquals(r.getResultCode(), resultCode);
    assertNotNull(r.getDiagnosticMessage());
    assertNull(r.getMatchedDN());
    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);
    assertFalse(r.hasResponseControl());
    assertFalse(r.hasResponseControl("1.2.3.4"));
    assertFalse(r.hasResponseControl("1.2.3.5"));
    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(ldapException.getResultString());

    assertNotNull(ldapException.toString());
  }



  /**
   * Tests the fourth LDAPException constructor, which takes a result code,
   * error message, and cause.
   *
   * @param  resultCode  The result code to use for the test exception.
   */
  @Test(dataProvider = "testResultCodes")
  public void testConstructor4(ResultCode resultCode)
  {
    LDAPException ldapException =
         new LDAPException(resultCode, "foo", new Exception());

    assertEquals(ldapException.getResultCode(), resultCode);
    assertNotNull(ldapException.getMessage());
    assertEquals(ldapException.getMessage(), "foo");
    assertNotNull(ldapException.getCause());
    assertNull(ldapException.getMatchedDN());
    assertNotNull(ldapException.getReferralURLs());
    assertEquals(ldapException.getReferralURLs().length, 0);
    assertFalse(ldapException.hasResponseControl());
    assertFalse(ldapException.hasResponseControl("1.2.3.4"));
    assertFalse(ldapException.hasResponseControl("1.2.3.5"));
    assertNotNull(ldapException.getResponseControls());
    assertEquals(ldapException.getResponseControls().length, 0);

    LDAPResult r = ldapException.toLDAPResult();

    assertEquals(r.getResultCode(), resultCode);
    assertNotNull(r.getDiagnosticMessage());
    assertNull(r.getMatchedDN());
    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);
    assertFalse(r.hasResponseControl());
    assertFalse(r.hasResponseControl("1.2.3.4"));
    assertFalse(r.hasResponseControl("1.2.3.5"));
    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(ldapException.getResultString());

    assertNotNull(ldapException.toString());
  }



  /**
   * Tests the fifth LDAPException constructor, which takes a result code, error
   * message, matched DN, and set of referral URLs.
   *
   * @param  resultCode  The result code to use for the test exception.
   */
  @Test(dataProvider = "testResultCodes")
  public void testConstructor5(ResultCode resultCode)
  {
    String[] referralURLs = { "ldap://server.example.com/dc=example,dc=com" };

    LDAPException ldapException =
         new LDAPException(resultCode, "foo", "dc=example,dc=com",
                           referralURLs);

    assertEquals(ldapException.getResultCode(), resultCode);
    assertNotNull(ldapException.getMessage());
    assertEquals(ldapException.getMessage(), "foo");
    assertNull(ldapException.getCause());
    assertNotNull(ldapException.getMatchedDN());
    assertEquals(ldapException.getMatchedDN(), "dc=example,dc=com");
    assertNotNull(ldapException.getReferralURLs());
    assertEquals(ldapException.getReferralURLs().length, 1);
    assertFalse(ldapException.hasResponseControl());
    assertFalse(ldapException.hasResponseControl("1.2.3.4"));
    assertFalse(ldapException.hasResponseControl("1.2.3.5"));
    assertNotNull(ldapException.getResponseControls());
    assertEquals(ldapException.getResponseControls().length, 0);

    LDAPResult r = ldapException.toLDAPResult();

    assertEquals(r.getResultCode(), resultCode);
    assertNotNull(r.getDiagnosticMessage());
    assertNotNull(r.getMatchedDN());
    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 1);
    assertFalse(r.hasResponseControl());
    assertFalse(r.hasResponseControl("1.2.3.4"));
    assertFalse(r.hasResponseControl("1.2.3.5"));
    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(ldapException.getResultString());

    assertNotNull(ldapException.toString());
  }



  /**
   * Tests the fifth LDAPException constructor, which takes a result code, error
   * message, matched DN, and set of referral URLs, using a null set of referral
   * URLs.
   *
   * @param  resultCode  The result code to use for the test exception.
   */
  @Test(dataProvider = "testResultCodes")
  public void testConstructor5NullReferralURLs(ResultCode resultCode)
  {
    LDAPException ldapException =
         new LDAPException(resultCode, "foo", "dc=example,dc=com", null);

    assertEquals(ldapException.getResultCode(), resultCode);
    assertNotNull(ldapException.getMessage());
    assertEquals(ldapException.getMessage(), "foo");
    assertNull(ldapException.getCause());
    assertNotNull(ldapException.getMatchedDN());
    assertEquals(ldapException.getMatchedDN(), "dc=example,dc=com");
    assertNotNull(ldapException.getReferralURLs());
    assertEquals(ldapException.getReferralURLs().length, 0);
    assertFalse(ldapException.hasResponseControl());
    assertFalse(ldapException.hasResponseControl("1.2.3.4"));
    assertFalse(ldapException.hasResponseControl("1.2.3.5"));
    assertNotNull(ldapException.getResponseControls());
    assertEquals(ldapException.getResponseControls().length, 0);

    LDAPResult r = ldapException.toLDAPResult();

    assertEquals(r.getResultCode(), resultCode);
    assertNotNull(r.getDiagnosticMessage());
    assertNotNull(r.getMatchedDN());
    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);
    assertFalse(r.hasResponseControl());
    assertFalse(r.hasResponseControl("1.2.3.4"));
    assertFalse(r.hasResponseControl("1.2.3.5"));
    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(ldapException.getResultString());

    assertNotNull(ldapException.toString());
  }



  /**
   * Tests the sixth LDAPException constructor, which takes a result code, error
   * message, matched DN, set of referral URLs, and cause.
   *
   * @param  resultCode  The result code to use for the test exception.
   */
  @Test(dataProvider = "testResultCodes")
  public void testConstructor6(ResultCode resultCode)
  {
    String[] referralURLs =
    {
      "ldap://server1.example.com/dc=example,dc=com",
      "ldap://server2.example.com/dc=example,dc=com"
    };

    LDAPException ldapException =
         new LDAPException(resultCode, "foo", "dc=example,dc=com",
                           referralURLs, new Exception());

    assertEquals(ldapException.getResultCode(), resultCode);
    assertNotNull(ldapException.getMessage());
    assertEquals(ldapException.getMessage(), "foo");
    assertNotNull(ldapException.getCause());
    assertNotNull(ldapException.getMatchedDN());
    assertEquals(ldapException.getMatchedDN(), "dc=example,dc=com");
    assertNotNull(ldapException.getReferralURLs());
    assertEquals(ldapException.getReferralURLs().length, 2);
    assertFalse(ldapException.hasResponseControl());
    assertFalse(ldapException.hasResponseControl("1.2.3.4"));
    assertFalse(ldapException.hasResponseControl("1.2.3.5"));
    assertNotNull(ldapException.getResponseControls());
    assertEquals(ldapException.getResponseControls().length, 0);

    LDAPResult r = ldapException.toLDAPResult();

    assertEquals(r.getResultCode(), resultCode);
    assertNotNull(r.getDiagnosticMessage());
    assertNotNull(r.getMatchedDN());
    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 2);
    assertFalse(r.hasResponseControl());
    assertFalse(r.hasResponseControl("1.2.3.4"));
    assertFalse(r.hasResponseControl("1.2.3.5"));
    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(ldapException.getResultString());

    assertNotNull(ldapException.toString());
  }



  /**
   * Tests the sixth LDAPException constructor, which takes a result code, error
   * message, matched DN, set of referral URLs, and cause, using a null set of
   * referral URLs.
   *
   * @param  resultCode  The result code to use for the test exception.
   */
  @Test(dataProvider = "testResultCodes")
  public void testConstructor6NullReferralURLs(ResultCode resultCode)
  {
    LDAPException ldapException =
         new LDAPException(resultCode, "foo", "dc=example,dc=com", null,
                           new Exception());

    assertEquals(ldapException.getResultCode(), resultCode);
    assertNotNull(ldapException.getMessage());
    assertEquals(ldapException.getMessage(), "foo");
    assertNotNull(ldapException.getCause());
    assertNotNull(ldapException.getMatchedDN());
    assertEquals(ldapException.getMatchedDN(), "dc=example,dc=com");
    assertNotNull(ldapException.getReferralURLs());
    assertEquals(ldapException.getReferralURLs().length, 0);
    assertFalse(ldapException.hasResponseControl());
    assertFalse(ldapException.hasResponseControl("1.2.3.4"));
    assertFalse(ldapException.hasResponseControl("1.2.3.5"));
    assertNotNull(ldapException.getResponseControls());
    assertEquals(ldapException.getResponseControls().length, 0);

    LDAPResult r = ldapException.toLDAPResult();

    assertEquals(r.getResultCode(), resultCode);
    assertNotNull(r.getDiagnosticMessage());
    assertNotNull(r.getMatchedDN());
    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);
    assertFalse(r.hasResponseControl());
    assertFalse(r.hasResponseControl("1.2.3.4"));
    assertFalse(r.hasResponseControl("1.2.3.5"));
    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(ldapException.getResultString());

    assertNotNull(ldapException.toString());
  }



  /**
   * Tests the seventh LDAPException constructor, which takes a result code,
   * error message, matched DN, set of referral URLs, and set of response
   * controls.
   *
   * @param  resultCode  The result code to use for the test exception.
   */
  @Test(dataProvider = "testResultCodes")
  public void testConstructor7(ResultCode resultCode)
  {
    String[] referralURLs =
    {
      "ldap://server1.example.com/dc=example,dc=com",
      "ldap://server2.example.com/dc=example,dc=com"
    };

    Control[] responseControls =
    {
      new Control("1.2.3.4", true, new ASN1OctetString())
    };

    LDAPException ldapException =
         new LDAPException(resultCode, "foo", "dc=example,dc=com",
                           referralURLs, responseControls);

    assertEquals(ldapException.getResultCode(), resultCode);
    assertNotNull(ldapException.getMessage());
    assertEquals(ldapException.getMessage(), "foo");
    assertNull(ldapException.getCause());
    assertNotNull(ldapException.getMatchedDN());
    assertEquals(ldapException.getMatchedDN(), "dc=example,dc=com");
    assertNotNull(ldapException.getReferralURLs());
    assertEquals(ldapException.getReferralURLs().length, 2);
    assertTrue(ldapException.hasResponseControl());
    assertTrue(ldapException.hasResponseControl("1.2.3.4"));
    assertFalse(ldapException.hasResponseControl("1.2.3.5"));
    assertNotNull(ldapException.getResponseControls());
    assertNotNull(ldapException.getResponseControl("1.2.3.4"));
    assertNull(ldapException.getResponseControl("1.2.3.5"));
    assertEquals(ldapException.getResponseControls().length, 1);

    LDAPResult r = ldapException.toLDAPResult();

    assertEquals(r.getResultCode(), resultCode);
    assertNotNull(r.getDiagnosticMessage());
    assertNotNull(r.getMatchedDN());
    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 2);
    assertTrue(r.hasResponseControl());
    assertTrue(r.hasResponseControl("1.2.3.4"));
    assertFalse(r.hasResponseControl("1.2.3.5"));
    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 1);

    assertNotNull(ldapException.getResultString());

    assertNotNull(ldapException.toString());
  }



  /**
   * Tests the seventh LDAPException constructor, which takes a result code,
   * error message, matched DN, set of referral URLs, and set of response
   * controls.
   *
   * @param  resultCode  The result code to use for the test exception.
   */
  @Test(dataProvider = "testResultCodes")
  public void testConstructor7MultipleControls(ResultCode resultCode)
  {
    String[] referralURLs =
    {
      "ldap://server1.example.com/dc=example,dc=com",
      "ldap://server2.example.com/dc=example,dc=com"
    };

    Control[] responseControls =
    {
      new Control("1.2.3.4", true, new ASN1OctetString()),
      new Control("1.2.3.5", true, new ASN1OctetString())
    };

    LDAPException ldapException =
         new LDAPException(resultCode, "foo", "dc=example,dc=com",
                           referralURLs, responseControls);

    assertEquals(ldapException.getResultCode(), resultCode);
    assertNotNull(ldapException.getMessage());
    assertEquals(ldapException.getMessage(), "foo");
    assertNull(ldapException.getCause());
    assertNotNull(ldapException.getMatchedDN());
    assertEquals(ldapException.getMatchedDN(), "dc=example,dc=com");
    assertNotNull(ldapException.getReferralURLs());
    assertEquals(ldapException.getReferralURLs().length, 2);
    assertTrue(ldapException.hasResponseControl());
    assertTrue(ldapException.hasResponseControl("1.2.3.4"));
    assertTrue(ldapException.hasResponseControl("1.2.3.5"));
    assertFalse(ldapException.hasResponseControl("1.2.3.6"));
    assertNotNull(ldapException.getResponseControls());
    assertNotNull(ldapException.getResponseControl("1.2.3.4"));
    assertNotNull(ldapException.getResponseControl("1.2.3.5"));
    assertNull(ldapException.getResponseControl("1.2.3.6"));
    assertEquals(ldapException.getResponseControls().length, 2);

    LDAPResult r = ldapException.toLDAPResult();

    assertEquals(r.getResultCode(), resultCode);
    assertNotNull(r.getDiagnosticMessage());
    assertNotNull(r.getMatchedDN());
    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 2);
    assertTrue(r.hasResponseControl());
    assertTrue(r.hasResponseControl("1.2.3.4"));
    assertTrue(r.hasResponseControl("1.2.3.5"));
    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 2);

    assertNotNull(ldapException.getResultString());

    assertNotNull(ldapException.toString());
  }



  /**
   * Tests the seventh LDAPException constructor, which takes a result code,
   * error message, matched DN, set of referral URLs, and set of controls, using
   * a null set of referral URLs and a null set of controls.
   *
   * @param  resultCode  The result code to use for the test exception.
   */
  @Test(dataProvider = "testResultCodes")
  public void testConstructor7NullReferralURLs(ResultCode resultCode)
  {
    LDAPException ldapException =
         new LDAPException(resultCode, "foo", "dc=example,dc=com", null,
                           (Control[]) null);

    assertEquals(ldapException.getResultCode(), resultCode);
    assertNotNull(ldapException.getMessage());
    assertEquals(ldapException.getMessage(), "foo");
    assertNull(ldapException.getCause());
    assertNotNull(ldapException.getMatchedDN());
    assertEquals(ldapException.getMatchedDN(), "dc=example,dc=com");
    assertNotNull(ldapException.getReferralURLs());
    assertEquals(ldapException.getReferralURLs().length, 0);
    assertFalse(ldapException.hasResponseControl());
    assertFalse(ldapException.hasResponseControl("1.2.3.4"));
    assertFalse(ldapException.hasResponseControl("1.2.3.5"));
    assertNotNull(ldapException.getResponseControls());
    assertEquals(ldapException.getResponseControls().length, 0);

    LDAPResult r = ldapException.toLDAPResult();

    assertEquals(r.getResultCode(), resultCode);
    assertNotNull(r.getDiagnosticMessage());
    assertNotNull(r.getMatchedDN());
    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);
    assertFalse(r.hasResponseControl());
    assertFalse(r.hasResponseControl("1.2.3.4"));
    assertFalse(r.hasResponseControl("1.2.3.5"));
    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(ldapException.getResultString());

    assertNotNull(ldapException.toString());
  }



  /**
   * Tests the eighth LDAPException constructor, which takes a result code,
   * error message, matched DN, set of referral URLs, set of response controls,
   * and cause.
   *
   * @param  resultCode  The result code to use for the test exception.
   */
  @Test(dataProvider = "testResultCodes")
  public void testConstructor8(ResultCode resultCode)
  {
    String[] referralURLs =
    {
      "ldap://server1.example.com/dc=example,dc=com",
      "ldap://server2.example.com/dc=example,dc=com"
    };

    Control[] responseControls =
    {
      new Control("1.2.3.4", true, new ASN1OctetString())
    };

    LDAPException ldapException =
         new LDAPException(resultCode, "foo", "dc=example,dc=com",
                           referralURLs, responseControls, new Exception());

    assertEquals(ldapException.getResultCode(), resultCode);
    assertNotNull(ldapException.getMessage());
    assertEquals(ldapException.getMessage(), "foo");
    assertNotNull(ldapException.getCause());
    assertNotNull(ldapException.getMatchedDN());
    assertEquals(ldapException.getMatchedDN(), "dc=example,dc=com");
    assertNotNull(ldapException.getReferralURLs());
    assertEquals(ldapException.getReferralURLs().length, 2);
    assertTrue(ldapException.hasResponseControl());
    assertTrue(ldapException.hasResponseControl("1.2.3.4"));
    assertFalse(ldapException.hasResponseControl("1.2.3.5"));
    assertNotNull(ldapException.getResponseControls());
    assertEquals(ldapException.getResponseControls().length, 1);
    assertNotNull(ldapException.getResponseControl("1.2.3.4"));
    assertNull(ldapException.getResponseControl("1.2.3.5"));

    LDAPResult r = ldapException.toLDAPResult();

    assertEquals(r.getResultCode(), resultCode);
    assertNotNull(r.getDiagnosticMessage());
    assertNotNull(r.getMatchedDN());
    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 2);
    assertTrue(r.hasResponseControl());
    assertTrue(r.hasResponseControl("1.2.3.4"));
    assertFalse(r.hasResponseControl("1.2.3.5"));
    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 1);

    assertNotNull(ldapException.getResultString());

    assertNotNull(ldapException.toString());
  }



  /**
   * Tests the eighth LDAPException constructor, which takes a result code,
   * error message, matched DN, set of referral URLs, set of response controls,
   * and cause.
   *
   * @param  resultCode  The result code to use for the test exception.
   */
  @Test(dataProvider = "testResultCodes")
  public void testConstructor8MultipleControls(ResultCode resultCode)
  {
    String[] referralURLs =
    {
      "ldap://server1.example.com/dc=example,dc=com",
      "ldap://server2.example.com/dc=example,dc=com"
    };

    Control[] responseControls =
    {
      new Control("1.2.3.4", true, new ASN1OctetString()),
      new Control("1.2.3.5", true, new ASN1OctetString())
    };

    LDAPException ldapException =
         new LDAPException(resultCode, "foo", "dc=example,dc=com",
                           referralURLs, responseControls, new Exception());

    assertEquals(ldapException.getResultCode(), resultCode);
    assertNotNull(ldapException.getMessage());
    assertEquals(ldapException.getMessage(), "foo");
    assertNotNull(ldapException.getCause());
    assertNotNull(ldapException.getMatchedDN());
    assertEquals(ldapException.getMatchedDN(), "dc=example,dc=com");
    assertNotNull(ldapException.getReferralURLs());
    assertEquals(ldapException.getReferralURLs().length, 2);
    assertTrue(ldapException.hasResponseControl());
    assertTrue(ldapException.hasResponseControl("1.2.3.4"));
    assertTrue(ldapException.hasResponseControl("1.2.3.5"));
    assertFalse(ldapException.hasResponseControl("1.2.3.6"));
    assertNotNull(ldapException.getResponseControls());
    assertEquals(ldapException.getResponseControls().length, 2);
    assertNotNull(ldapException.getResponseControl("1.2.3.4"));
    assertNotNull(ldapException.getResponseControl("1.2.3.5"));
    assertNull(ldapException.getResponseControl("1.2.3.6"));

    LDAPResult r = ldapException.toLDAPResult();

    assertEquals(r.getResultCode(), resultCode);
    assertNotNull(r.getDiagnosticMessage());
    assertNotNull(r.getMatchedDN());
    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 2);
    assertTrue(r.hasResponseControl());
    assertTrue(r.hasResponseControl("1.2.3.4"));
    assertTrue(r.hasResponseControl("1.2.3.5"));
    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 2);

    assertNotNull(ldapException.getResultString());

    assertNotNull(ldapException.toString());
  }



  /**
   * Tests the eighth LDAPException constructor, which takes a result code,
   * error message, matched DN, set of referral URLs, set of response controls,
   * and cause, using a null set of referral URLs.
   *
   * @param  resultCode  The result code to use for the test exception.
   */
  @Test(dataProvider = "testResultCodes")
  public void testConstructor8NullReferralURLs(ResultCode resultCode)
  {
    LDAPException ldapException =
         new LDAPException(resultCode, "foo", "dc=example,dc=com", null,
                           null, new Exception());

    assertEquals(ldapException.getResultCode(), resultCode);
    assertNotNull(ldapException.getMessage());
    assertEquals(ldapException.getMessage(), "foo");
    assertNotNull(ldapException.getCause());
    assertNotNull(ldapException.getMatchedDN());
    assertEquals(ldapException.getMatchedDN(), "dc=example,dc=com");
    assertNotNull(ldapException.getReferralURLs());
    assertEquals(ldapException.getReferralURLs().length, 0);
    assertFalse(ldapException.hasResponseControl());
    assertFalse(ldapException.hasResponseControl("1.2.3.4"));
    assertFalse(ldapException.hasResponseControl("1.2.3.5"));
    assertNotNull(ldapException.getResponseControls());
    assertEquals(ldapException.getResponseControls().length, 0);

    LDAPResult r = ldapException.toLDAPResult();

    assertEquals(r.getResultCode(), resultCode);
    assertNotNull(r.getDiagnosticMessage());
    assertNotNull(r.getMatchedDN());
    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);
    assertFalse(r.hasResponseControl());
    assertFalse(r.hasResponseControl("1.2.3.4"));
    assertFalse(r.hasResponseControl("1.2.3.5"));
    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(ldapException.getResultString());

    assertNotNull(ldapException.toString());
  }



  /**
   * Tests the ninth LDAPException constructor, which takes an LDAPResult
   * object.
   *
   * @param  resultCode  The result code to use for the test exception.
   */
  @Test(dataProvider = "testResultCodes")
  public void testConstructor9(ResultCode resultCode)
  {
    LDAPResult ldapResult = new LDAPResult(1, resultCode, "foo",
         "dc=example,dc=com", (String[]) null, (Control[]) null);
    LDAPException ldapException = new LDAPException(ldapResult);

    assertEquals(ldapException.getResultCode(), resultCode);
    assertNotNull(ldapException.getMessage());
    assertEquals(ldapException.getMessage(), "foo");
    assertNull(ldapException.getCause());
    assertNotNull(ldapException.getMatchedDN());
    assertEquals(ldapException.getMatchedDN(), "dc=example,dc=com");
    assertNotNull(ldapException.getReferralURLs());
    assertEquals(ldapException.getReferralURLs().length, 0);
    assertFalse(ldapException.hasResponseControl());
    assertFalse(ldapException.hasResponseControl("1.2.3.4"));
    assertFalse(ldapException.hasResponseControl("1.2.3.5"));
    assertNotNull(ldapException.getResponseControls());
    assertEquals(ldapException.getResponseControls().length, 0);

    LDAPResult r = ldapException.toLDAPResult();

    assertEquals(r.getResultCode(), resultCode);
    assertNotNull(r.getDiagnosticMessage());
    assertNotNull(r.getMatchedDN());
    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);
    assertFalse(r.hasResponseControl());
    assertFalse(r.hasResponseControl("1.2.3.4"));
    assertFalse(r.hasResponseControl("1.2.3.5"));
    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(ldapException.getResultString());

    assertNotNull(ldapException.toString());
  }



  /**
   * Tests the ninth LDAPException constructor, which takes an LDAPResult
   * object, using an alternate result object that tests different code paths.
   *
   * @param  resultCode  The result code to use for the test exception.
   */
  @Test(dataProvider = "testResultCodes")
  public void testConstructor9Alt(ResultCode resultCode)
  {
    String[] referralURLs =
    {
      "ldap://server1.example.com/dc=example,dc=com",
      "ldap://server2.example.com/dc=example,dc=com"
    };

    Control[] responseControls =
    {
      new Control("1.2.3.4", true, new ASN1OctetString())
    };

    LDAPResult ldapResult =
         new LDAPResult(1, resultCode, null, null, referralURLs,
                        responseControls);
    LDAPException ldapException = new LDAPException(ldapResult);

    assertEquals(ldapException.getResultCode(), resultCode);
    assertNotNull(ldapException.getMessage());
    assertNull(ldapException.getCause());
    assertNull(ldapException.getMatchedDN());
    assertNotNull(ldapException.getReferralURLs());
    assertEquals(ldapException.getReferralURLs().length, 2);
    assertNotNull(ldapException.getResponseControls());
    assertTrue(ldapException.hasResponseControl());
    assertTrue(ldapException.hasResponseControl("1.2.3.4"));
    assertFalse(ldapException.hasResponseControl("1.2.3.5"));
    assertEquals(ldapException.getResponseControls().length, 1);
    assertNotNull(ldapException.getResponseControl("1.2.3.4"));
    assertNull(ldapException.getResponseControl("1.2.3.5"));

    LDAPResult r = ldapException.toLDAPResult();

    assertEquals(r.getResultCode(), resultCode);
    assertNotNull(r.getDiagnosticMessage());
    assertNull(r.getMatchedDN());
    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 2);
    assertTrue(r.hasResponseControl());
    assertTrue(r.hasResponseControl("1.2.3.4"));
    assertFalse(r.hasResponseControl("1.2.3.5"));
    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 1);

    assertNotNull(ldapException.getResultString());

    assertNotNull(ldapException.toString());
  }



  /**
   * Tests the ninth LDAPException constructor, which takes an LDAPResult
   * object, using an alternate result object that tests different code paths.
   *
   * @param  resultCode  The result code to use for the test exception.
   */
  @Test(dataProvider = "testResultCodes")
  public void testConstructor9AltMultipleControls(ResultCode resultCode)
  {
    String[] referralURLs =
    {
      "ldap://server1.example.com/dc=example,dc=com",
      "ldap://server2.example.com/dc=example,dc=com"
    };

    Control[] responseControls =
    {
      new Control("1.2.3.4", true, new ASN1OctetString()),
      new Control("1.2.3.5", true, new ASN1OctetString())
    };

    LDAPResult ldapResult =
         new LDAPResult(1, resultCode, null, null, referralURLs,
                        responseControls);
    LDAPException ldapException = new LDAPException(ldapResult);

    assertEquals(ldapException.getResultCode(), resultCode);
    assertNotNull(ldapException.getMessage());
    assertNull(ldapException.getCause());
    assertNull(ldapException.getMatchedDN());
    assertNotNull(ldapException.getReferralURLs());
    assertEquals(ldapException.getReferralURLs().length, 2);
    assertNotNull(ldapException.getResponseControls());
    assertTrue(ldapException.hasResponseControl());
    assertTrue(ldapException.hasResponseControl("1.2.3.4"));
    assertTrue(ldapException.hasResponseControl("1.2.3.5"));
    assertFalse(ldapException.hasResponseControl("1.2.3.6"));
    assertEquals(ldapException.getResponseControls().length, 2);
    assertNotNull(ldapException.getResponseControl("1.2.3.4"));
    assertNotNull(ldapException.getResponseControl("1.2.3.5"));
    assertNull(ldapException.getResponseControl("1.2.3.6"));

    LDAPResult r = ldapException.toLDAPResult();

    assertEquals(r.getResultCode(), resultCode);
    assertNotNull(r.getDiagnosticMessage());
    assertNull(r.getMatchedDN());
    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 2);
    assertTrue(r.hasResponseControl());
    assertTrue(r.hasResponseControl("1.2.3.4"));
    assertTrue(r.hasResponseControl("1.2.3.5"));
    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 2);

    assertNotNull(ldapException.getResultString());

    assertNotNull(ldapException.toString());
  }



  /**
   * Tests the tenth LDAPException constructor, which takes an LDAPResult
   * object and a cause.
   *
   * @param  resultCode  The result code to use for the test exception.
   */
  @Test(dataProvider = "testResultCodes")
  public void testConstructor10(ResultCode resultCode)
  {
    LDAPResult ldapResult = new LDAPResult(1, resultCode, "foo",
         "dc=example,dc=com", (String[]) null, (Control[]) null);
    LDAPException ldapException =
         new LDAPException(ldapResult, new Exception());

    assertEquals(ldapException.getResultCode(), resultCode);
    assertNotNull(ldapException.getMessage());
    assertEquals(ldapException.getMessage(), "foo");
    assertNotNull(ldapException.getCause());
    assertNotNull(ldapException.getMatchedDN());
    assertEquals(ldapException.getMatchedDN(), "dc=example,dc=com");
    assertNotNull(ldapException.getReferralURLs());
    assertEquals(ldapException.getReferralURLs().length, 0);
    assertFalse(ldapException.hasResponseControl());
    assertFalse(ldapException.hasResponseControl("1.2.3.4"));
    assertFalse(ldapException.hasResponseControl("1.2.3.5"));
    assertNotNull(ldapException.getResponseControls());
    assertEquals(ldapException.getResponseControls().length, 0);

    LDAPResult r = ldapException.toLDAPResult();

    assertEquals(r.getResultCode(), resultCode);
    assertNotNull(r.getDiagnosticMessage());
    assertNotNull(r.getMatchedDN());
    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);
    assertFalse(r.hasResponseControl());
    assertFalse(r.hasResponseControl("1.2.3.4"));
    assertFalse(r.hasResponseControl("1.2.3.5"));
    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(ldapException.getResultString());

    assertNotNull(ldapException.toString());
  }



  /**
   * Tests the tenth LDAPException constructor, which takes an LDAPResult
   * object and a cause, using an alternate result object that tests different
   * code paths.
   *
   * @param  resultCode  The result code to use for the test exception.
   */
  @Test(dataProvider = "testResultCodes")
  public void testConstructor10Alt(ResultCode resultCode)
  {
    String[] referralURLs =
    {
      "ldap://server1.example.com/dc=example,dc=com",
      "ldap://server2.example.com/dc=example,dc=com"
    };

    Control[] responseControls =
    {
      new Control("1.2.3.4", true, new ASN1OctetString())
    };

    LDAPResult ldapResult =
         new LDAPResult(1, resultCode, null, null, referralURLs,
                        responseControls);
    LDAPException ldapException =
         new LDAPException(ldapResult, new Exception());

    assertEquals(ldapException.getResultCode(), resultCode);
    assertNotNull(ldapException.getMessage());
    assertNotNull(ldapException.getCause());
    assertNull(ldapException.getMatchedDN());
    assertNotNull(ldapException.getReferralURLs());
    assertEquals(ldapException.getReferralURLs().length, 2);
    assertTrue(ldapException.hasResponseControl());
    assertTrue(ldapException.hasResponseControl("1.2.3.4"));
    assertFalse(ldapException.hasResponseControl("1.2.3.5"));
    assertNotNull(ldapException.getResponseControls());
    assertEquals(ldapException.getResponseControls().length, 1);
    assertNotNull(ldapException.getResponseControl("1.2.3.4"));
    assertNull(ldapException.getResponseControl("1.2.3.5"));

    LDAPResult r = ldapException.toLDAPResult();

    assertEquals(r.getResultCode(), resultCode);
    assertNotNull(r.getDiagnosticMessage());
    assertNull(r.getMatchedDN());
    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 2);
    assertTrue(r.hasResponseControl());
    assertTrue(r.hasResponseControl("1.2.3.4"));
    assertFalse(r.hasResponseControl("1.2.3.5"));
    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 1);

    assertNotNull(ldapException.getResultString());

    assertNotNull(ldapException.toString());
  }



  /**
   * Tests the tenth LDAPException constructor, which takes an LDAPResult
   * object and a cause, using an alternate result object that tests different
   * code paths.
   *
   * @param  resultCode  The result code to use for the test exception.
   */
  @Test(dataProvider = "testResultCodes")
  public void testConstructor10AltMultipleControls(ResultCode resultCode)
  {
    String[] referralURLs =
    {
      "ldap://server1.example.com/dc=example,dc=com",
      "ldap://server2.example.com/dc=example,dc=com"
    };

    Control[] responseControls =
    {
      new Control("1.2.3.4", true, new ASN1OctetString()),
      new Control("1.2.3.5", true, new ASN1OctetString())
    };

    LDAPResult ldapResult =
         new LDAPResult(1, resultCode, null, null, referralURLs,
                        responseControls);
    LDAPException ldapException =
         new LDAPException(ldapResult, new Exception());

    assertEquals(ldapException.getResultCode(), resultCode);
    assertNotNull(ldapException.getMessage());
    assertNotNull(ldapException.getCause());
    assertNull(ldapException.getMatchedDN());
    assertNotNull(ldapException.getReferralURLs());
    assertEquals(ldapException.getReferralURLs().length, 2);
    assertTrue(ldapException.hasResponseControl());
    assertTrue(ldapException.hasResponseControl("1.2.3.4"));
    assertTrue(ldapException.hasResponseControl("1.2.3.5"));
    assertFalse(ldapException.hasResponseControl("1.2.3.6"));
    assertNotNull(ldapException.getResponseControls());
    assertEquals(ldapException.getResponseControls().length, 2);
    assertNotNull(ldapException.getResponseControl("1.2.3.4"));
    assertNotNull(ldapException.getResponseControl("1.2.3.5"));
    assertNull(ldapException.getResponseControl("1.2.3.6"));

    LDAPResult r = ldapException.toLDAPResult();

    assertEquals(r.getResultCode(), resultCode);
    assertNotNull(r.getDiagnosticMessage());
    assertNull(r.getMatchedDN());
    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 2);
    assertTrue(r.hasResponseControl());
    assertTrue(r.hasResponseControl("1.2.3.4"));
    assertTrue(r.hasResponseControl("1.2.3.5"));
    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 2);

    assertNotNull(ldapException.getResultString());

    assertNotNull(ldapException.toString());
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
    final LDAPException le = new LDAPException(ResultCode.CONNECT_ERROR,
         "The connection attempt failed",
         new ConnectException("The connection attempt failed"));

    final String defaultMessage = le.getExceptionMessage(false, false);
    assertFalse(defaultMessage.contains("trace="));
    assertFalse(defaultMessage.contains("cause="));

    final String messageWithCause = le.getExceptionMessage(true, false);
    assertFalse(messageWithCause.contains("trace="));
    assertTrue(messageWithCause.contains("cause="));

    final String messageWithTrace = le.getExceptionMessage(false, true);
    assertTrue(messageWithTrace.contains("trace="));
    assertTrue(messageWithTrace.contains("cause="));
  }
}
