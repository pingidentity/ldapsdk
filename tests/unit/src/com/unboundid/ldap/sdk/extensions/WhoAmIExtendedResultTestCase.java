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
package com.unboundid.ldap.sdk.extensions;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the WhoAmIExtendedResult class.
 */
public class WhoAmIExtendedResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the constructor with a successful result and non-null result value.
   */
  @Test()
  public void testConstructor1SuccessNonNullValue()
  {
    ASN1OctetString resultValue =
         new ASN1OctetString("dn:uid=test.user,ou=People,dc=example,dc=com");

    ExtendedResult extendedResult =
         new ExtendedResult(1, ResultCode.SUCCESS, null, null, null, null,
                            resultValue, null);

    WhoAmIExtendedResult whoAmIResult =
         new WhoAmIExtendedResult(extendedResult);

    assertEquals(whoAmIResult.getMessageID(), 1);

    assertEquals(whoAmIResult.getResultCode(), ResultCode.SUCCESS);

    assertNull(whoAmIResult.getDiagnosticMessage());

    assertNull(whoAmIResult.getMatchedDN());

    assertNotNull(whoAmIResult.getReferralURLs());
    assertEquals(whoAmIResult.getReferralURLs().length, 0);

    assertNotNull(whoAmIResult.getResponseControls());
    assertEquals(whoAmIResult.getResponseControls().length, 0);

    assertNull(whoAmIResult.getOID());

    assertNotNull(whoAmIResult.getValue());

    assertNotNull(whoAmIResult.getAuthorizationID());
    assertEquals(whoAmIResult.getAuthorizationID(),
                 "dn:uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(whoAmIResult.getExtendedResultName());
    assertNotNull(whoAmIResult.toString());
  }



  /**
   * Tests the constructor with a successful result and an empty result value.
   */
  @Test()
  public void testConstructor1SuccessEmptyValue()
  {
    ASN1OctetString resultValue = new ASN1OctetString();

    ExtendedResult extendedResult =
         new ExtendedResult(1, ResultCode.SUCCESS, null, null, null, null,
                            resultValue, null);

    WhoAmIExtendedResult whoAmIResult =
         new WhoAmIExtendedResult(extendedResult);

    assertEquals(whoAmIResult.getMessageID(), 1);

    assertEquals(whoAmIResult.getResultCode(), ResultCode.SUCCESS);

    assertNull(whoAmIResult.getDiagnosticMessage());

    assertNull(whoAmIResult.getMatchedDN());

    assertNotNull(whoAmIResult.getReferralURLs());
    assertEquals(whoAmIResult.getReferralURLs().length, 0);

    assertNotNull(whoAmIResult.getResponseControls());
    assertEquals(whoAmIResult.getResponseControls().length, 0);

    assertNull(whoAmIResult.getOID());

    assertNotNull(whoAmIResult.getValue());

    assertNotNull(whoAmIResult.getAuthorizationID());
    assertEquals(whoAmIResult.getAuthorizationID(), "");

    assertNotNull(whoAmIResult.getExtendedResultName());
    assertNotNull(whoAmIResult.toString());
  }



  /**
   * Tests the constructor with a successful result and a {@code null} value.
   */
  @Test()
  public void testConstructor1SuccessNullValue()
  {
    ExtendedResult extendedResult =
         new ExtendedResult(1, ResultCode.SUCCESS, null, null, null, null, null,
                            null);

    WhoAmIExtendedResult whoAmIResult =
         new WhoAmIExtendedResult(extendedResult);

    assertEquals(whoAmIResult.getMessageID(), 1);

    assertEquals(whoAmIResult.getResultCode(), ResultCode.SUCCESS);

    assertNull(whoAmIResult.getDiagnosticMessage());

    assertNull(whoAmIResult.getMatchedDN());

    assertNotNull(whoAmIResult.getReferralURLs());
    assertEquals(whoAmIResult.getReferralURLs().length, 0);

    assertNotNull(whoAmIResult.getResponseControls());
    assertEquals(whoAmIResult.getResponseControls().length, 0);

    assertNull(whoAmIResult.getOID());

    assertNull(whoAmIResult.getValue());

    assertNull(whoAmIResult.getAuthorizationID());

    assertNotNull(whoAmIResult.getExtendedResultName());
    assertNotNull(whoAmIResult.toString());
  }



  /**
   * Tests the constructor with a failed result and a {@code null} value.
   */
  @Test()
  public void testConstructor1FailedNullValue()
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

    ExtendedResult extendedResult =
         new ExtendedResult(1, ResultCode.UNAVAILABLE,
                            "This server is currently unavailable",
                            "dc=example,dc=com", referralURLs, null, null,
                            controls);

    WhoAmIExtendedResult whoAmIResult =
         new WhoAmIExtendedResult(extendedResult);

    assertEquals(whoAmIResult.getMessageID(), 1);

    assertEquals(whoAmIResult.getResultCode(), ResultCode.UNAVAILABLE);

    assertNotNull(whoAmIResult.getDiagnosticMessage());
    assertEquals(whoAmIResult.getDiagnosticMessage(),
                 "This server is currently unavailable");

    assertNotNull(whoAmIResult.getMatchedDN());
    assertEquals(whoAmIResult.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(whoAmIResult.getReferralURLs());
    assertEquals(whoAmIResult.getReferralURLs().length, 2);

    assertNotNull(whoAmIResult.getResponseControls());
    assertEquals(whoAmIResult.getResponseControls().length, 2);

    assertNull(whoAmIResult.getOID());

    assertNull(whoAmIResult.getValue());

    assertNull(whoAmIResult.getAuthorizationID());

    assertNotNull(whoAmIResult.getExtendedResultName());
    assertNotNull(whoAmIResult.toString());
  }



  /**
   * Tests the second constructor with a success result and an authorization ID.
   */
  @Test()
  public void testConstructor2SuccessWithAuthzID()
  {
    WhoAmIExtendedResult r = new WhoAmIExtendedResult(1, ResultCode.SUCCESS,
         null, null, null, "dn:uid=test.user,ou=People,dc=example,dc=com",
         null);
    r = new WhoAmIExtendedResult(r);

    assertEquals(r.getMessageID(), 1);

    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNull(r.getOID());

    assertNotNull(r.getValue());

    assertNotNull(r.getAuthorizationID());
    assertEquals(r.getAuthorizationID(),
                 "dn:uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(r.getExtendedResultName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the second constructor with a success result but without an
   * authorization ID.
   */
  @Test()
  public void testConstructor2SuccessWithoutAuthzID()
  {
    WhoAmIExtendedResult r = new WhoAmIExtendedResult(1, ResultCode.SUCCESS,
                                      null, null, null, null, null);
    r = new WhoAmIExtendedResult(r);

    assertEquals(r.getMessageID(), 1);

    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNull(r.getOID());

    assertNull(r.getValue());

    assertNull(r.getAuthorizationID());

    assertNotNull(r.getExtendedResultName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the second constructor with a failure result but without an
   * authorization ID.
   */
  @Test()
  public void testConstructor2Failed()
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

    WhoAmIExtendedResult r = new WhoAmIExtendedResult(1, ResultCode.UNAVAILABLE,
         "This server is currently unavailable", "dc=example,dc=com",
         referralURLs, null, controls);
    r = new WhoAmIExtendedResult(r);

    assertEquals(r.getMessageID(), 1);

    assertEquals(r.getResultCode(), ResultCode.UNAVAILABLE);

    assertNotNull(r.getDiagnosticMessage());

    assertNotNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 2);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 2);

    assertNull(r.getOID());

    assertNull(r.getValue());

    assertNull(r.getAuthorizationID());

    assertNotNull(r.getExtendedResultName());
    assertNotNull(r.toString());
  }
}
