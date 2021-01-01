/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the PasswordModifyExtendedResult
 * class.
 */
public class PasswordModifyExtendedResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the constructors for this class for a success result with a generated
   * password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorsSuccessWithGeneratedPassword()
         throws Exception
  {
    PasswordModifyExtendedResult r =
         new PasswordModifyExtendedResult(1, ResultCode.SUCCESS, null, null,
                  null, new ASN1OctetString("newpassword"), null);
    r = new PasswordModifyExtendedResult(r);

    assertEquals(r.getMessageID(), 1);

    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(r.getGeneratedPassword());
    assertEquals(r.getGeneratedPassword(), "newpassword");

    assertNotNull(r.getGeneratedPasswordBytes());
    assertEquals(r.getGeneratedPasswordBytes(),
                 "newpassword".getBytes("UTF-8"));

    assertNotNull(r.getExtendedResultName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the constructors for this class for a success result without a
   * generated password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorsSuccessWithoutGeneratedPassword()
         throws Exception
  {
    PasswordModifyExtendedResult r =
         new PasswordModifyExtendedResult(1, ResultCode.SUCCESS, null, null,
                                          null, null, null);
    r = new PasswordModifyExtendedResult(r);

    assertEquals(r.getMessageID(), 1);

    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNull(r.getGeneratedPassword());

    assertNull(r.getGeneratedPasswordBytes());

    assertNotNull(r.getExtendedResultName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the constructors for this class for a non-success result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorsNonSuccess()
         throws Exception
  {
    String diagnosticMessage = "Not gonna do it.";

    String matchedDN = "dc=example,dc=com";

    String[] referralURLs =
    {
      "ldap://server1.example.com:389/dc=example,dc=com??sub?(foo=bar)",
      "ldap://server2.example.com:389/dc=example,dc=com??sub?(foo=bar)"
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString(new byte[1])),
    };

    PasswordModifyExtendedResult r = new PasswordModifyExtendedResult(1,
         ResultCode.UNWILLING_TO_PERFORM, diagnosticMessage, matchedDN,
         referralURLs, null, controls);
    r = new PasswordModifyExtendedResult(r);

    assertEquals(r.getMessageID(), 1);

    assertEquals(r.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);

    assertNotNull(r.getDiagnosticMessage());

    assertNotNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 2);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 2);

    assertNull(r.getGeneratedPassword());

    assertNull(r.getGeneratedPasswordBytes());

    assertNotNull(r.getExtendedResultName());
    assertNotNull(r.toString());
  }
}
