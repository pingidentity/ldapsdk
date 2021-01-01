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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.util.HashMap;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the
 * EndBatchedTransactionExtendedResult class.
 */
public class EndBatchedTransactionExtendedResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the constructors with a success response and no operation response
   * controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorsSuccessNoOpControls()
         throws Exception
  {
    EndBatchedTransactionExtendedResult r =
         new EndBatchedTransactionExtendedResult(3, ResultCode.SUCCESS, null,
                                                 null, null, null, null, null);
    r = new EndBatchedTransactionExtendedResult(r);

    assertNotNull(r);

    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertEquals(r.getFailedOpMessageID(), -1);

    assertNotNull(r.getOperationResponseControls());
    assertTrue(r.getOperationResponseControls().isEmpty());

    assertNotNull(r.getExtendedResultName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the constructors with a success response and operation response
   * controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorsSuccessWithOpControls()
         throws Exception
  {
    Control[] opControls1 =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString(new byte[1]))
    };

    Control[] opControls2 =
    {
      new Control("1.2.3.6"),
      new Control("1.2.3.7", true, new ASN1OctetString(new byte[1]))
    };

    HashMap<Integer,Control[]> opControls = new HashMap<Integer,Control[]>();
    opControls.put(1, opControls1);
    opControls.put(2, opControls2);


    EndBatchedTransactionExtendedResult r =
         new EndBatchedTransactionExtendedResult(3, ResultCode.SUCCESS, null,
                                                 null, null, null, opControls,
                                                 null);
    r = new EndBatchedTransactionExtendedResult(r);

    assertNotNull(r);

    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertEquals(r.getFailedOpMessageID(), -1);

    assertNotNull(r.getOperationResponseControls());
    assertFalse(r.getOperationResponseControls().isEmpty());
    assertNotNull(r.getOperationResponseControls(1));
    assertNotNull(r.getOperationResponseControls(2));
    assertNull(r.getOperationResponseControls(3));

    assertNotNull(r.getExtendedResultName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the constructors with a failure response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorsFailure()
         throws Exception
  {
    String[] referralURLs =
    {
      "ldap://server1.example.com/dc=example,dc=com",
      "ldap://server2.example.com/dc=example,dc=com",
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString(new byte[1]))
    };

    EndBatchedTransactionExtendedResult r =
         new EndBatchedTransactionExtendedResult(3,
                  ResultCode.UNWILLING_TO_PERFORM, "Not gonna do it",
                  "dc=example,dc=com", referralURLs, 1, null, controls);
    r = new EndBatchedTransactionExtendedResult(r);

    assertNotNull(r);

    assertEquals(r.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);

    assertNotNull(r.getDiagnosticMessage());

    assertNotNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 2);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 2);

    assertEquals(r.getFailedOpMessageID(), 1);

    assertNotNull(r.getOperationResponseControls());
    assertTrue(r.getOperationResponseControls().isEmpty());

    assertNotNull(r.getExtendedResultName());
    assertNotNull(r.toString());
  }
}
