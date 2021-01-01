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



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the interactive transaction
 * aborted extended result.
 */
@SuppressWarnings("deprecation")
public class InteractiveTransactionAbortedExtendedResultTestCase
     extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor, which creates a notice of disconnection result
   * from a generic extended result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    ExtendedResult r = new ExtendedResult(1, ResultCode.ADMIN_LIMIT_EXCEEDED,
         "Transaction was idle for too long", null, null,
         "1.3.6.1.4.1.30221.2.6.5", null, null);

    InteractiveTransactionAbortedExtendedResult itaer =
         new InteractiveTransactionAbortedExtendedResult(r);

    assertNotNull(itaer);

    assertEquals(itaer.getMessageID(), 1);

    assertEquals(itaer.getResultCode(), ResultCode.ADMIN_LIMIT_EXCEEDED);

    assertNotNull(itaer.getDiagnosticMessage());
    assertEquals(itaer.getDiagnosticMessage(),
                 "Transaction was idle for too long");

    assertNull(itaer.getMatchedDN());

    assertNotNull(itaer.getReferralURLs());
    assertEquals(itaer.getReferralURLs().length, 0);

    assertNull(itaer.getValue());

    assertNotNull(itaer.getOID());
    assertEquals(itaer.getOID(), "1.3.6.1.4.1.30221.2.6.5");

    assertNotNull(itaer.getResponseControls());
    assertEquals(itaer.getResponseControls().length, 0);

    assertNotNull(r.getExtendedResultName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the first constructor, which creates a notice of disconnection result
   * from the individual components.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    String[] referralURLs =
    {
      "ldap://server1.example.com/dc=example,dc=om",
      "ldap://server2.example.com/dc=example,dc=om"
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5")
    };

    InteractiveTransactionAbortedExtendedResult r =
         new InteractiveTransactionAbortedExtendedResult(1,
                  ResultCode.ADMIN_LIMIT_EXCEEDED,
                  "Transaction was idle for too long",
                  "dc=example,dc=com", referralURLs, controls);

    assertNotNull(r);

    assertEquals(r.getMessageID(), 1);

    assertEquals(r.getResultCode(), ResultCode.ADMIN_LIMIT_EXCEEDED);

    assertNotNull(r.getDiagnosticMessage());
    assertEquals(r.getDiagnosticMessage(),
                 "Transaction was idle for too long");

    assertNotNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 2);

    assertNull(r.getValue());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.5");

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 2);

    assertNotNull(r.getExtendedResultName());
    assertNotNull(r.toString());
  }
}
