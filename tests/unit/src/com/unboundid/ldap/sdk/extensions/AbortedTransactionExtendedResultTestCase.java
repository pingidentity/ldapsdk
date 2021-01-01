/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides test coverage for the
 * {@code AbortedTransactionExtendedResult} class.
 */
public final class AbortedTransactionExtendedResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the extended result with only a minimal set of
   * information provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorMinimal()
         throws Exception
  {
    AbortedTransactionExtendedResult r = new AbortedTransactionExtendedResult(
         new ASN1OctetString("txnid"), ResultCode.OTHER, null, null, null,
         null);
    r = new AbortedTransactionExtendedResult(r);

    assertNotNull(r);

    assertNotNull(r.getValue());

    assertNotNull(r.getTransactionID());
    assertEquals(r.getTransactionID(), new ASN1OctetString("txnid"));

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.1.21.4");

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.OTHER);

    assertEquals(r.getMessageID(), 0);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for the extended result with a complete set of
   * information provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorComplete()
         throws Exception
  {
    String[] refs =
    {
      "ldap:///server1.example.com:389?dc=example,dc=com",
      "ldap:///server2.example.com:389?dc=example,dc=com"
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5")
    };

    AbortedTransactionExtendedResult r = new AbortedTransactionExtendedResult(
         new ASN1OctetString("txnid"), ResultCode.OTHER, "diagnostic message",
         "dc=example,dc=com", refs, controls);
    r = new AbortedTransactionExtendedResult(r);

    assertNotNull(r);

    assertNotNull(r.getValue());

    assertNotNull(r.getTransactionID());
    assertEquals(r.getTransactionID(), new ASN1OctetString("txnid"));

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.1.21.4");

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.OTHER);

    assertEquals(r.getMessageID(), 0);

    assertNotNull(r.getDiagnosticMessage());
    assertEquals(r.getDiagnosticMessage(), "diagnostic message");

    assertNotNull(r.getMatchedDN());
    assertEquals(new DN(r.getMatchedDN()), new DN("dc=example,dc=com"));

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 2);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 2);

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for an attempt to decode an extended result with no
   * value as an aborted transaction result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructorNoValue()
         throws Exception
  {
    new AbortedTransactionExtendedResult(new ExtendedResult(0,
         ResultCode.SUCCESS, null, null, null, null, null, null));
  }
}
