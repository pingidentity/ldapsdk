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



import java.util.ArrayList;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * Provides a set of test cases for the start interactive transaction extended
 * result.
 */
@SuppressWarnings("deprecation")
public class StartInteractiveTransactionExtendedResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with a failure response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Failure()
         throws Exception
  {
    ExtendedResult r = new ExtendedResult(1,
         ResultCode.INSUFFICIENT_ACCESS_RIGHTS, "Insufficient permission",
         null, null, null, null, null);

    StartInteractiveTransactionExtendedResult siter =
         new StartInteractiveTransactionExtendedResult(r);

    assertNotNull(siter);

    assertEquals(siter.getMessageID(), 1);

    assertEquals(siter.getResultCode(), ResultCode.INSUFFICIENT_ACCESS_RIGHTS);

    assertNotNull(siter.getDiagnosticMessage());
    assertEquals(siter.getDiagnosticMessage(), "Insufficient permission");

    assertNull(siter.getMatchedDN());

    assertNotNull(siter.getReferralURLs());
    assertEquals(siter.getReferralURLs().length, 0);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNull(siter.getTransactionID());

    assertNull(siter.getBaseDNs());

    assertNotNull(siter.toString());
  }



  /**
   * Tests the first constructor with a transaction ID but no base DNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1NoBaseDNs()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1OctetString((byte) 0x80, "txnid")
    };

    ASN1OctetString value =
         new ASN1OctetString(new ASN1Sequence(elements).encode());

    ExtendedResult r = new ExtendedResult(1, ResultCode.SUCCESS, null, null,
                                          null, null, value, null);

    StartInteractiveTransactionExtendedResult siter =
         new StartInteractiveTransactionExtendedResult(r);

    assertNotNull(siter);

    assertEquals(siter.getMessageID(), 1);

    assertEquals(siter.getResultCode(), ResultCode.SUCCESS);

    assertNull(siter.getDiagnosticMessage());

    assertNull(siter.getMatchedDN());

    assertNotNull(siter.getReferralURLs());
    assertEquals(siter.getReferralURLs().length, 0);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(siter.getTransactionID());
    assertEquals(siter.getTransactionID().stringValue(), "txnid");

    assertNull(siter.getBaseDNs());

    assertNotNull(siter.toString());
  }



  /**
   * Tests the first constructor with a transaction ID and set of base DNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1WithBaseDNs()
         throws Exception
  {
    ASN1Element[] baseDNElements =
    {
      new ASN1OctetString("dc=example,dc=com")
    };

    ASN1Element[] elements =
    {
      new ASN1OctetString((byte) 0x80, "txnid"),
      new ASN1Sequence((byte) 0xA1, baseDNElements)
    };

    ASN1OctetString value =
         new ASN1OctetString(new ASN1Sequence(elements).encode());

    ExtendedResult r = new ExtendedResult(1, ResultCode.SUCCESS, null, null,
                                          null, null, value, null);

    StartInteractiveTransactionExtendedResult siter =
         new StartInteractiveTransactionExtendedResult(r);

    assertNotNull(siter);

    assertEquals(siter.getMessageID(), 1);

    assertEquals(siter.getResultCode(), ResultCode.SUCCESS);

    assertNull(siter.getDiagnosticMessage());

    assertNull(siter.getMatchedDN());

    assertNotNull(siter.getReferralURLs());
    assertEquals(siter.getReferralURLs().length, 0);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(siter.getTransactionID());
    assertEquals(siter.getTransactionID().stringValue(), "txnid");

    assertNotNull(siter.getBaseDNs());
    assertEquals(siter.getBaseDNs().size(), 1);

    assertNotNull(siter.toString());
  }



  /**
   * Tests the first constructor with a value that is not a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor1ValueNotSequence()
         throws Exception
  {
    ExtendedResult r = new ExtendedResult(1, ResultCode.SUCCESS, null, null,
         null, null, new ASN1OctetString("x"), null);
    new StartInteractiveTransactionExtendedResult(r);
  }



  /**
   * Tests the first constructor with a set of base DNs that is not a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor1BaseDNsNotSequence()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1OctetString((byte) 0xA1, "x")
    };

    ExtendedResult r = new ExtendedResult(1, ResultCode.SUCCESS, null, null,
         null, null, new ASN1OctetString(new ASN1Sequence(elements).encode()),
         null);
    new StartInteractiveTransactionExtendedResult(r);
  }



  /**
   * Tests the first constructor with a value sequence that doesn't contain a
   * transaction ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor1ValueSequenceNoTransactionID()
         throws Exception
  {
    ExtendedResult r = new ExtendedResult(1, ResultCode.SUCCESS, null, null,
         null, null, new ASN1OctetString(new ASN1Sequence().encode()), null);
    new StartInteractiveTransactionExtendedResult(r);
  }



  /**
   * Tests the first constructor with a value sequence containing an element
   * with an invalid type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor1ValueSequenceInvalidType()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1OctetString((byte) 0x01, "Invalid BER type")
    };

    ExtendedResult r = new ExtendedResult(1, ResultCode.SUCCESS, null, null,
         null, null, new ASN1OctetString(new ASN1Sequence(elements).encode()),
         null);
    new StartInteractiveTransactionExtendedResult(r);
  }



  /**
   * Tests the second constructor with a failure response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Failure()
         throws Exception
  {
    String[] referralURLs =
    {
      "ldap://server1.example.com/",
      "ldap://server2.example.com/",
    };

    StartInteractiveTransactionExtendedResult r =
         new StartInteractiveTransactionExtendedResult(1,
                  ResultCode.INSUFFICIENT_ACCESS_RIGHTS,
                  "Insufficient permission", "dc=example,dc=com", referralURLs,
                  null, null, null);

    assertNotNull(r);

    assertEquals(r.getMessageID(), 1);

    assertEquals(r.getResultCode(), ResultCode.INSUFFICIENT_ACCESS_RIGHTS);

    assertNotNull(r.getDiagnosticMessage());
    assertEquals(r.getDiagnosticMessage(), "Insufficient permission");

    assertNotNull(r.getMatchedDN());
    assertEquals(new DN(r.getMatchedDN()), new DN("dc=example,dc=com"));

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 2);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNull(r.getTransactionID());

    assertNull(r.getBaseDNs());

    assertNotNull(r.getExtendedResultName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the second constructor with a transaction ID but no base DNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NoBaseDNs()
         throws Exception
  {
    StartInteractiveTransactionExtendedResult r =
         new StartInteractiveTransactionExtendedResult(1, ResultCode.SUCCESS,
                  null, null, null, new ASN1OctetString("txnid"), null, null);

    assertNotNull(r);

    assertEquals(r.getMessageID(), 1);

    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(r.getTransactionID());
    assertEquals(r.getTransactionID().stringValue(), "txnid");

    assertNull(r.getBaseDNs());

    assertNotNull(r.getExtendedResultName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the second constructor with a transaction ID and base DNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2WithBaseDNs()
         throws Exception
  {
    ArrayList<String> baseDNs = new ArrayList<String>(1);
    baseDNs.add("dc=example,dc=com");
    baseDNs.add("o=example.com");

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString())
    };

    StartInteractiveTransactionExtendedResult r =
         new StartInteractiveTransactionExtendedResult(1, ResultCode.SUCCESS,
                  null, null, null, new ASN1OctetString("txnid"), baseDNs,
                  controls);

    assertNotNull(r);

    assertEquals(r.getMessageID(), 1);

    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 2);

    assertNotNull(r.getTransactionID());
    assertEquals(r.getTransactionID().stringValue(), "txnid");

    assertNotNull(r.getBaseDNs());
    assertEquals(r.getBaseDNs().size(), 2);

    assertNotNull(r.getExtendedResultName());
    assertNotNull(r.toString());
  }
}
