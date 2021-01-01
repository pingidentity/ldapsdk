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

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * Provides a set of test cases for the end interactive transaction extended
 * request.
 */
@SuppressWarnings("deprecation")
public class EndInteractiveTransactionExtendedRequestTestCase
     extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with the commit flag set to {@code true}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Commit()
         throws Exception
  {
    EndInteractiveTransactionExtendedRequest r =
         new EndInteractiveTransactionExtendedRequest(
                  new ASN1OctetString("txnid"), true);
    r = new EndInteractiveTransactionExtendedRequest(r.duplicate());

    assertNotNull(r);

    assertNotNull(r.getTransactionID());
    assertEquals(r.getTransactionID().stringValue(), "txnid");

    assertTrue(r.commit());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.4");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the first constructor with the commit flag set to {@code false}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Abort()
         throws Exception
  {
    EndInteractiveTransactionExtendedRequest r =
         new EndInteractiveTransactionExtendedRequest(
                  new ASN1OctetString("txnid"), false);
    r = new EndInteractiveTransactionExtendedRequest(r.duplicate());

    assertNotNull(r);

    assertNotNull(r.getTransactionID());
    assertEquals(r.getTransactionID().stringValue(), "txnid");

    assertFalse(r.commit());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.4");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the second constructor with the commit flag set to {@code true}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Commit()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString())
    };

    EndInteractiveTransactionExtendedRequest r =
         new EndInteractiveTransactionExtendedRequest(
                  new ASN1OctetString("txnid"), true, controls);
    r = new EndInteractiveTransactionExtendedRequest(r.duplicate());

    assertNotNull(r);

    assertNotNull(r.getTransactionID());
    assertEquals(r.getTransactionID().stringValue(), "txnid");

    assertTrue(r.commit());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.4");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the second constructor with the commit flag set to {@code false}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Abort()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString())
    };

    EndInteractiveTransactionExtendedRequest r =
         new EndInteractiveTransactionExtendedRequest(
                  new ASN1OctetString("txnid"), false, controls);
    r = new EndInteractiveTransactionExtendedRequest(r.duplicate());

    assertNotNull(r);

    assertNotNull(r.getTransactionID());
    assertEquals(r.getTransactionID().stringValue(), "txnid");

    assertFalse(r.commit());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.4");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the third constructor with an extended request that does not have a
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3NoValue()
         throws Exception
  {
    ExtendedRequest r = new ExtendedRequest("1.3.6.1.4.1.30221.2.6.4",
                                            (ASN1OctetString) null);
    new EndInteractiveTransactionExtendedRequest(r);
  }



  /**
   * Tests the third constructor with an extended request whose value is not a
   * sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueNotSequence()
         throws Exception
  {
    ExtendedRequest r =
         new ExtendedRequest("1.3.6.1.4.1.30221.2.6.4",
                             new ASN1OctetString("x"));
    new EndInteractiveTransactionExtendedRequest(r);
  }



  /**
   * Tests the third constructor with an extended request whose value is an
   * empty sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueEmptySequence()
         throws Exception
  {
    ASN1OctetString value = new ASN1OctetString(new ASN1Sequence().encode());

    ExtendedRequest r =
         new ExtendedRequest("1.3.6.1.4.1.30221.2.6.4", value);
    new EndInteractiveTransactionExtendedRequest(r);
  }



  /**
   * Tests the third constructor with an extended request whose value is a
   * sequence with an invalid type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueSequenceInvalidType()
         throws Exception
  {
    ASN1Element[] elements = new ASN1Element[]
    {
      new ASN1OctetString((byte) 0x01, "Invalid BER type")
    };

    ASN1OctetString value =
         new ASN1OctetString(new ASN1Sequence(elements).encode());

    ExtendedRequest r =
         new ExtendedRequest("1.3.6.1.4.1.30221.2.6.4", value);
    new EndInteractiveTransactionExtendedRequest(r);
  }
}
