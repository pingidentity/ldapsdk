/*
 * Copyright 2007-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2007-2018 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.AsyncRequestIDFactory;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the CancelExtendedRequest class.
 */
public class CancelExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    CancelExtendedRequest extendedRequest =
         new CancelExtendedRequest(AsyncRequestIDFactory.create(999));
    extendedRequest = new CancelExtendedRequest(extendedRequest);
    extendedRequest = extendedRequest.duplicate();

    assertNotNull(extendedRequest.getOID());
    assertEquals(extendedRequest.getOID(), "1.3.6.1.1.8");

    assertNotNull(extendedRequest.getValue());

    assertEquals(extendedRequest.getTargetMessageID(), 999);

    assertNotNull(extendedRequest.getControls());
    assertEquals(extendedRequest.getControls().length, 0);

    assertNotNull(extendedRequest.getExtendedRequestName());
    assertNotNull(extendedRequest.toString());
  }



  /**
   * Tests the second constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    CancelExtendedRequest extendedRequest = new CancelExtendedRequest(999);
    extendedRequest = new CancelExtendedRequest(extendedRequest);
    extendedRequest = extendedRequest.duplicate();

    assertNotNull(extendedRequest.getOID());
    assertEquals(extendedRequest.getOID(), "1.3.6.1.1.8");

    assertNotNull(extendedRequest.getValue());

    assertEquals(extendedRequest.getTargetMessageID(), 999);

    assertNotNull(extendedRequest.getControls());
    assertEquals(extendedRequest.getControls().length, 0);

    assertNotNull(extendedRequest.getExtendedRequestName());
    assertNotNull(extendedRequest.toString());
  }



  /**
   * Tests the third constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    CancelExtendedRequest extendedRequest =
         new CancelExtendedRequest(AsyncRequestIDFactory.create(999), controls);
    extendedRequest = new CancelExtendedRequest(extendedRequest);
    extendedRequest = extendedRequest.duplicate();

    assertNotNull(extendedRequest.getOID());
    assertEquals(extendedRequest.getOID(), "1.3.6.1.1.8");

    assertNotNull(extendedRequest.getValue());

    assertEquals(extendedRequest.getTargetMessageID(), 999);

    assertNotNull(extendedRequest.getControls());
    assertEquals(extendedRequest.getControls().length, 2);

    assertNotNull(extendedRequest.getExtendedRequestName());
    assertNotNull(extendedRequest.toString());
  }



  /**
   * Tests the fourth constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    CancelExtendedRequest extendedRequest =
         new CancelExtendedRequest(999, controls);
    extendedRequest = new CancelExtendedRequest(extendedRequest);
    extendedRequest = extendedRequest.duplicate();

    assertNotNull(extendedRequest.getOID());
    assertEquals(extendedRequest.getOID(), "1.3.6.1.1.8");

    assertNotNull(extendedRequest.getValue());

    assertEquals(extendedRequest.getTargetMessageID(), 999);

    assertNotNull(extendedRequest.getControls());
    assertEquals(extendedRequest.getControls().length, 2);

    assertNotNull(extendedRequest.getExtendedRequestName());
    assertNotNull(extendedRequest.toString());
  }



  /**
   * Tests the fifth constructor with a generic request containing no value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor5NoValue()
         throws Exception
  {
    new CancelExtendedRequest(new ExtendedRequest("1.2.3.4"));
  }



  /**
   * Tests the fifth constructor with a generic request with an invalid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor5InnvalidValue()
         throws Exception
  {
    new CancelExtendedRequest(new ExtendedRequest("1.2.3.4",
                                                  new ASN1OctetString("foo")));
  }
}
