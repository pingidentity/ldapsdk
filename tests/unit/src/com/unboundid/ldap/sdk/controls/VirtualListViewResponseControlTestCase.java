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
package com.unboundid.ldap.sdk.controls;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResult;



/**
 * This class provides a set of test cases for the
 * VirtualListViewResponseControl class.
 */
public class VirtualListViewResponseControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor.
   */
  @Test()
  public void testConstructor1()
  {
    new ServerSideSortResponseControl();
  }



  /**
   * Tests the second constructor with a non-{@code null} context ID.
   */
  @Test()
  public void testConstructor2()
  {
    VirtualListViewResponseControl c =
         new VirtualListViewResponseControl(1, 10, ResultCode.SUCCESS,
                                            new ASN1OctetString());

    assertEquals(c.getResultCode(), ResultCode.SUCCESS);
    assertEquals(c.getTargetPosition(), 1);
    assertEquals(c.getContentCount(), 10);
    assertNotNull(c.getContextID());
    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a {@code null} context ID.
   */
  @Test()
  public void testConstructor2NullContextID()
  {
    VirtualListViewResponseControl c =
         new VirtualListViewResponseControl(1, 10, ResultCode.SUCCESS, null);

    assertEquals(c.getResultCode(), ResultCode.SUCCESS);
    assertEquals(c.getTargetPosition(), 1);
    assertEquals(c.getContentCount(), 10);
    assertNull(c.getContextID());
    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor including a context ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3WithContextID()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1Integer(10),
      new ASN1Integer(100),
      new ASN1Enumerated(0),
      new ASN1OctetString(new byte[1])
    };

    VirtualListViewResponseControl c =
         new VirtualListViewResponseControl("2.16.840.1.113730.3.4.10", false,
                  new ASN1OctetString(new ASN1Sequence(elements).encode()));

    assertEquals(c.getTargetPosition(), 10);

    assertEquals(c.getContentCount(), 100);

    assertEquals(c.getResultCode(), ResultCode.SUCCESS);

    assertNotNull(c.getContextID());

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor not including a context ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3WithoutContextID()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1Integer(10),
      new ASN1Integer(100),
      new ASN1Enumerated(0)
    };

    VirtualListViewResponseControl c =
         new VirtualListViewResponseControl("2.16.840.1.113730.3.4.10", false,
                  new ASN1OctetString(new ASN1Sequence(elements).encode()));

    assertEquals(c.getTargetPosition(), 10);

    assertEquals(c.getContentCount(), 100);

    assertEquals(c.getResultCode(), ResultCode.SUCCESS);

    assertNull(c.getContextID());

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with a {@code null} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3NullValue()
         throws Exception
  {
    new VirtualListViewResponseControl("2.16.840.1.113730.3.4.10", false, null);
  }



  /**
   * Tests the third constructor with a value that can't be decoded as a
   * sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueNotSequence()
         throws Exception
  {
    new VirtualListViewResponseControl("2.16.840.1.113730.3.4.10", false,
             new ASN1OctetString(new ASN1OctetString(new byte[1]).encode()));
  }



  /**
   * Tests the third constructor with a value sequence with an invalid number of
   * elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueSequenceInvalidLength()
         throws Exception
  {
    new VirtualListViewResponseControl("2.16.840.1.113730.3.4.10", false,
             new ASN1OctetString(new ASN1Sequence().encode()));
  }



  /**
   * Tests the third constructor with a value sequence in which the first
   * element cannot be decoded as an integer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueSequenceFirstElementNotInteger()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1OctetString(),
      new ASN1Integer(10),
      new ASN1Enumerated(0)
    };

    new VirtualListViewResponseControl("2.16.840.1.113730.3.4.10", false,
             new ASN1OctetString(new ASN1Sequence(elements).encode()));
  }



  /**
   * Tests the third constructor with a value sequence in which the second
   * element cannot be decoded as an integer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueSequenceSecondElementNotInteger()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1Integer(5),
      new ASN1OctetString(),
      new ASN1Enumerated(0)
    };

    new VirtualListViewResponseControl("2.16.840.1.113730.3.4.10", false,
             new ASN1OctetString(new ASN1Sequence(elements).encode()));
  }



  /**
   * Tests the third constructor with a value sequence in which the third
   * element cannot be decoded as an enumerated element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueSequenceSecondElementNotEnumerated()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1Integer(5),
      new ASN1Integer(10),
      new ASN1OctetString()
    };

    new VirtualListViewResponseControl("2.16.840.1.113730.3.4.10", false,
             new ASN1OctetString(new ASN1Sequence(elements).encode()));
  }



  /**
   * Tests the {@code get} method with a result that does not contain a virtual
   * list view response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetMissing()
         throws Exception
  {
    final Control[] controls = new Control[0];

    final SearchResult r = new SearchResult(1, ResultCode.SUCCESS, null, null,
         null, 10, 0, controls);

    final VirtualListViewResponseControl c =
         VirtualListViewResponseControl.get(r);
    assertNull(c);
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is already of the appropriate type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValidCorrectType()
         throws Exception
  {
    final Control[] controls =
    {
      new VirtualListViewResponseControl(1, 123, ResultCode.SUCCESS,
           new ASN1OctetString("foo"))
    };

    final SearchResult r = new SearchResult(1, ResultCode.SUCCESS, null, null,
         null, 10, 0, controls);

    final VirtualListViewResponseControl c =
         VirtualListViewResponseControl.get(r);
    assertNotNull(c);

    assertEquals(c.getTargetPosition(), 1);

    assertEquals(c.getContentCount(), 123);

    assertNotNull(c.getResultCode());
    assertEquals(c.getResultCode(), ResultCode.SUCCESS);

    assertNotNull(c.getContextID());
    assertEquals(c.getContextID().stringValue(), "foo");
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that can be parsed as a virtual list view
   * response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValidGenericType()
         throws Exception
  {
    final Control tmp = new VirtualListViewResponseControl(1, 123,
         ResultCode.SUCCESS, new ASN1OctetString("foo"));

    final Control[] controls =
    {
      new Control(tmp.getOID(), tmp.isCritical(), tmp.getValue())
    };

    final SearchResult r = new SearchResult(1, ResultCode.SUCCESS, null, null,
         null, 10, 0, controls);

    final VirtualListViewResponseControl c =
         VirtualListViewResponseControl.get(r);
    assertNotNull(c);

    assertEquals(c.getTargetPosition(), 1);

    assertEquals(c.getContentCount(), 123);

    assertNotNull(c.getResultCode());
    assertEquals(c.getResultCode(), ResultCode.SUCCESS);

    assertNotNull(c.getContextID());
    assertEquals(c.getContextID().stringValue(), "foo");
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that cannot be parsed as a virtual list view
   * response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetInvalidGenericType()
         throws Exception
  {
    final Control[] controls =
    {
      new Control(VirtualListViewResponseControl.VIRTUAL_LIST_VIEW_RESPONSE_OID,
           false, null)
    };

    final SearchResult r = new SearchResult(1, ResultCode.SUCCESS, null, null,
         null, 10, 0, controls);

    VirtualListViewResponseControl.get(r);
  }
}
