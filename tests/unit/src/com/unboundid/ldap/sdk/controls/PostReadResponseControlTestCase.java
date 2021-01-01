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
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the PostReadResponseControl
 * class.
 */
public class PostReadResponseControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor.
   */
  @Test()
  public void testConstructor1()
  {
    new PostReadResponseControl();
  }



  /**
   * Tests the second constructor.
   */
  @Test()
  public void testConstructor2()
  {
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };

    ReadOnlyEntry entry = new ReadOnlyEntry("dc=example,dc=com", attrs);

    PostReadResponseControl c = new PostReadResponseControl(entry);

    assertFalse(c.isCritical());

    assertNotNull(c.getEntry());
    assertEquals(c.getEntry().getDN(), "dc=example,dc=com");

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with a value that contains a valid entry with
   * attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3ValidEntryWithAttributes()
         throws Exception
  {
    String dn = "dc=example,dc=com";

    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };

    ASN1Element[] attrElements = new ASN1Element[attrs.length];
    for (int i=0; i < attrs.length; i++)
    {
      attrElements[i] = attrs[i].encode();
    }

    ASN1Element[] elements =
    {
      new ASN1OctetString(dn),
      new ASN1Sequence(attrElements)
    };

    PostReadResponseControl c =
         new PostReadResponseControl("1.3.6.1.1.13.2", false,
                  new ASN1OctetString(new ASN1Sequence(elements).encode()));

    assertNotNull(c.getEntry());
    assertEquals(c.getEntry().getDN(), dn);

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with a value that contains a valid entry with
   * no attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3ValidEntryNoAttributes()
         throws Exception
  {
    String dn = "dc=example,dc=com";
    ASN1Element[] elements =
    {
      new ASN1OctetString(dn),
      new ASN1Sequence()
    };

    PostReadResponseControl c =
         new PostReadResponseControl("1.3.6.1.1.13.2", false,
                  new ASN1OctetString(new ASN1Sequence(elements).encode()));

    assertNotNull(c.getEntry());
    assertEquals(c.getEntry().getDN(), dn);

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
    new PostReadResponseControl("1.3.6.1.1.13.2", false, null);
  }



  /**
   * Tests the third constructor with a value that is not a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueNotSequence()
         throws Exception
  {
    new PostReadResponseControl("1.3.6.1.1.13.2", false,
             new ASN1OctetString(new byte[1]));
  }



  /**
   * Tests the third constructor with a value sequence with an invalid number of
   * elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueSequenceInvalidElementCount()
         throws Exception
  {
    new PostReadResponseControl("1.3.6.1.1.13.2", false,
             new ASN1OctetString(new ASN1Sequence().encode()));
  }



  /**
   * Tests the third constructor with a value sequence in which the second
   * element is not a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueSequenceSecondElementNotSequence()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1OctetString("dc=example,dc=com"),
      new ASN1OctetString(new byte[1])
    };

    new PostReadResponseControl("1.3.6.1.1.13.2", false,
             new ASN1OctetString(new ASN1Sequence(elements).encode()));
  }



  /**
   * Tests the third constructor with a value sequence in which the second
   * element is not a sequence of sequences.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueSequenceSecondElementNotSequenceOfSequence()
         throws Exception
  {
    ASN1Element[] bogusElements =
    {
      new ASN1OctetString(new byte[1])
    };

    ASN1Element[] elements =
    {
      new ASN1OctetString("dc=example,dc=com"),
      new ASN1Sequence(bogusElements)
    };

    new PostReadResponseControl("1.3.6.1.1.13.2", false,
             new ASN1OctetString(new ASN1Sequence(elements).encode()));
  }



  /**
   * Tests the {@code get} method with a result that does not contain a
   * post-read response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetMissing()
         throws Exception
  {
    final Control[] controls = new Control[0];

    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS);

    final PostReadResponseControl c = PostReadResponseControl.get(r);
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
      new PostReadResponseControl(new ReadOnlyEntry(
           generateDomainEntry("example", "dc=com")))
    };

    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    final PostReadResponseControl c = PostReadResponseControl.get(r);
    assertNotNull(c);

    assertNotNull(c.getEntry());
    assertEquals(c.getEntry().getParsedDN(), new DN("dc=example,dc=com"));
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that can be parsed as a post-read response
   * control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValidGenericType()
         throws Exception
  {
    final Control tmp = new PostReadResponseControl(new ReadOnlyEntry(
         generateDomainEntry("example", "dc=com")));

    final Control[] controls =
    {
      new Control(tmp.getOID(), tmp.isCritical(), tmp.getValue())
    };

    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    final PostReadResponseControl c = PostReadResponseControl.get(r);
    assertNotNull(c);

    assertNotNull(c.getEntry());
    assertEquals(c.getEntry().getParsedDN(), new DN("dc=example,dc=com"));
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that cannot be parsed as an post-read response
   * control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetInvalidGenericType()
         throws Exception
  {
    final Control[] controls =
    {
      new Control(PostReadResponseControl.POST_READ_RESPONSE_OID, false, null)
    };

    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    PostReadResponseControl.get(r);
  }
}
