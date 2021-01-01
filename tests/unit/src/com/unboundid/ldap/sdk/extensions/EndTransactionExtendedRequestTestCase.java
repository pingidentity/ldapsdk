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
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the
 * {@code EndTransactionExtendedRequest} class.
 */
public class EndTransactionExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with a non-{@code null} transaction ID and a
   * commit value of {@code true}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Commit()
         throws Exception
  {
    EndTransactionExtendedRequest r =
         new EndTransactionExtendedRequest(new ASN1OctetString("123"), true);
    r = new EndTransactionExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.1.21.3");

    assertNotNull(r.getValue());

    assertNotNull(r.getTransactionID());
    assertEquals(r.getTransactionID().stringValue(), "123");

    assertTrue(r.commit());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the first constructor with a non-{@code null} transaction ID and a
   * commit value of {@code false}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Abort()
         throws Exception
  {
    EndTransactionExtendedRequest r =
         new EndTransactionExtendedRequest(new ASN1OctetString("123"), false);
    r = new EndTransactionExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.1.21.3");

    assertNotNull(r.getValue());

    assertNotNull(r.getTransactionID());
    assertEquals(r.getTransactionID().stringValue(), "123");

    assertFalse(r.commit());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the first constructor with a {@code null} transaction ID.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1Null()
  {
    new EndTransactionExtendedRequest(null, true);
  }



  /**
   * Tests the second constructor with a non-{@code null} transaction ID and a
   * commit value of {@code true}.
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
      new Control("1.2.3.5", true, null)
    };

    EndTransactionExtendedRequest r =
         new EndTransactionExtendedRequest(new ASN1OctetString("123"), true,
              controls);
    r = new EndTransactionExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.1.21.3");

    assertNotNull(r.getValue());

    assertNotNull(r.getTransactionID());
    assertEquals(r.getTransactionID().stringValue(), "123");

    assertTrue(r.commit());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the second constructor with a non-{@code null} transaction ID and a
   * commit value of {@code false}.
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
      new Control("1.2.3.5", true, null)
    };

    EndTransactionExtendedRequest r =
         new EndTransactionExtendedRequest(new ASN1OctetString("123"), false,
              controls);
    r = new EndTransactionExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.1.21.3");

    assertNotNull(r.getValue());

    assertNotNull(r.getTransactionID());
    assertEquals(r.getTransactionID().stringValue(), "123");

    assertFalse(r.commit());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the second constructor with a {@code null} transaction ID.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor2Null()
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    new EndTransactionExtendedRequest(null, true, controls);
  }



  /**
   * Tests the third constructor with a generic request containing no value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3NoValue()
         throws Exception
  {
    new EndTransactionExtendedRequest(new ExtendedRequest("1.2.3.4"));
  }



  /**
   * Tests the third constructor with a generic request containing an invalid
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3InvalidValue()
         throws Exception
  {
    new EndTransactionExtendedRequest(
         new ExtendedRequest("1.2.3.4", new ASN1OctetString("foo")));
  }
}
