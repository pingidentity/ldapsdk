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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.util.Arrays;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SimpleBindRequest;



/**
 * This class provides test coverage for the get authorization entry request
 * control.
 */
public class GetAuthorizationEntryRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor, which does not take any arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl();
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertTrue(c.includeAuthNEntry());

    assertTrue(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertTrue(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor without any attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NoAttributes()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(true, false);
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertTrue(c.includeAuthNEntry());

    assertFalse(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertTrue(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a null set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NullAttributes()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(false, true, (String[]) null);
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertFalse(c.includeAuthNEntry());

    assertTrue(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertTrue(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a single attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2SingleAttribute()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(true, true, "cn");
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertTrue(c.includeAuthNEntry());

    assertTrue(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertFalse(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with multiple attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2MultipleAttributes()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(true, true, "givenName", "sn");
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertTrue(c.includeAuthNEntry());

    assertTrue(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertFalse(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor without any attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3NoAttributes()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(true, false,
                                                 Arrays.<String>asList());
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertTrue(c.includeAuthNEntry());

    assertFalse(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertTrue(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with a null set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3NullAttributes()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(false, true,
                                                 (List<String>) null);
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertFalse(c.includeAuthNEntry());

    assertTrue(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertTrue(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with a single attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3SingleAttribute()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(true, true,
                                                 Arrays.asList("cn"));
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertTrue(c.includeAuthNEntry());

    assertTrue(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertFalse(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with multiple attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3MultipleAttributes()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(true, true,
                  Arrays.asList("givenName", "sn"));
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertTrue(c.includeAuthNEntry());

    assertTrue(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertFalse(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the fourth constructor without any attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4NoAttributes()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(true, true, false);
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertTrue(c.includeAuthNEntry());

    assertFalse(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertTrue(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the fourth constructor with a null set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4NullAttributes()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(false, false, true,
                                                 (String[]) null);
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertFalse(c.includeAuthNEntry());

    assertTrue(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertTrue(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the fourth constructor with a single attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4SingleAttribute()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(true, true, true, "cn");
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertTrue(c.includeAuthNEntry());

    assertTrue(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertFalse(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the fourth constructor with multiple attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4MultipleAttributes()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(false, true, true, "givenName",
                                                 "sn");
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertTrue(c.includeAuthNEntry());

    assertTrue(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertFalse(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the fifth constructor without any attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5NoAttributes()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(true, true, false,
                                                 Arrays.<String>asList());
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertTrue(c.includeAuthNEntry());

    assertFalse(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertTrue(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the fifth constructor with a null set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5NullAttributes()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(false, false, true,
                                                 (List<String>) null);
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertFalse(c.includeAuthNEntry());

    assertTrue(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertTrue(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the fifth constructor with a single attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5SingleAttribute()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(true, true, true,
                                                 Arrays.asList("cn"));
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertTrue(c.includeAuthNEntry());

    assertTrue(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertFalse(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the fifth constructor with multiple attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5MultipleAttributes()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(false, true, true,
                  Arrays.asList("givenName", "sn"));
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertTrue(c.includeAuthNEntry());

    assertTrue(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertFalse(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the sixth constructor with a control value that is not a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor6ValueNotSequence()
         throws Exception
  {
    Control c = new Control("1.2.3.4", false,
                            new ASN1OctetString(new byte[1]));
    new GetAuthorizationEntryRequestControl(c);
  }



  /**
   * Tests the sixth constructor with a control value sequence containing an
   * invalid element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor6ValueSequenceHasInvalidType()
         throws Exception
  {
    ASN1Sequence s = new ASN1Sequence(new ASN1OctetString((byte) 0x00));
    Control c = new Control("1.2.3.4", false, new ASN1OctetString(s.encode()));
    new GetAuthorizationEntryRequestControl(c);
  }



  /**
   * Sends a request to the server containing the get authorization entry
   * request control.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendRequestWithGetAuthorizationEntryRequestControl()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getUnauthenticatedConnection();

    try
    {
      BindResult bindResult = conn.bind(new SimpleBindRequest(getTestBindDN(),
           getTestBindPassword(),
           new GetAuthorizationEntryRequestControl(true, true, "*", "+")));

      assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);

      GetAuthorizationEntryResponseControl c =
           GetAuthorizationEntryResponseControl.get(bindResult);
      assertNotNull(c);

      assertTrue(c.isAuthenticated());

      assertTrue(c.identitiesMatch());

      assertNotNull(c.getAuthNID());
      assertNotNull(c.getAuthNEntry());

      assertNotNull(c.getAuthZID());
      assertNotNull(c.getAuthZEntry());

      assertNotNull(c.getControlName());

      assertNotNull(c.toString());
    }
    finally
    {
      conn.close();
    }
  }
}
