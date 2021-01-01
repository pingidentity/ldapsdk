/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
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
 * Copyright (C) 2014-2021 Ping Identity Corporation
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

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResultEntry;



/**
 * This class provides a set of test cases for the get backend set ID response
 * control.
 */
public final class GetBackendSetIDResponseControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with a get backend set ID response control with a single
   * backend set ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleBackendSetID()
         throws Exception
  {
    GetBackendSetIDResponseControl c =
         new GetBackendSetIDResponseControl("eb-id", "bs-id");
    c = new GetBackendSetIDResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.34");
    assertEquals(c.getOID(),
         GetBackendSetIDResponseControl.GET_BACKEND_SET_ID_RESPONSE_OID);

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getEntryBalancingRequestProcessorID());
    assertEquals(c.getEntryBalancingRequestProcessorID(), "eb-id");

    assertNotNull(c.getBackendSetIDs());
    assertEquals(c.getBackendSetIDs().size(), 1);
    assertTrue(c.getBackendSetIDs().contains("bs-id"));
    assertFalse(c.getBackendSetIDs().contains("eb-id"));

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior with a get backend set ID response control with multiple
   * backend set IDs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleBackendSetIDs()
         throws Exception
  {
    GetBackendSetIDResponseControl c =
         new GetBackendSetIDResponseControl("eb-id",
              Arrays.asList("bs-id-1", "bs-id-2"));
    c = new GetBackendSetIDResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.34");
    assertEquals(c.getOID(),
         GetBackendSetIDResponseControl.GET_BACKEND_SET_ID_RESPONSE_OID);

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getEntryBalancingRequestProcessorID());
    assertEquals(c.getEntryBalancingRequestProcessorID(), "eb-id");

    assertNotNull(c.getBackendSetIDs());
    assertEquals(c.getBackendSetIDs().size(), 2);
    assertTrue(c.getBackendSetIDs().contains("bs-id-1"));
    assertTrue(c.getBackendSetIDs().contains("bs-id-2"));
    assertFalse(c.getBackendSetIDs().contains("eb-id"));

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the get method for an {@code LDAPResult} object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetForLDAPResult()
         throws Exception
  {
    LDAPResult r = new LDAPResult(-1, ResultCode.SUCCESS);
    assertNull(GetBackendSetIDResponseControl.get(r));

    Control[] controls =
    {
      new GetBackendSetIDResponseControl("eb-id", "bs-id")
    };
    r = new LDAPResult(-1, ResultCode.SUCCESS, null, null, null, controls);
    assertNotNull(GetBackendSetIDResponseControl.get(r));

    controls = new Control[]
    {
      new Control("1.2.3.4"),
    };
    r = new LDAPResult(-1, ResultCode.SUCCESS, null, null, null, controls);
    assertNull(GetBackendSetIDResponseControl.get(r));

    controls = new Control[]
    {
      new Control("1.2.3.4"),
      new Control("1.3.6.1.4.1.30221.2.5.34", false,
           new GetBackendSetIDResponseControl("eb-id", "bs-id").getValue())
    };
    r = new LDAPResult(-1, ResultCode.SUCCESS, null, null, null, controls);
    assertNotNull(GetBackendSetIDResponseControl.get(r));

    controls = new Control[]
    {
      new Control("1.2.3.4"),
      new Control("1.3.6.1.4.1.30221.2.5.34", false,
           new ASN1OctetString("malformed"))
    };
    try
    {
      r = new LDAPResult(-1, ResultCode.SUCCESS, null, null, null, controls);
      GetBackendSetIDResponseControl.get(r);
      fail("Expected an exception for a malformed control");
    }
    catch (final LDAPException le)
    {
      assertResultCodeEquals(le, ResultCode.DECODING_ERROR);
    }
  }



  /**
   * Tests the behavior of the get method for a {@code SearchResultEntry}
   * object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetForSearchResultEntry()
         throws Exception
  {
    final Entry e = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    SearchResultEntry sre = new SearchResultEntry(e);
    assertNull(GetBackendSetIDResponseControl.get(sre));

    Control[] controls =
    {
      new GetBackendSetIDResponseControl("eb-id", "bs-id")
    };
    sre = new SearchResultEntry(e, controls);
    assertNotNull(GetBackendSetIDResponseControl.get(sre));

    controls = new Control[]
    {
      new Control("1.2.3.4"),
    };
    sre = new SearchResultEntry(e, controls);
    assertNull(GetBackendSetIDResponseControl.get(sre));

    controls = new Control[]
    {
      new Control("1.2.3.4"),
      new Control("1.3.6.1.4.1.30221.2.5.34", false,
           new GetBackendSetIDResponseControl("eb-id", "bs-id").getValue())
    };
    sre = new SearchResultEntry(e, controls);
    assertNotNull(GetBackendSetIDResponseControl.get(sre));

    controls = new Control[]
    {
      new Control("1.2.3.4"),
      new Control("1.3.6.1.4.1.30221.2.5.34", false,
           new ASN1OctetString("malformed"))
    };
    try
    {
      sre = new SearchResultEntry(e, controls);
      GetBackendSetIDResponseControl.get(sre);
      fail("Expected an exception for a malformed control");
    }
    catch (final LDAPException le)
    {
      assertResultCodeEquals(le, ResultCode.DECODING_ERROR);
    }
  }



  /**
   * Tests the behavior of the get method for an {@code ExtendedResult}
   * object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetForExtendedResult()
         throws Exception
  {
    LDAPResult r = new LDAPResult(-1, ResultCode.SUCCESS);
    ExtendedResult er = new ExtendedResult(r);
    assertTrue(GetBackendSetIDResponseControl.get(er).isEmpty());

    Control[] controls =
    {
      new GetBackendSetIDResponseControl("eb-id", "bs-id")
    };
    r = new LDAPResult(-1, ResultCode.SUCCESS, null, null, null, controls);
    er = new ExtendedResult(r);
    assertFalse(GetBackendSetIDResponseControl.get(er).isEmpty());
    assertEquals(GetBackendSetIDResponseControl.get(er).size(), 1);

    controls = new Control[]
    {
      new Control("1.2.3.4"),
    };
    r = new LDAPResult(-1, ResultCode.SUCCESS, null, null, null, controls);
    er = new ExtendedResult(r);
    assertTrue(GetBackendSetIDResponseControl.get(er).isEmpty());

    controls = new Control[]
    {
      new Control("1.2.3.4"),
      new Control("1.3.6.1.4.1.30221.2.5.34", false,
           new GetBackendSetIDResponseControl("eb-id", "bs-id").getValue())
    };
    r = new LDAPResult(-1, ResultCode.SUCCESS, null, null, null, controls);
    er = new ExtendedResult(r);
    assertFalse(GetBackendSetIDResponseControl.get(er).isEmpty());
    assertEquals(GetBackendSetIDResponseControl.get(er).size(), 1);

    controls = new Control[]
    {
      new Control("1.2.3.4"),
      new Control("1.3.6.1.4.1.30221.2.5.34", false,
           new GetBackendSetIDResponseControl("eb-id-1", "bs-id-1").getValue()),
      new Control("1.3.6.1.4.1.30221.2.5.34", false,
           new GetBackendSetIDResponseControl("eb-id-2", "bs-id-2").getValue())
    };
    r = new LDAPResult(-1, ResultCode.SUCCESS, null, null, null, controls);
    er = new ExtendedResult(r);
    assertFalse(GetBackendSetIDResponseControl.get(er).isEmpty());
    assertEquals(GetBackendSetIDResponseControl.get(er).size(), 2);

    controls = new Control[]
    {
      new Control("1.2.3.4"),
      new Control("1.3.6.1.4.1.30221.2.5.34", false,
           new ASN1OctetString("malformed"))
    };
    try
    {
      r = new LDAPResult(-1, ResultCode.SUCCESS, null, null, null, controls);
      er = new ExtendedResult(r);
      GetBackendSetIDResponseControl.get(er);
      fail("Expected an exception for a malformed control");
    }
    catch (final LDAPException le)
    {
      assertResultCodeEquals(le, ResultCode.DECODING_ERROR);
    }
  }



  /**
   * Tests the behavior when attempting to decode a control has does not have
   * a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeWithoutValues()
         throws Exception
  {
    new GetBackendSetIDResponseControl("1.3.6.1.4.1.30221.2.5.34", false, null);
  }



  /**
   * Tests the behavior when attempting to decode a control has a value that is
   * not a valid ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new GetBackendSetIDResponseControl("1.3.6.1.4.1.30221.2.5.34", false,
         new ASN1OctetString("foo"));
  }
}
