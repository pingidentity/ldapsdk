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

import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResult;



/**
 * This class provides a set of test cases for the get matching entry count
 * response control.
 */
public final class MatchingEntryCountResponseControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the control for an examined response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExaminedCountResponse()
         throws Exception
  {
    MatchingEntryCountResponseControl c =
         MatchingEntryCountResponseControl.createExactCountResponse(0, true,
              Arrays.asList("debug1", "debug2"));
    c = new MatchingEntryCountResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.37");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getCountType());
    assertEquals(c.getCountType(), MatchingEntryCountType.EXAMINED_COUNT);

    assertEquals(c.getCountValue(), 0);

    assertTrue(c.searchIndexed());

    assertNotNull(c.getDebugInfo());
    assertEquals(c.getDebugInfo().size(), 2);

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the control for an unexamined response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnexaminedCountResponse()
         throws Exception
  {
    MatchingEntryCountResponseControl c =
         MatchingEntryCountResponseControl.createExactCountResponse(123, false,
              null);
    c = new MatchingEntryCountResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.37");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getCountType());
    assertEquals(c.getCountType(), MatchingEntryCountType.UNEXAMINED_COUNT);

    assertEquals(c.getCountValue(), 123);

    assertTrue(c.searchIndexed());

    assertNotNull(c.getDebugInfo());
    assertEquals(c.getDebugInfo().size(), 0);

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the control for an unexamined response for search
   * criteria that the server considers unindexed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnindexedUnexaminedCountResponse()
         throws Exception
  {
    MatchingEntryCountResponseControl c =
         MatchingEntryCountResponseControl.createExactCountResponse(123, false,
              false, null);
    c = new MatchingEntryCountResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.37");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getCountType());
    assertEquals(c.getCountType(), MatchingEntryCountType.UNEXAMINED_COUNT);

    assertEquals(c.getCountValue(), 123);

    assertFalse(c.searchIndexed());

    assertNotNull(c.getDebugInfo());
    assertEquals(c.getDebugInfo().size(), 0);

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the control for an upper bound response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUpperBoundResponse()
         throws Exception
  {
    MatchingEntryCountResponseControl c =
         MatchingEntryCountResponseControl.createUpperBoundResponse(456,
              Arrays.<String>asList());
    c = new MatchingEntryCountResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.37");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getCountType());
    assertEquals(c.getCountType(), MatchingEntryCountType.UPPER_BOUND);

    assertEquals(c.getCountValue(), 456);

    assertTrue(c.searchIndexed());

    assertNotNull(c.getDebugInfo());
    assertEquals(c.getDebugInfo().size(), 0);

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the control for an upper bound response for search
   * criteria that the server considers unindexed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnindexedUpperBoundResponse()
         throws Exception
  {
    MatchingEntryCountResponseControl c =
         MatchingEntryCountResponseControl.createUpperBoundResponse(456, false,
              Arrays.<String>asList());
    c = new MatchingEntryCountResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.37");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getCountType());
    assertEquals(c.getCountType(), MatchingEntryCountType.UPPER_BOUND);

    assertEquals(c.getCountValue(), 456);

    assertFalse(c.searchIndexed());

    assertNotNull(c.getDebugInfo());
    assertEquals(c.getDebugInfo().size(), 0);

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the control for an unknown count response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnknownCountResponse()
         throws Exception
  {
    MatchingEntryCountResponseControl c =
         MatchingEntryCountResponseControl.createUnknownCountResponse(
              Arrays.asList("debug"));
    c = new MatchingEntryCountResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.37");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getCountType());
    assertEquals(c.getCountType(), MatchingEntryCountType.UNKNOWN);

    assertEquals(c.getCountValue(), -1);

    assertFalse(c.searchIndexed());

    assertNotNull(c.getDebugInfo());
    assertEquals(c.getDebugInfo().size(), 1);

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the {@code get} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGet()
         throws Exception
  {
    SearchResult r = new SearchResult(-1, ResultCode.SUCCESS, null, null, null,
         0, 0, null);
    assertNull(MatchingEntryCountResponseControl.get(r));

    Control[] controls =
    {
      new Control("1.2.3.4")
    };
    r = new SearchResult(-1, ResultCode.SUCCESS, null, null, null,
         0, 0, controls);
    assertNull(MatchingEntryCountResponseControl.get(r));

    controls = new Control[]
    {
      MatchingEntryCountResponseControl.createUnknownCountResponse(null)
    };
    r = new SearchResult(-1, ResultCode.SUCCESS, null, null, null,
         0, 0, controls);
    assertNotNull(MatchingEntryCountResponseControl.get(r));

    controls = new Control[]
    {
      new Control("1.2.3.4"),
      new Control("1.3.6.1.4.1.30221.2.5.37", false,
           MatchingEntryCountResponseControl.createUnknownCountResponse(null).
                getValue())
    };
    r = new SearchResult(-1, ResultCode.SUCCESS, null, null, null,
         0, 0, controls);
    assertNotNull(MatchingEntryCountResponseControl.get(r));
  }



  /**
   * Tests the behavior when trying to decode a control that does not have a
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNoValue()
         throws Exception
  {
    new MatchingEntryCountResponseControl("1.3.6.1.4.1.30221.2.5.37", false,
         null);
  }



  /**
   * Tests the behavior when trying to decode a control whose value cannot be
   * parsed as an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new MatchingEntryCountResponseControl("1.3.6.1.4.1.30221.2.5.37", false,
         new ASN1OctetString("foo"));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence
   * contains an invalid count type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueInvalidCountType()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Integer((byte) 0x84, 12345));

    new MatchingEntryCountResponseControl("1.3.6.1.4.1.30221.2.5.37", false,
         new ASN1OctetString(valueSequence.encode()));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence
   * contains an element with an unexpected BER type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueInvalidElementType()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Integer((byte) 0x80, 12345),
         new ASN1OctetString((byte) 0x12, "foo"));

    new MatchingEntryCountResponseControl("1.3.6.1.4.1.30221.2.5.37", false,
         new ASN1OctetString(valueSequence.encode()));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence
   * contains a negative exact count value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNegativeExactCount()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Integer((byte) 0x80, -1));

    new MatchingEntryCountResponseControl("1.3.6.1.4.1.30221.2.5.37", false,
         new ASN1OctetString(valueSequence.encode()));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence
   * contains an upper bound value of zero.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNegativeZeroUpperBound()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Integer((byte) 0x82, -1));

    new MatchingEntryCountResponseControl("1.3.6.1.4.1.30221.2.5.37", false,
         new ASN1OctetString(valueSequence.encode()));
  }
}
