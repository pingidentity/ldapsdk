/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.experimental;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResult;



/**
 * This class provides a set of test cases for the Active Directory DirSync
 * control.
 */
public final class ActiveDirectoryDirSyncControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the control with a cookie.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithCookie()
         throws Exception
  {
    ActiveDirectoryDirSyncControl c = new ActiveDirectoryDirSyncControl(true,
         123, 456, new ASN1OctetString("789"));

    c = new ActiveDirectoryDirSyncControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());
    assertNotNull(c);

    assertEquals(c.getFlags(), 123);

    assertEquals(c.getMaxAttributeCount(), 456);

    assertNotNull(c.getCookie());
    assertEquals(c.getCookie(), new ASN1OctetString("789"));

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.2.840.113556.1.4.841");

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the control without a cookie.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutCookie()
         throws Exception
  {
    ActiveDirectoryDirSyncControl c = new ActiveDirectoryDirSyncControl(true,
         987, 654, null);

    c = new ActiveDirectoryDirSyncControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());
    assertNotNull(c);

    assertEquals(c.getFlags(), 987);

    assertEquals(c.getMaxAttributeCount(), 654);

    assertNotNull(c.getCookie());
    assertEquals(c.getCookie(), new ASN1OctetString());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.2.840.113556.1.4.841");

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when trying to decode a generic control with no value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMissingValue()
         throws Exception
  {
    final ActiveDirectoryDirSyncControl c = new ActiveDirectoryDirSyncControl();
    c.decodeControl("1.2.840.113556.1.4.841", true, null);
  }



  /**
   * Tests the behavior when trying to decode a generic control whose value
   * cannot be decoded as an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    final ActiveDirectoryDirSyncControl c = new ActiveDirectoryDirSyncControl();
    c.decodeControl("1.2.840.113556.1.4.841", true, new ASN1OctetString("foo"));
  }



  /**
   * Tests the behavior of the get method for a search result with no controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetNoControl()
         throws Exception
  {
    final SearchResult searchResult = new SearchResult(2, ResultCode.SUCCESS,
         null, null, null, 0, 0, null);
    assertNull(ActiveDirectoryDirSyncControl.get(searchResult));
  }



  /**
   * Tests the behavior of the get method for a search result with a control but
   * no DirSync control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetNoDirSyncControl()
         throws Exception
  {
    final Control[] controls =
    {
      new Control("1.2.3.4")
    };

    final SearchResult searchResult = new SearchResult(2, ResultCode.SUCCESS,
         null, null, null, 0, 0, controls);
    assertNull(ActiveDirectoryDirSyncControl.get(searchResult));
  }



  /**
   * Tests the behavior of the get method for a search result with a pre-decoded
   * DirSync control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetDecodedDirSyncControl()
         throws Exception
  {
    final int flags = ActiveDirectoryDirSyncControl.FLAG_INCREMENTAL_VALUES |
         ActiveDirectoryDirSyncControl.FLAG_OBJECT_SECURITY;
    final Control[] controls =
    {
      new ActiveDirectoryDirSyncControl(true, flags, 50, null)
    };

    final SearchResult searchResult = new SearchResult(2, ResultCode.SUCCESS,
         null, null, null, 0, 0, controls);
    final ActiveDirectoryDirSyncControl responseControl =
         ActiveDirectoryDirSyncControl.get(searchResult);
    assertNotNull(responseControl);

    assertEquals(responseControl.getFlags(), flags);

    assertEquals(responseControl.getMaxAttributeCount(), 50);

    assertNotNull(responseControl.getCookie());
    assertEquals(responseControl.getCookie().getValueLength(), 0);
  }



  /**
   * Tests the behavior of the get method for a search result with a non-decoded
   * DirSync control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetGenericControl()
         throws Exception
  {
    final int flags = ActiveDirectoryDirSyncControl.FLAG_INCREMENTAL_VALUES |
         ActiveDirectoryDirSyncControl.FLAG_OBJECT_SECURITY;
    final Control[] controls =
    {
      new Control(ActiveDirectoryDirSyncControl.DIRSYNC_OID, true,
           new ActiveDirectoryDirSyncControl(true, flags, 50, null).getValue())
    };

    final SearchResult searchResult = new SearchResult(2, ResultCode.SUCCESS,
         null, null, null, 0, 0, controls);
    final ActiveDirectoryDirSyncControl responseControl =
         ActiveDirectoryDirSyncControl.get(searchResult);
    assertNotNull(responseControl);

    assertEquals(responseControl.getFlags(), flags);

    assertEquals(responseControl.getMaxAttributeCount(), 50);

    assertNotNull(responseControl.getCookie());
    assertEquals(responseControl.getCookie().getValueLength(), 0);
  }



  /**
   * Tests the behavior of the get method for a search result with a generic
   * control that can't be decoded as a DirSync control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetMalformedControl()
         throws Exception
  {
    final Control[] controls =
    {
      new Control(ActiveDirectoryDirSyncControl.DIRSYNC_OID, true,
           new ASN1OctetString("malformed"))
    };

    final SearchResult searchResult = new SearchResult(2, ResultCode.SUCCESS,
         null, null, null, 0, 0, controls);
    ActiveDirectoryDirSyncControl.get(searchResult);
  }
}
