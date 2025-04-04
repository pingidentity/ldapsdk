/*
 * Copyright 2008-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2025 Ping Identity Corporation
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
 * Copyright (C) 2008-2025 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the
 * DraftZeilengaLDAPNoOp12RequestControl class.
 */
public class DraftZeilengaLDAPNoOp12RequestControlTestCase
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
    DraftZeilengaLDAPNoOp12RequestControl c =
         new DraftZeilengaLDAPNoOp12RequestControl();
    c = new DraftZeilengaLDAPNoOp12RequestControl(c);

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a valid generic control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Valid()
         throws Exception
  {
    Control genericControl =
         new Control(DraftZeilengaLDAPNoOp12RequestControl.NO_OP_REQUEST_OID,
              true, null);
    DraftZeilengaLDAPNoOp12RequestControl c =
         new DraftZeilengaLDAPNoOp12RequestControl(genericControl);

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with an invalid generic control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor2Invalid()
         throws Exception
  {
    Control genericControl =
         new Control(DraftZeilengaLDAPNoOp12RequestControl.NO_OP_REQUEST_OID,
              true, new ASN1OctetString("foo"));
    new DraftZeilengaLDAPNoOp12RequestControl(genericControl);
  }



  /**
   * Sends a request to the server containing the LDAP no-op request control.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendRequestWithNoOpRequestControl()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    Control[] controls =
    {
      new DraftZeilengaLDAPNoOp12RequestControl()
    };

    LDAPConnection conn = getAdminConnection();

    try
    {
      LDAPResult result = conn.add(new AddRequest(getTestBaseDN(),
                                                  getBaseEntryAttributes(),
                                                  controls));
      assertEquals(result.getResultCode(), ResultCode.NO_OPERATION);
    }
    finally
    {
      conn.close();
    }
  }
}
