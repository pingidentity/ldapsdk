/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the soft delete request control.
 */
public final class SoftDeleteRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a version of the control created with the default settings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultControl()
         throws Exception
  {
    SoftDeleteRequestControl c = new SoftDeleteRequestControl();
    c = new SoftDeleteRequestControl(c);

    assertNull(c.getValue());

    assertTrue(c.isCritical());

    assertTrue(c.returnSoftDeleteResponse());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests a version of the control created with all non-default settings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonDefaultControl()
         throws Exception
  {
    SoftDeleteRequestControl c = new SoftDeleteRequestControl(false, false);
    c = new SoftDeleteRequestControl(c);

    assertNotNull(c.getValue());

    assertFalse(c.isCritical());

    assertFalse(c.returnSoftDeleteResponse());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the ability to create a soft delete request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSoftDeleteRequest()
         throws Exception
  {
    final DeleteRequest softDeleteRequest =
         SoftDeleteRequestControl.createSoftDeleteRequest(
              "uid=test.user,ou=People,dc=example,dc=com", true, true);

    assertNotNull(softDeleteRequest);

    assertNotNull(softDeleteRequest.getDN());
    assertTrue(DN.equals(softDeleteRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com"));

    final SoftDeleteRequestControl c =
         (SoftDeleteRequestControl)
         softDeleteRequest.getControl(
              SoftDeleteRequestControl.SOFT_DELETE_REQUEST_OID);
    assertNotNull(c);

    assertTrue(c.isCritical());

    assertFalse(c.hasValue());

    assertTrue(c.returnSoftDeleteResponse());
  }



  /**
   * Tests the behavior when attempting to decode a control with value that
   * cannot be parsed as a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedValue()
         throws Exception
  {
    new SoftDeleteRequestControl(new Control(
         SoftDeleteRequestControl.SOFT_DELETE_REQUEST_OID, true,
         new ASN1OctetString("this is not a valid value")));
  }



  /**
   * Tests the behavior when attempting to decode a control whose value has an
   * invalid sequence element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceBadElement()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Integer((byte) 0x82, -1),
         new ASN1OctetString((byte) 0x83, "unexpected type"));

    new SoftDeleteRequestControl(new Control(
         SoftDeleteRequestControl.SOFT_DELETE_REQUEST_OID, true,
         new ASN1OctetString(valueSequence.encode())));
  }
}
