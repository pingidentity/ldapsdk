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



import java.util.ArrayList;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the undelete request control.
 */
public final class UndeleteRequestControlTestCase
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
    UndeleteRequestControl c = new UndeleteRequestControl();
    c = new UndeleteRequestControl(c);

    assertNull(c.getValue());

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the ability to create an undelete request with the default
   * settings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateUndeleteRequestDefault()
         throws Exception
  {
    final AddRequest undeleteRequest =
         UndeleteRequestControl.createUndeleteRequest(
              "uid=test.user,ou=People,dc=example,dc=com",
              "entryUUID=00000000-0000-0000-0000-000000000000,ou=People," +
                   "dc=example,dc=com");

    assertNotNull(undeleteRequest);

    assertTrue(DN.equals(undeleteRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com"));

    assertTrue(undeleteRequest.hasAttribute("ds-undelete-from-dn"));
    assertTrue(DN.equals(
         undeleteRequest.getAttribute("ds-undelete-from-dn").getValue(),
         "entryUUID=00000000-0000-0000-0000-000000000000,ou=People," +
                   "dc=example,dc=com"));

    assertFalse(undeleteRequest.hasAttribute("ds-undelete-changes"));

    assertFalse(undeleteRequest.hasAttribute("ds-undelete-old-password"));

    assertFalse(undeleteRequest.hasAttribute("ds-undelete-new-password"));

    assertFalse(undeleteRequest.hasAttribute(
         "ds-undelete-must-change-password"));

    assertFalse(undeleteRequest.hasAttribute("ds-undelete-disable-account"));

    final UndeleteRequestControl c =
         (UndeleteRequestControl)
         undeleteRequest.getControl(
              UndeleteRequestControl.UNDELETE_REQUEST_OID);
    assertNotNull(c);

    assertTrue(c.isCritical());

    assertFalse(c.hasValue());
  }



  /**
   * Tests the ability to create an undelete request with an extended set of
   * information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateUndeleteRequestExtended()
         throws Exception
  {
    final ArrayList<Modification> changes = new ArrayList<Modification>(2);
    changes.add(new Modification(ModificationType.REPLACE, "description",
         "new description"));
    changes.add(new Modification(ModificationType.ADD, "displayName",
         "new displayName"));

    final AddRequest undeleteRequest =
         UndeleteRequestControl.createUndeleteRequest(
              "uid=test.user,ou=People,dc=example,dc=com",
              "entryUUID=00000000-0000-0000-0000-000000000000,ou=People," +
                   "dc=example,dc=com",
              changes, "oldPW", "newPW", true, true);

    assertNotNull(undeleteRequest);

    assertTrue(DN.equals(undeleteRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com"));

    assertTrue(undeleteRequest.hasAttribute("ds-undelete-from-dn"));
    assertTrue(DN.equals(
         undeleteRequest.getAttribute("ds-undelete-from-dn").getValue(),
         "entryUUID=00000000-0000-0000-0000-000000000000,ou=People," +
                   "dc=example,dc=com"));

    assertTrue(undeleteRequest.hasAttribute("ds-undelete-changes"));

    assertTrue(undeleteRequest.hasAttribute("ds-undelete-old-password"));
    assertEquals(
         undeleteRequest.getAttribute("ds-undelete-old-password").getValue(),
         "oldPW");

    assertTrue(undeleteRequest.hasAttribute("ds-undelete-new-password"));
    assertEquals(
         undeleteRequest.getAttribute("ds-undelete-new-password").getValue(),
         "newPW");

    assertTrue(undeleteRequest.hasAttribute(
         "ds-undelete-must-change-password"));
    assertTrue(undeleteRequest.getAttribute(
         "ds-undelete-must-change-password").getValueAsBoolean());

    assertTrue(undeleteRequest.hasAttribute("ds-undelete-disable-account"));
    assertTrue(undeleteRequest.getAttribute("ds-undelete-disable-account").
         getValueAsBoolean());

    final UndeleteRequestControl c =
         (UndeleteRequestControl)
         undeleteRequest.getControl(
              UndeleteRequestControl.UNDELETE_REQUEST_OID);
    assertNotNull(c);

    assertTrue(c.isCritical());

    assertFalse(c.hasValue());
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
    new UndeleteRequestControl(new Control(
         UndeleteRequestControl.UNDELETE_REQUEST_OID, true,
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

    new UndeleteRequestControl(new Control(
         UndeleteRequestControl.UNDELETE_REQUEST_OID, true,
         new ASN1OctetString(valueSequence.encode())));
  }
}
