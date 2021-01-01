/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.unboundidds.extensions.PasswordQualityRequirement;



/**
 * This class provides a set of test cases for the password quality requirement
 * class.
 */
public final class PasswordQualityRequirementValidationResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a result that indicates that the requirement was
   * satisfied.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequirementSatisfied()
         throws Exception
  {
    PasswordQualityRequirementValidationResult r =
         new PasswordQualityRequirementValidationResult(
              new PasswordQualityRequirement("this will be satisfied"), true,
              null);

    r = PasswordQualityRequirementValidationResult.decode(r.encode());
    assertNotNull(r);

    assertNotNull(r.getPasswordRequirement());
    assertEquals(r.getPasswordRequirement().getDescription(),
         "this will be satisfied");

    assertTrue(r.requirementSatisfied());

    assertNull(r.getAdditionalInfo());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior for a result that indicates that the requirement was not
   * satisfied.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequirementNotSatisfied()
         throws Exception
  {
    PasswordQualityRequirementValidationResult r =
         new PasswordQualityRequirementValidationResult(
              new PasswordQualityRequirement("this will not be satisfied"),
              false, "Not good enough");

    r = PasswordQualityRequirementValidationResult.decode(r.encode());
    assertNotNull(r);

    assertNotNull(r.getPasswordRequirement());
    assertEquals(r.getPasswordRequirement().getDescription(),
         "this will not be satisfied");

    assertFalse(r.requirementSatisfied());

    assertNotNull(r.getAdditionalInfo());
    assertEquals(r.getAdditionalInfo(), "Not good enough");

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to decode an ASN.1 element that is not a
   * sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeElementNotSequence()
         throws Exception
  {
    PasswordQualityRequirementValidationResult.decode(
         new ASN1OctetString("this is not a sequence"));
  }



  /**
   * Tests the behavior when trying to decode an ASN.1 element whose sequence
   * contains an unexpected element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeUnexpectedElementType()
         throws Exception
  {
    final ASN1Sequence s = new ASN1Sequence(
         new PasswordQualityRequirement("description").encode(),
         new ASN1Boolean(true),
         new ASN1OctetString((byte) 0x12, "unexpected element type"));

    PasswordQualityRequirementValidationResult.decode(s);
  }
}
