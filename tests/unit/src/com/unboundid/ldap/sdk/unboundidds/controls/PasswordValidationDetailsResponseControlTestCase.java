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



import java.util.Arrays;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Null;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.unboundidds.extensions.PasswordQualityRequirement;



/**
 * This class provides a set of test cases for the password validation details
 * response control.
 */
public final class PasswordValidationDetailsResponseControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a control that provides information about the
   * results of validation processing when there were no requirements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidationDetailsResultWithoutRequirements()
         throws Exception
  {
    PasswordValidationDetailsResponseControl c =
         new PasswordValidationDetailsResponseControl(
              PasswordValidationDetailsResponseType.VALIDATION_DETAILS, null,
              false, false, null);

    final Control genericControl = Control.decode(c.getOID(), c.isCritical(),
         c.getValue());
    assertNotNull(genericControl);
    assertTrue(
         genericControl instanceof PasswordValidationDetailsResponseControl);

    c = (PasswordValidationDetailsResponseControl) genericControl;

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.41");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getResponseType());
    assertEquals(c.getResponseType(),
         PasswordValidationDetailsResponseType.VALIDATION_DETAILS);

    assertNotNull(c.getValidationResults());
    assertTrue(c.getValidationResults().isEmpty());

    assertFalse(c.missingCurrentPassword());

    assertFalse(c.mustChangePassword());

    assertNull(c.getSecondsUntilExpiration());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior for a control that provides information about the
   * results of validation processing when there were requirements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidationDetailsResultWithRequirements()
         throws Exception
  {
    final List<PasswordQualityRequirementValidationResult> validationResults =
         Arrays.asList(
              new PasswordQualityRequirementValidationResult(
                   new PasswordQualityRequirement("this was accepted"),
                   true, null),
              new PasswordQualityRequirementValidationResult(
                   new PasswordQualityRequirement("this was not accepted"),
                   false, "Not good enough"));

    PasswordValidationDetailsResponseControl c =
         new PasswordValidationDetailsResponseControl(
              PasswordValidationDetailsResponseType.VALIDATION_DETAILS,
              validationResults, true, true, 12345);

    final Control genericControl = Control.decode(c.getOID(), c.isCritical(),
         c.getValue());
    assertNotNull(genericControl);
    assertTrue(
         genericControl instanceof PasswordValidationDetailsResponseControl);

    c = (PasswordValidationDetailsResponseControl) genericControl;

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.41");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getResponseType());
    assertEquals(c.getResponseType(),
         PasswordValidationDetailsResponseType.VALIDATION_DETAILS);

    assertNotNull(c.getValidationResults());
    assertFalse(c.getValidationResults().isEmpty());
    assertEquals(c.getValidationResults().size(), 2);

    assertTrue(c.missingCurrentPassword());

    assertTrue(c.mustChangePassword());

    assertNotNull(c.getSecondsUntilExpiration());
    assertEquals(c.getSecondsUntilExpiration().intValue(), 12345);

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior for a control that indicates the request did not
   * include any password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoPasswordProvidedResult()
         throws Exception
  {
    PasswordValidationDetailsResponseControl c =
         new PasswordValidationDetailsResponseControl(
              PasswordValidationDetailsResponseType.NO_PASSWORD_PROVIDED,
              null, false, false, null);

    final Control genericControl = Control.decode(c.getOID(), c.isCritical(),
         c.getValue());
    assertNotNull(genericControl);
    assertTrue(
         genericControl instanceof PasswordValidationDetailsResponseControl);

    c = (PasswordValidationDetailsResponseControl) genericControl;

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.41");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getResponseType());
    assertEquals(c.getResponseType(),
         PasswordValidationDetailsResponseType.NO_PASSWORD_PROVIDED);

    assertNotNull(c.getValidationResults());
    assertTrue(c.getValidationResults().isEmpty());

    assertFalse(c.missingCurrentPassword());

    assertFalse(c.mustChangePassword());

    assertNull(c.getSecondsUntilExpiration());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior for a control that indicates the request had multiple
   * passwords.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultiplePasswordsProvidedResult()
         throws Exception
  {
    PasswordValidationDetailsResponseControl c =
         new PasswordValidationDetailsResponseControl(
              PasswordValidationDetailsResponseType.MULTIPLE_PASSWORDS_PROVIDED,
              null, false, false, null);

    final Control genericControl = Control.decode(c.getOID(), c.isCritical(),
         c.getValue());
    assertNotNull(genericControl);
    assertTrue(
         genericControl instanceof PasswordValidationDetailsResponseControl);

    c = (PasswordValidationDetailsResponseControl) genericControl;

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.41");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getResponseType());
    assertEquals(c.getResponseType(),
         PasswordValidationDetailsResponseType.MULTIPLE_PASSWORDS_PROVIDED);

    assertNotNull(c.getValidationResults());
    assertTrue(c.getValidationResults().isEmpty());

    assertFalse(c.missingCurrentPassword());

    assertFalse(c.mustChangePassword());

    assertNull(c.getSecondsUntilExpiration());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior for a control that indicates the server encountered a
   * problem that caused it to reject the operation before any validation could
   * be attempted.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoValidationAttemptedResult()
         throws Exception
  {
    PasswordValidationDetailsResponseControl c =
         new PasswordValidationDetailsResponseControl(
              PasswordValidationDetailsResponseType.NO_VALIDATION_ATTEMPTED,
              null, true, false, (60*60*24*180));

    final Control genericControl = Control.decode(c.getOID(), c.isCritical(),
         c.getValue());
    assertNotNull(genericControl);
    assertTrue(
         genericControl instanceof PasswordValidationDetailsResponseControl);

    c = (PasswordValidationDetailsResponseControl) genericControl;

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.41");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getResponseType());
    assertEquals(c.getResponseType(),
         PasswordValidationDetailsResponseType.NO_VALIDATION_ATTEMPTED);

    assertNotNull(c.getValidationResults());
    assertTrue(c.getValidationResults().isEmpty());

    assertTrue(c.missingCurrentPassword());

    assertFalse(c.mustChangePassword());

    assertNotNull(c.getSecondsUntilExpiration());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when trying to decode a control that does not have a
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlWithoutValue()
         throws Exception
  {
    new PasswordValidationDetailsResponseControl().decodeControl(
         "1.3.6.1.4.1.30221.2.5.41", false, null);
  }



  /**
   * Tests the behavior when trying to decode a control whose value is not
   * a valid ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueNotSequence()
         throws Exception
  {
    new PasswordValidationDetailsResponseControl().decodeControl(
         "1.3.6.1.4.1.30221.2.5.41", false,
         new ASN1OctetString("not a valid sequence"));
  }



  /**
   * Tests the behavior when trying to decode a control whose value contains an
   * invalid validation response type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlInvalidValidationResponseType()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Null((byte) 0x12));

    new PasswordValidationDetailsResponseControl().decodeControl(
         "1.3.6.1.4.1.30221.2.5.41", false,
         new ASN1OctetString(valueSequence.encode()));
  }



  /**
   * Tests the behavior of the get method for a result that does not have any
   * controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithoutControls()
         throws Exception
  {
    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS);
    assertNull(PasswordValidationDetailsResponseControl.get(r));

    assertNull(PasswordValidationDetailsResponseControl.get(
         new LDAPException(r)));
  }



  /**
   * Tests the behavior of the get method for a result that has controls, but
   * none of them is a password validation details response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithControlsOfDifferentTypes()
         throws Exception
  {
    final Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5")
    };

    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS, null, null,
         null, controls);
    assertNull(PasswordValidationDetailsResponseControl.get(r));

    assertNull(PasswordValidationDetailsResponseControl.get(
         new LDAPException(r)));
  }



  /**
   * Tests the behavior of the get method for a result that has a control that
   * is already an instance of a password validation details response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithPreDecodedControl()
         throws Exception
  {
    final PasswordValidationDetailsResponseControl c =
         new PasswordValidationDetailsResponseControl(
              PasswordValidationDetailsResponseType.NO_PASSWORD_PROVIDED, null,
              false, false, null);

    final Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5"),
      c
    };

    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS, null, null,
         null, controls);
    assertNotNull(PasswordValidationDetailsResponseControl.get(r));
    assertEquals(
         PasswordValidationDetailsResponseControl.get(r).getResponseType(),
         PasswordValidationDetailsResponseType.NO_PASSWORD_PROVIDED);

    assertNotNull(PasswordValidationDetailsResponseControl.get(
         new LDAPException(r)));
  }



  /**
   * Tests the behavior of the get method for a result that has a control that
   * is a valid password validation details response control but that has not
   * yet been decoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithValidNonDecodedControl()
         throws Exception
  {
    final PasswordValidationDetailsResponseControl c =
         new PasswordValidationDetailsResponseControl(
              PasswordValidationDetailsResponseType.NO_PASSWORD_PROVIDED, null,
              false, false, null);

    final Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5"),
      new Control(c.getOID(), c.isCritical(), c.getValue())
    };

    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS, null, null,
         null, controls);
    assertNotNull(PasswordValidationDetailsResponseControl.get(r));
    assertEquals(
         PasswordValidationDetailsResponseControl.get(r).getResponseType(),
         PasswordValidationDetailsResponseType.NO_PASSWORD_PROVIDED);

    assertNotNull(PasswordValidationDetailsResponseControl.get(
         new LDAPException(r)));
  }



  /**
   * Tests the behavior of the get method for a result that has a control with
   * the right OID but that isn't a valid password validation details response
   * control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetWithUndecodableControl()
         throws Exception
  {
    final Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5"),
      new Control("1.3.6.1.4.1.30221.2.5.41", false, null)
    };

    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS, null, null,
         null, controls);
    PasswordValidationDetailsResponseControl.get(r);
  }
}
