/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the password update behavior
 * request control.
 */
public final class PasswordUpdateBehaviorRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
\   * Tests the behavior for the case in which all of the properties have their
   * default null values.
   *
   * @throws Exception If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultProperties()
       throws Exception
  {
    final PasswordUpdateBehaviorRequestControlProperties properties =
         new PasswordUpdateBehaviorRequestControlProperties();

    PasswordUpdateBehaviorRequestControl control =
         new PasswordUpdateBehaviorRequestControl(properties, true);

    control = new PasswordUpdateBehaviorRequestControl(control);
    assertNotNull(control);

    assertNotNull(control.getOID());
    assertEquals(control.getOID(), "1.3.6.1.4.1.30221.2.5.51");

    assertTrue(control.isCritical());

    assertNotNull(control.getValue());

    assertNotNull(control.getControlName());

    assertNull(control.getIsSelfChange());

    assertNull(control.getAllowPreEncodedPassword());

    assertNull(control.getSkipPasswordValidation());

    assertNull(control.getIgnorePasswordHistory());

    assertNull(control.getIgnoreMinimumPasswordAge());

    assertNull(control.getPasswordStorageScheme());

    assertNull(control.getMustChangePassword());

    assertNotNull(control.toString());
  }



  /**
   * Tests the behavior for the case in which all of the properties are set with
   * non-default values, and in which the Boolean values are all true.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllTrueProperties()
         throws Exception
  {
    final PasswordUpdateBehaviorRequestControlProperties properties =
         new PasswordUpdateBehaviorRequestControlProperties();
    properties.setIsSelfChange(true);
    properties.setAllowPreEncodedPassword(true);
    properties.setSkipPasswordValidation(true);
    properties.setIgnorePasswordHistory(true);
    properties.setIgnoreMinimumPasswordAge(true);
    properties.setPasswordStorageScheme("true");
    properties.setMustChangePassword(true);

    PasswordUpdateBehaviorRequestControl control =
         new PasswordUpdateBehaviorRequestControl(properties, true);

    control = new PasswordUpdateBehaviorRequestControl(control);
    assertNotNull(control);

    assertNotNull(control.getOID());
    assertEquals(control.getOID(), "1.3.6.1.4.1.30221.2.5.51");

    assertTrue(control.isCritical());

    assertNotNull(control.getValue());

    assertNotNull(control.getControlName());

    assertNotNull(control.getIsSelfChange());
    assertEquals(control.getIsSelfChange(), Boolean.TRUE);

    assertNotNull(control.getAllowPreEncodedPassword());
    assertEquals(control.getAllowPreEncodedPassword(), Boolean.TRUE);

    assertNotNull(control.getSkipPasswordValidation());
    assertEquals(control.getSkipPasswordValidation(), Boolean.TRUE);

    assertNotNull(control.getIgnorePasswordHistory());
    assertEquals(control.getIgnorePasswordHistory(), Boolean.TRUE);

    assertNotNull(control.getIgnoreMinimumPasswordAge());
    assertEquals(control.getIgnoreMinimumPasswordAge(), Boolean.TRUE);

    assertNotNull(control.getPasswordStorageScheme());
    assertEquals(control.getPasswordStorageScheme(), "true");

    assertNotNull(control.getMustChangePassword());
    assertEquals(control.getMustChangePassword(), Boolean.TRUE);

    assertNotNull(control.toString());
  }



  /**
   * Tests the behavior for the case in which all of the properties are set with
   * non-default values, and in which the Boolean values are all false.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllFalseProperties()
         throws Exception
  {
    final PasswordUpdateBehaviorRequestControlProperties properties =
         new PasswordUpdateBehaviorRequestControlProperties();
    properties.setIsSelfChange(false);
    properties.setAllowPreEncodedPassword(false);
    properties.setSkipPasswordValidation(false);
    properties.setIgnorePasswordHistory(false);
    properties.setIgnoreMinimumPasswordAge(false);
    properties.setPasswordStorageScheme("false");
    properties.setMustChangePassword(false);

    PasswordUpdateBehaviorRequestControl control =
         new PasswordUpdateBehaviorRequestControl(properties, false);

    control = new PasswordUpdateBehaviorRequestControl(control);
    assertNotNull(control);

    assertNotNull(control.getOID());
    assertEquals(control.getOID(), "1.3.6.1.4.1.30221.2.5.51");

    assertFalse(control.isCritical());

    assertNotNull(control.getValue());

    assertNotNull(control.getControlName());

    assertNotNull(control.getIsSelfChange());
    assertEquals(control.getIsSelfChange(), Boolean.FALSE);

    assertNotNull(control.getAllowPreEncodedPassword());
    assertEquals(control.getAllowPreEncodedPassword(), Boolean.FALSE);

    assertNotNull(control.getSkipPasswordValidation());
    assertEquals(control.getSkipPasswordValidation(), Boolean.FALSE);

    assertNotNull(control.getIgnorePasswordHistory());
    assertEquals(control.getIgnorePasswordHistory(), Boolean.FALSE);

    assertNotNull(control.getIgnoreMinimumPasswordAge());
    assertEquals(control.getIgnoreMinimumPasswordAge(), Boolean.FALSE);

    assertNotNull(control.getPasswordStorageScheme());
    assertEquals(control.getPasswordStorageScheme(), "false");

    assertNotNull(control.getMustChangePassword());
    assertEquals(control.getMustChangePassword(), Boolean.FALSE);

    assertNotNull(control.toString());
  }



  /**
   * Tests the behavior for the case in which only the isSelfChange property is
   * set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIsSelfChange()
         throws Exception
  {
    final PasswordUpdateBehaviorRequestControlProperties properties =
         new PasswordUpdateBehaviorRequestControlProperties();
    properties.setIsSelfChange(true);

    PasswordUpdateBehaviorRequestControl control =
         new PasswordUpdateBehaviorRequestControl(properties, false);

    control = new PasswordUpdateBehaviorRequestControl(control);
    assertNotNull(control);

    assertNotNull(control.getOID());
    assertEquals(control.getOID(), "1.3.6.1.4.1.30221.2.5.51");

    assertFalse(control.isCritical());

    assertNotNull(control.getValue());

    assertNotNull(control.getControlName());

    assertNotNull(control.getIsSelfChange());
    assertEquals(control.getIsSelfChange(), Boolean.TRUE);

    assertNull(control.getAllowPreEncodedPassword());

    assertNull(control.getSkipPasswordValidation());

    assertNull(control.getIgnorePasswordHistory());

    assertNull(control.getIgnoreMinimumPasswordAge());

    assertNull(control.getPasswordStorageScheme());

    assertNull(control.getMustChangePassword());

    assertNotNull(control.toString());
  }



  /**
   * Tests the behavior for the case in which only the allowPreEncodedPassword
   * property is set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllowPreEncodedPassword()
         throws Exception
  {
    final PasswordUpdateBehaviorRequestControlProperties properties =
         new PasswordUpdateBehaviorRequestControlProperties();
    properties.setAllowPreEncodedPassword(true);

    PasswordUpdateBehaviorRequestControl control =
         new PasswordUpdateBehaviorRequestControl(properties, false);

    control = new PasswordUpdateBehaviorRequestControl(control);
    assertNotNull(control);

    assertNotNull(control.getOID());
    assertEquals(control.getOID(), "1.3.6.1.4.1.30221.2.5.51");

    assertFalse(control.isCritical());

    assertNotNull(control.getValue());

    assertNotNull(control.getControlName());

    assertNull(control.getIsSelfChange());

    assertNotNull(control.getAllowPreEncodedPassword());
    assertEquals(control.getAllowPreEncodedPassword(), Boolean.TRUE);

    assertNull(control.getSkipPasswordValidation());

    assertNull(control.getIgnorePasswordHistory());

    assertNull(control.getIgnoreMinimumPasswordAge());

    assertNull(control.getPasswordStorageScheme());

    assertNull(control.getMustChangePassword());

    assertNotNull(control.toString());
  }



  /**
   * Tests the behavior for the case in which only the skipPasswordValidation
   * property is set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSkipPasswordValidation()
         throws Exception
  {
    final PasswordUpdateBehaviorRequestControlProperties properties =
         new PasswordUpdateBehaviorRequestControlProperties();
    properties.setSkipPasswordValidation(true);

    PasswordUpdateBehaviorRequestControl control =
         new PasswordUpdateBehaviorRequestControl(properties, false);

    control = new PasswordUpdateBehaviorRequestControl(control);
    assertNotNull(control);

    assertNotNull(control.getOID());
    assertEquals(control.getOID(), "1.3.6.1.4.1.30221.2.5.51");

    assertFalse(control.isCritical());

    assertNotNull(control.getValue());

    assertNotNull(control.getControlName());

    assertNull(control.getIsSelfChange());

    assertNull(control.getAllowPreEncodedPassword());

    assertNotNull(control.getSkipPasswordValidation());
    assertEquals(control.getSkipPasswordValidation(), Boolean.TRUE);

    assertNull(control.getIgnorePasswordHistory());

    assertNull(control.getIgnoreMinimumPasswordAge());

    assertNull(control.getPasswordStorageScheme());

    assertNull(control.getMustChangePassword());

    assertNotNull(control.toString());
  }



  /**
   * Tests the behavior for the case in which only the ignorePasswordHistory
   * property is set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIgnorePasswordHistory()
         throws Exception
  {
    final PasswordUpdateBehaviorRequestControlProperties properties =
         new PasswordUpdateBehaviorRequestControlProperties();
    properties.setIgnorePasswordHistory(true);

    PasswordUpdateBehaviorRequestControl control =
         new PasswordUpdateBehaviorRequestControl(properties, false);

    control = new PasswordUpdateBehaviorRequestControl(control);
    assertNotNull(control);

    assertNotNull(control.getOID());
    assertEquals(control.getOID(), "1.3.6.1.4.1.30221.2.5.51");

    assertFalse(control.isCritical());

    assertNotNull(control.getValue());

    assertNotNull(control.getControlName());

    assertNull(control.getIsSelfChange());

    assertNull(control.getAllowPreEncodedPassword());

    assertNull(control.getSkipPasswordValidation());

    assertNotNull(control.getIgnorePasswordHistory());
    assertEquals(control.getIgnorePasswordHistory(), Boolean.TRUE);

    assertNull(control.getIgnoreMinimumPasswordAge());

    assertNull(control.getPasswordStorageScheme());

    assertNull(control.getMustChangePassword());

    assertNotNull(control.toString());
  }



  /**
   * Tests the behavior for the case in which only the ignoreMinimumPasswordAge
   * property is set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIgnoreMinimumPasswordAge()
         throws Exception
  {
    final PasswordUpdateBehaviorRequestControlProperties properties =
         new PasswordUpdateBehaviorRequestControlProperties();
    properties.setIgnoreMinimumPasswordAge(true);

    PasswordUpdateBehaviorRequestControl control =
         new PasswordUpdateBehaviorRequestControl(properties, false);

    control = new PasswordUpdateBehaviorRequestControl(control);
    assertNotNull(control);

    assertNotNull(control.getOID());
    assertEquals(control.getOID(), "1.3.6.1.4.1.30221.2.5.51");

    assertFalse(control.isCritical());

    assertNotNull(control.getValue());

    assertNotNull(control.getControlName());

    assertNull(control.getIsSelfChange());

    assertNull(control.getAllowPreEncodedPassword());

    assertNull(control.getSkipPasswordValidation());

    assertNull(control.getIgnorePasswordHistory());

    assertNotNull(control.getIgnoreMinimumPasswordAge());
    assertEquals(control.getIgnoreMinimumPasswordAge(), Boolean.TRUE);

    assertNull(control.getPasswordStorageScheme());

    assertNull(control.getMustChangePassword());

    assertNotNull(control.toString());
  }



  /**
   * Tests the behavior for the case in which only the passwordStorageScheme
   * property is set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordStorageScheme()
         throws Exception
  {
    final PasswordUpdateBehaviorRequestControlProperties properties =
         new PasswordUpdateBehaviorRequestControlProperties();
    properties.setPasswordStorageScheme("PBKDF2");

    PasswordUpdateBehaviorRequestControl control =
         new PasswordUpdateBehaviorRequestControl(properties, false);

    control = new PasswordUpdateBehaviorRequestControl(control);
    assertNotNull(control);

    assertNotNull(control.getOID());
    assertEquals(control.getOID(), "1.3.6.1.4.1.30221.2.5.51");

    assertFalse(control.isCritical());

    assertNotNull(control.getValue());

    assertNotNull(control.getControlName());

    assertNull(control.getIsSelfChange());

    assertNull(control.getAllowPreEncodedPassword());

    assertNull(control.getSkipPasswordValidation());

    assertNull(control.getIgnorePasswordHistory());

    assertNull(control.getIgnoreMinimumPasswordAge());

    assertNotNull(control.getPasswordStorageScheme());
    assertEquals(control.getPasswordStorageScheme(), "PBKDF2");

    assertNull(control.getMustChangePassword());

    assertNotNull(control.toString());
  }



  /**
   * Tests the behavior for the case in which only the mustChangePassword
   * property is set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMustChangePassword()
         throws Exception
  {
    final PasswordUpdateBehaviorRequestControlProperties properties =
         new PasswordUpdateBehaviorRequestControlProperties();
    properties.setMustChangePassword(true);

    PasswordUpdateBehaviorRequestControl control =
         new PasswordUpdateBehaviorRequestControl(properties, false);

    control = new PasswordUpdateBehaviorRequestControl(control);
    assertNotNull(control);

    assertNotNull(control.getOID());
    assertEquals(control.getOID(), "1.3.6.1.4.1.30221.2.5.51");

    assertFalse(control.isCritical());

    assertNotNull(control.getValue());

    assertNotNull(control.getControlName());

    assertNull(control.getIsSelfChange());

    assertNull(control.getAllowPreEncodedPassword());

    assertNull(control.getSkipPasswordValidation());

    assertNull(control.getIgnorePasswordHistory());

    assertNull(control.getIgnoreMinimumPasswordAge());

    assertNull(control.getPasswordStorageScheme());

    assertNotNull(control.getMustChangePassword());
    assertEquals(control.getMustChangePassword(), Boolean.TRUE);

    assertNotNull(control.toString());
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
    new PasswordUpdateBehaviorRequestControl(new Control(
         "1.3.6.1.4.1.30221.2.5.51", true, null));
  }



  /**
   * Tests the behavior when trying to decode a control whose value is not an
   * ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new PasswordUpdateBehaviorRequestControl(new Control(
         "1.3.6.1.4.1.30221.2.5.51", true,
         new ASN1OctetString("not a sequence")));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence
   * contains an element with an unrecognized BER type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueContainsUnrecognizedElement()
         throws Exception
  {
    new PasswordUpdateBehaviorRequestControl(new Control(
         "1.3.6.1.4.1.30221.2.5.51", true,
         new ASN1OctetString(new ASN1Sequence(new ASN1OctetString((byte) 0x00,
              "unrecognized type")).encode())));
  }
}
