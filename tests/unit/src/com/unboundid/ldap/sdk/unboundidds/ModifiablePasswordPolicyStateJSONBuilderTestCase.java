/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import java.util.Date;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNull;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a set of test cases for the
 * {@code ModifiablePasswordPolicyStateJSONBuilder} class.
 */
public final class ModifiablePasswordPolicyStateJSONBuilderTestCase
       extends LDAPSDKTestCase
{
  /**
   * A {@code Date} object that is {@code null}.
   */
  private static final Date NULL_DATE = null;



  /**
   * A {@code Long} object that is {@code null}.
   */
  private static final Long NULL_LONG = null;



  /**
   * Tests the behavior for a password policy state builder created without
   * setting any fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyBuilder()
         throws Exception
  {
    ModifiablePasswordPolicyStateJSONBuilder builder =
         new ModifiablePasswordPolicyStateJSONBuilder();

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNull(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNull(builder.getAccountExpirationTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    final ModifyRequest modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         JSONObject.EMPTY_OBJECT);
  }



  /**
   * Tests the behavior for properties related to the password changed time.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordChangedTime()
         throws Exception
  {
    final Date now = new Date();
    ModifiablePasswordPolicyStateJSONBuilder builder =
         new ModifiablePasswordPolicyStateJSONBuilder().
              setPasswordChangedTime(now.getTime());

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNotNull(builder.getPasswordChangedTime());
    assertEquals(builder.getPasswordChangedTime().longValue(), now.getTime());

    assertNull(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNull(builder.getAccountExpirationTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    ModifyRequest modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         new JSONObject(new JSONField(
              "password-changed-time", StaticUtils.encodeRFC3339Time(now))));


    builder.setPasswordChangedTime(-1234L);

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNotNull(builder.getPasswordChangedTime());
    assertEquals(builder.getPasswordChangedTime().longValue(), -1L);

    assertNull(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNull(builder.getAccountExpirationTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         new JSONObject(new JSONField(
              "password-changed-time", JSONNull.NULL)));


    builder.setPasswordChangedTime(now);

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNotNull(builder.getPasswordChangedTime());
    assertEquals(builder.getPasswordChangedTime().longValue(), now.getTime());

    assertNull(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNull(builder.getAccountExpirationTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         new JSONObject(new JSONField(
              "password-changed-time", StaticUtils.encodeRFC3339Time(now))));


    builder.setPasswordChangedTime(NULL_DATE);

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNotNull(builder.getPasswordChangedTime());
    assertEquals(builder.getPasswordChangedTime().longValue(), -1L);

    assertNull(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNull(builder.getAccountExpirationTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         new JSONObject(new JSONField(
              "password-changed-time", JSONNull.NULL)));


    builder.setPasswordChangedTime(NULL_LONG);

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNull(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNull(builder.getAccountExpirationTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         JSONObject.EMPTY_OBJECT);


    builder.clearPasswordChangedTime();

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNotNull(builder.getPasswordChangedTime());
    assertEquals(builder.getPasswordChangedTime().longValue(), -1L);

    assertNull(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNull(builder.getAccountExpirationTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         new JSONObject(new JSONField(
              "password-changed-time", JSONNull.NULL)));
  }



  /**
   * Tests the behavior for properties related to the account is disabled flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAccountIsDisabled()
         throws Exception
  {
    ModifiablePasswordPolicyStateJSONBuilder builder =
         new ModifiablePasswordPolicyStateJSONBuilder().
              setAccountIsDisabled(true);

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNotNull(builder.getAccountIsDisabled());
    assertTrue(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNull(builder.getAccountExpirationTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    ModifyRequest modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         new JSONObject(new JSONField(
              "account-is-disabled", true)));


    builder.setAccountIsDisabled(false);

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNotNull(builder.getAccountIsDisabled());
    assertFalse(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNull(builder.getAccountExpirationTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         new JSONObject(new JSONField(
              "account-is-disabled", false)));


    builder.setAccountIsDisabled(null);

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNull(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNull(builder.getAccountExpirationTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         JSONObject.EMPTY_OBJECT);
  }



  /**
   * Tests the behavior for properties related to the account activation time.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAccountActivationTime()
         throws Exception
  {
    final Date now = new Date();
    ModifiablePasswordPolicyStateJSONBuilder builder =
         new ModifiablePasswordPolicyStateJSONBuilder().
              setAccountActivationTime(now.getTime());

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNull(builder.getAccountIsDisabled());

    assertNotNull(builder.getAccountActivationTime());
    assertEquals(builder.getAccountActivationTime().longValue(), now.getTime());

    assertNull(builder.getAccountExpirationTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    ModifyRequest modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         new JSONObject(new JSONField(
              "account-activation-time", StaticUtils.encodeRFC3339Time(now))));


    builder.setAccountActivationTime(-1234L);

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNull(builder.getAccountIsDisabled());

    assertNotNull(builder.getAccountActivationTime());
    assertEquals(builder.getAccountActivationTime().longValue(), -1L);

    assertNull(builder.getAccountExpirationTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         new JSONObject(new JSONField(
              "account-activation-time", JSONNull.NULL)));


    builder.setAccountActivationTime(now);

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNull(builder.getAccountIsDisabled());

    assertNotNull(builder.getAccountActivationTime());
    assertEquals(builder.getAccountActivationTime().longValue(), now.getTime());

    assertNull(builder.getAccountExpirationTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         new JSONObject(new JSONField(
              "account-activation-time", StaticUtils.encodeRFC3339Time(now))));


    builder.setAccountActivationTime(NULL_DATE);

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNull(builder.getAccountIsDisabled());

    assertNotNull(builder.getAccountActivationTime());
    assertEquals(builder.getAccountActivationTime().longValue(), -1L);

    assertNull(builder.getAccountExpirationTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         new JSONObject(new JSONField(
              "account-activation-time", JSONNull.NULL)));


    builder.setAccountActivationTime(NULL_LONG);

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNull(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNull(builder.getAccountExpirationTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         JSONObject.EMPTY_OBJECT);


    builder.clearAccountActivationTime();

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNull(builder.getAccountIsDisabled());

    assertNotNull(builder.getAccountActivationTime());
    assertEquals(builder.getAccountActivationTime().longValue(), -1L);

    assertNull(builder.getAccountExpirationTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         new JSONObject(new JSONField(
              "account-activation-time", JSONNull.NULL)));
  }



  /**
   * Tests the behavior for properties related to the account expiration time.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAccountExpirationTime()
         throws Exception
  {
    final Date now = new Date();
    ModifiablePasswordPolicyStateJSONBuilder builder =
         new ModifiablePasswordPolicyStateJSONBuilder().
              setAccountExpirationTime(now.getTime());

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNull(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNotNull(builder.getAccountExpirationTime());
    assertEquals(builder.getAccountExpirationTime().longValue(), now.getTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    ModifyRequest modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         new JSONObject(new JSONField(
              "account-expiration-time", StaticUtils.encodeRFC3339Time(now))));


    builder.setAccountExpirationTime(-1234L);

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNull(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNotNull(builder.getAccountExpirationTime());
    assertEquals(builder.getAccountExpirationTime().longValue(), -1L);

    assertNull(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         new JSONObject(new JSONField(
              "account-expiration-time", JSONNull.NULL)));


    builder.setAccountExpirationTime(now);

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNull(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNotNull(builder.getAccountExpirationTime());
    assertEquals(builder.getAccountExpirationTime().longValue(), now.getTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         new JSONObject(new JSONField(
              "account-expiration-time", StaticUtils.encodeRFC3339Time(now))));


    builder.setAccountExpirationTime(NULL_DATE);

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNull(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNotNull(builder.getAccountExpirationTime());
    assertEquals(builder.getAccountExpirationTime().longValue(), -1L);

    assertNull(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         new JSONObject(new JSONField(
              "account-expiration-time", JSONNull.NULL)));


    builder.setAccountExpirationTime(NULL_LONG);

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNull(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNull(builder.getAccountExpirationTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         JSONObject.EMPTY_OBJECT);


    builder.clearAccountExpirationTime();

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNull(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNotNull(builder.getAccountExpirationTime());
    assertEquals(builder.getAccountExpirationTime().longValue(), -1L);

    assertNull(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         new JSONObject(new JSONField(
              "account-expiration-time", JSONNull.NULL)));
  }



  /**
   * Tests the behavior for properties related to the account is failure-locked
   * flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAccountIsFailureLocked()
         throws Exception
  {
    ModifiablePasswordPolicyStateJSONBuilder builder =
         new ModifiablePasswordPolicyStateJSONBuilder().
              setAccountIsFailureLocked(true);

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNull(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNull(builder.getAccountExpirationTime());

    assertNotNull(builder.getAccountIsFailureLocked());
    assertTrue(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    ModifyRequest modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         new JSONObject(new JSONField(
              "account-is-failure-locked", true)));


    builder.setAccountIsFailureLocked(false);

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNull(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNull(builder.getAccountExpirationTime());

    assertNotNull(builder.getAccountIsFailureLocked());
    assertFalse(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         new JSONObject(new JSONField(
              "account-is-failure-locked", false)));


    builder.setAccountIsFailureLocked(null);

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNull(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNull(builder.getAccountExpirationTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         JSONObject.EMPTY_OBJECT);
  }



  /**
   * Tests the behavior for properties related to the password expiration warned
   * time.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordExpirationWarnedTime()
         throws Exception
  {
    final Date now = new Date();
    ModifiablePasswordPolicyStateJSONBuilder builder =
         new ModifiablePasswordPolicyStateJSONBuilder().
              setPasswordExpirationWarnedTime(now.getTime());

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNull(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNull(builder.getAccountExpirationTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNotNull(builder.getPasswordExpirationWarnedTime());
    assertEquals(builder.getPasswordExpirationWarnedTime().longValue(),
         now.getTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    ModifyRequest modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         new JSONObject(new JSONField(
              "password-expiration-warned-time",
              StaticUtils.encodeRFC3339Time(now))));


    builder.setPasswordExpirationWarnedTime(-1234L);

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNull(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNull(builder.getAccountExpirationTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNotNull(builder.getPasswordExpirationWarnedTime());
    assertEquals(builder.getPasswordExpirationWarnedTime().longValue(), -1L);

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         new JSONObject(new JSONField(
              "password-expiration-warned-time", JSONNull.NULL)));


    builder.setPasswordExpirationWarnedTime(now);

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNull(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNull(builder.getAccountExpirationTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNotNull(builder.getPasswordExpirationWarnedTime());
    assertEquals(builder.getPasswordExpirationWarnedTime().longValue(),
         now.getTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         new JSONObject(new JSONField(
              "password-expiration-warned-time",
              StaticUtils.encodeRFC3339Time(now))));


    builder.setPasswordExpirationWarnedTime(NULL_DATE);

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNull(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNull(builder.getAccountExpirationTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNotNull(builder.getPasswordExpirationWarnedTime());
    assertEquals(builder.getPasswordExpirationWarnedTime().longValue(), -1L);

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         new JSONObject(new JSONField(
              "password-expiration-warned-time", JSONNull.NULL)));


    builder.setPasswordExpirationWarnedTime(NULL_LONG);

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNull(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNull(builder.getAccountExpirationTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         JSONObject.EMPTY_OBJECT);


    builder.clearPasswordExpirationWarnedTime();

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNull(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNull(builder.getAccountExpirationTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNotNull(builder.getPasswordExpirationWarnedTime());
    assertEquals(builder.getPasswordExpirationWarnedTime().longValue(), -1L);

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         new JSONObject(new JSONField(
              "password-expiration-warned-time", JSONNull.NULL)));
  }



  /**
   * Tests the behavior for properties related to the must change password flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMustChangePassword()
         throws Exception
  {
    ModifiablePasswordPolicyStateJSONBuilder builder =
         new ModifiablePasswordPolicyStateJSONBuilder().
              setMustChangePassword(true);

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNull(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNull(builder.getAccountExpirationTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNotNull(builder.getMustChangePassword());
    assertTrue(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    ModifyRequest modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         new JSONObject(new JSONField(
              "must-change-password", true)));


    builder.setMustChangePassword(false);

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNull(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNull(builder.getAccountExpirationTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNotNull(builder.getMustChangePassword());
    assertFalse(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         new JSONObject(new JSONField(
              "must-change-password", false)));


    builder.setMustChangePassword(null);

    builder = new ModifiablePasswordPolicyStateJSONBuilder(builder.build());

    assertNull(builder.getPasswordChangedTime());

    assertNull(builder.getAccountIsDisabled());

    assertNull(builder.getAccountActivationTime());

    assertNull(builder.getAccountExpirationTime());

    assertNull(builder.getAccountIsFailureLocked());

    assertNull(builder.getPasswordExpirationWarnedTime());

    assertNull(builder.getMustChangePassword());

    assertNotNull(builder.toString());

    modifyRequest = builder.toModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(modifyRequest);
    assertDNsEqual(modifyRequest.getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(modifyRequest.getModifications().size(), 1);
    assertEquals(modifyRequest.getModifications().get(0).getModificationType(),
         ModificationType.REPLACE);
    assertEquals(modifyRequest.getModifications().get(0).getAttributeName(),
         "ds-pwp-modifiable-state-json");
    assertEquals(
         new JSONObject(modifyRequest.getModifications().get(0).
              getAttribute().getValue()),
         JSONObject.EMPTY_OBJECT);
  }
}
