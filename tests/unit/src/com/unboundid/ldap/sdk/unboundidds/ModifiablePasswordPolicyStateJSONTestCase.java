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
import java.util.LinkedHashMap;
import java.util.Map;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONNull;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.
                   ModifiablePasswordPolicyStateJSONField.*;



/**
 * This class provides a set of test cases for the
 * {@code ModifiablePasswordPolicyStateJSON} class.
 */
public final class ModifiablePasswordPolicyStateJSONTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when trying to retrieve the modifiable password policy
   * state JSON object for a user that does not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetNoSuchUser()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    try (LDAPConnection connection = ds.getConnection())
    {
      try
      {
        ModifiablePasswordPolicyStateJSON.get(connection,
             "uid=missing,ou=People,dc=example,dc=com");
        fail("Expected an exception when trying to retrieve modifiable " +
             "password policy state information for a user that does not " +
             "exist.");
      }
      catch (final LDAPException e)
      {
        assertEquals(e.getResultCode(), ResultCode.NO_SUCH_OBJECT);
        assertNotNull(e.getMessage());
        assertFalse(e.getMessage().isEmpty());
      }
    }
  }



  /**
   * Tests the behavior when trying to retrieve the modifiable password policy
   * state JSON object for a user that exists but whose entry does not include
   * the ds-pwp-modifiable-state-json attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetNoSuchAttribute()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    try (LDAPConnection connection = ds.getConnection())
    {
      assertNull(ModifiablePasswordPolicyStateJSON.get(connection,
           "uid=test.user,ou=People,dc=example,dc=com"));
    }
  }



  /**
   * Tests the behavior when trying to retrieve the modifiable password policy
   * state JSON object for a user that exists and whose entry contains the
   * ds-pwp-modifiable-state-json attribute with a value that is not a valid
   * JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValueNotJSON()
         throws Exception
  {
    final Entry entry = new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "ds-pwp-modifiable-state-json: this-is-not-a-valid-json-object");


    try
    {
      ModifiablePasswordPolicyStateJSON.get(entry);
      fail("Expected an exception when trying to retrieve modifiable " +
           "password policy state information for a user with a malformed " +
           "value.");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
      assertNotNull(e.getMessage());
      assertFalse(e.getMessage().isEmpty());
    }
  }



  /**
   * Tests the behavior when trying to retrieve the modifiable password policy
   * state JSON object for a user that exists and whose entry contains the
   * ds-pwp-modifiable-state-json attribute with a value that is an empty JSON
   * object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValueEmptyJSONObject()
         throws Exception
  {
    final Entry entry = new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "ds-pwp-modifiable-state-json: {}");


    final ModifiablePasswordPolicyStateJSON state =
         ModifiablePasswordPolicyStateJSON.get(entry);
    assertNotNull(state);

    assertNull(state.getPasswordChangedTime());

    assertNull(state.getAccountIsDisabled());

    assertNull(state.getAccountActivationTime());

    assertNull(state.getAccountExpirationTime());

    assertNull(state.getAccountIsFailureLocked());

    assertNull(state.getPasswordExpirationWarnedTime());

    assertNull(state.getMustChangePassword());

    assertNotNull(state.toString());
    assertFalse(state.toString().isEmpty());
  }



  /**
   * Tests the behavior for the properties related to an account's password
   * changed time.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordChangedTime()
         throws Exception
  {
    final Date now = new Date();
    ModifiablePasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         PASSWORD_CHANGED_TIME, now));

    assertNotNull(state.getPasswordChangedTime());
    assertEquals(state.getPasswordChangedTime().longValue(), now.getTime());

    assertNull(state.getAccountIsDisabled());

    assertNull(state.getAccountActivationTime());

    assertNull(state.getAccountExpirationTime());

    assertNull(state.getAccountIsFailureLocked());

    assertNull(state.getPasswordExpirationWarnedTime());

    assertNull(state.getMustChangePassword());


    state = createState(StaticUtils.mapOf(
         PASSWORD_CHANGED_TIME, JSONNull.NULL));

    assertNotNull(state.getPasswordChangedTime());
    assertEquals(state.getPasswordChangedTime().longValue(), -1L);

    assertNull(state.getAccountIsDisabled());

    assertNull(state.getAccountActivationTime());

    assertNull(state.getAccountExpirationTime());

    assertNull(state.getAccountIsFailureLocked());

    assertNull(state.getPasswordExpirationWarnedTime());

    assertNull(state.getMustChangePassword());


    state = createState(StaticUtils.mapOf(
         PASSWORD_CHANGED_TIME, "malformed"));

    assertNull(state.getPasswordChangedTime());

    assertNull(state.getAccountIsDisabled());

    assertNull(state.getAccountActivationTime());

    assertNull(state.getAccountExpirationTime());

    assertNull(state.getAccountIsFailureLocked());

    assertNull(state.getPasswordExpirationWarnedTime());

    assertNull(state.getMustChangePassword());


    state = createState(StaticUtils.mapOf(
         PASSWORD_CHANGED_TIME, JSONBoolean.TRUE));

    assertNull(state.getPasswordChangedTime());

    assertNull(state.getAccountIsDisabled());

    assertNull(state.getAccountActivationTime());

    assertNull(state.getAccountExpirationTime());

    assertNull(state.getAccountIsFailureLocked());

    assertNull(state.getPasswordExpirationWarnedTime());

    assertNull(state.getMustChangePassword());
  }



  /**
   * Tests the behavior for the properties related to an account's
   * enabled/disabled state.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAccountIsDisabled()
         throws Exception
  {
    ModifiablePasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         ACCOUNT_IS_DISABLED, true));

    assertNull(state.getPasswordChangedTime());

    assertNotNull(state.getAccountIsDisabled());
    assertTrue(state.getAccountIsDisabled().booleanValue());

    assertNull(state.getAccountActivationTime());

    assertNull(state.getAccountExpirationTime());

    assertNull(state.getAccountIsFailureLocked());

    assertNull(state.getPasswordExpirationWarnedTime());

    assertNull(state.getMustChangePassword());


    state = createState(StaticUtils.mapOf(
         ACCOUNT_IS_DISABLED, false));

    assertNull(state.getPasswordChangedTime());

    assertNotNull(state.getAccountIsDisabled());
    assertFalse(state.getAccountIsDisabled().booleanValue());

    assertNull(state.getAccountActivationTime());

    assertNull(state.getAccountExpirationTime());

    assertNull(state.getAccountIsFailureLocked());

    assertNull(state.getPasswordExpirationWarnedTime());

    assertNull(state.getMustChangePassword());
  }



  /**
   * Tests the behavior for the properties related to an account's activation
   * time.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAccountActivationTime()
         throws Exception
  {
    final Date now = new Date();
    ModifiablePasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         ACCOUNT_ACTIVATION_TIME, now));

    assertNull(state.getPasswordChangedTime());

    assertNull(state.getAccountIsDisabled());

    assertNotNull(state.getAccountActivationTime());
    assertEquals(state.getAccountActivationTime().longValue(), now.getTime());

    assertNull(state.getAccountExpirationTime());

    assertNull(state.getAccountIsFailureLocked());

    assertNull(state.getPasswordExpirationWarnedTime());

    assertNull(state.getMustChangePassword());


    state = createState(StaticUtils.mapOf(
         ACCOUNT_ACTIVATION_TIME, JSONNull.NULL));

    assertNull(state.getPasswordChangedTime());

    assertNull(state.getAccountIsDisabled());

    assertNotNull(state.getAccountActivationTime());
    assertEquals(state.getAccountActivationTime().longValue(), -1L);

    assertNull(state.getAccountExpirationTime());

    assertNull(state.getAccountIsFailureLocked());

    assertNull(state.getPasswordExpirationWarnedTime());

    assertNull(state.getMustChangePassword());


    state = createState(StaticUtils.mapOf(
         ACCOUNT_ACTIVATION_TIME, "malformed"));

    assertNull(state.getPasswordChangedTime());

    assertNull(state.getAccountIsDisabled());

    assertNull(state.getAccountActivationTime());

    assertNull(state.getAccountExpirationTime());

    assertNull(state.getAccountIsFailureLocked());

    assertNull(state.getPasswordExpirationWarnedTime());

    assertNull(state.getMustChangePassword());


    state = createState(StaticUtils.mapOf(
         ACCOUNT_ACTIVATION_TIME, JSONBoolean.TRUE));

    assertNull(state.getPasswordChangedTime());

    assertNull(state.getAccountIsDisabled());

    assertNull(state.getAccountActivationTime());

    assertNull(state.getAccountExpirationTime());

    assertNull(state.getAccountIsFailureLocked());

    assertNull(state.getPasswordExpirationWarnedTime());

    assertNull(state.getMustChangePassword());
  }



  /**
   * Tests the behavior for the properties related to an account's expiration
   * time.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAccountExpirationTime()
         throws Exception
  {
    final Date now = new Date();
    ModifiablePasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         ACCOUNT_EXPIRATION_TIME, now));

    assertNull(state.getPasswordChangedTime());

    assertNull(state.getAccountIsDisabled());

    assertNull(state.getAccountActivationTime());

    assertNotNull(state.getAccountExpirationTime());
    assertEquals(state.getAccountExpirationTime().longValue(), now.getTime());

    assertNull(state.getAccountIsFailureLocked());

    assertNull(state.getPasswordExpirationWarnedTime());

    assertNull(state.getMustChangePassword());


    state = createState(StaticUtils.mapOf(
         ACCOUNT_EXPIRATION_TIME, JSONNull.NULL));

    assertNull(state.getPasswordChangedTime());

    assertNull(state.getAccountIsDisabled());

    assertNull(state.getAccountActivationTime());

    assertNotNull(state.getAccountExpirationTime());
    assertEquals(state.getAccountExpirationTime().longValue(), -1L);

    assertNull(state.getAccountIsFailureLocked());

    assertNull(state.getPasswordExpirationWarnedTime());

    assertNull(state.getMustChangePassword());


    state = createState(StaticUtils.mapOf(
         ACCOUNT_EXPIRATION_TIME, "malformed"));

    assertNull(state.getPasswordChangedTime());

    assertNull(state.getAccountIsDisabled());

    assertNull(state.getAccountActivationTime());

    assertNull(state.getAccountExpirationTime());

    assertNull(state.getAccountIsFailureLocked());

    assertNull(state.getPasswordExpirationWarnedTime());

    assertNull(state.getMustChangePassword());


    state = createState(StaticUtils.mapOf(
         ACCOUNT_EXPIRATION_TIME, JSONBoolean.TRUE));

    assertNull(state.getPasswordChangedTime());

    assertNull(state.getAccountIsDisabled());

    assertNull(state.getAccountActivationTime());

    assertNull(state.getAccountExpirationTime());

    assertNull(state.getAccountIsFailureLocked());

    assertNull(state.getPasswordExpirationWarnedTime());

    assertNull(state.getMustChangePassword());
  }



  /**
   * Tests the behavior for the properties related to an account's
   * failure-locked state.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAccountIsFailureLocked()
         throws Exception
  {
    ModifiablePasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         ACCOUNT_IS_FAILURE_LOCKED, true));

    assertNull(state.getPasswordChangedTime());

    assertNull(state.getAccountIsDisabled());

    assertNull(state.getAccountActivationTime());

    assertNull(state.getAccountExpirationTime());

    assertNotNull(state.getAccountIsFailureLocked());
    assertTrue(state.getAccountIsFailureLocked());

    assertNull(state.getPasswordExpirationWarnedTime());

    assertNull(state.getMustChangePassword());


    state = createState(StaticUtils.mapOf(
         ACCOUNT_IS_FAILURE_LOCKED, false));

    assertNull(state.getPasswordChangedTime());

    assertNull(state.getAccountIsDisabled());

    assertNull(state.getAccountActivationTime());

    assertNull(state.getAccountExpirationTime());

    assertNotNull(state.getAccountIsFailureLocked());
    assertFalse(state.getAccountIsFailureLocked());

    assertNull(state.getPasswordExpirationWarnedTime());

    assertNull(state.getMustChangePassword());
  }



  /**
   * Tests the behavior for the properties related to an account's password
   * expiration warned time.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordExpirationWarnedTime()
         throws Exception
  {
    final Date now = new Date();
    ModifiablePasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         PASSWORD_EXPIRATION_WARNED_TIME, now));

    assertNull(state.getPasswordChangedTime());

    assertNull(state.getAccountIsDisabled());

    assertNull(state.getAccountActivationTime());

    assertNull(state.getAccountExpirationTime());

    assertNull(state.getAccountIsFailureLocked());

    assertNotNull(state.getPasswordExpirationWarnedTime());
    assertEquals(state.getPasswordExpirationWarnedTime().longValue(),
         now.getTime());

    assertNull(state.getMustChangePassword());


    state = createState(StaticUtils.mapOf(
         PASSWORD_EXPIRATION_WARNED_TIME, JSONNull.NULL));

    assertNull(state.getPasswordChangedTime());

    assertNull(state.getAccountIsDisabled());

    assertNull(state.getAccountActivationTime());

    assertNull(state.getAccountExpirationTime());

    assertNull(state.getAccountIsFailureLocked());

    assertNotNull(state.getPasswordExpirationWarnedTime());
    assertEquals(state.getPasswordExpirationWarnedTime().longValue(), -1L);

    assertNull(state.getMustChangePassword());


    state = createState(StaticUtils.mapOf(
         PASSWORD_EXPIRATION_WARNED_TIME, "malformed"));

    assertNull(state.getPasswordChangedTime());

    assertNull(state.getAccountIsDisabled());

    assertNull(state.getAccountActivationTime());

    assertNull(state.getAccountExpirationTime());

    assertNull(state.getAccountIsFailureLocked());

    assertNull(state.getPasswordExpirationWarnedTime());

    assertNull(state.getMustChangePassword());


    state = createState(StaticUtils.mapOf(
         PASSWORD_EXPIRATION_WARNED_TIME, JSONBoolean.TRUE));

    assertNull(state.getPasswordChangedTime());

    assertNull(state.getAccountIsDisabled());

    assertNull(state.getAccountActivationTime());

    assertNull(state.getAccountExpirationTime());

    assertNull(state.getAccountIsFailureLocked());

    assertNull(state.getPasswordExpirationWarnedTime());

    assertNull(state.getMustChangePassword());
  }



  /**
   * Tests the behavior for the properties related to an account's must change
   * password state.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMustChangePassword()
         throws Exception
  {
    ModifiablePasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         MUST_CHANGE_PASSWORD, true));

    assertNull(state.getPasswordChangedTime());

    assertNull(state.getAccountIsDisabled());

    assertNull(state.getAccountActivationTime());

    assertNull(state.getAccountExpirationTime());

    assertNull(state.getAccountIsFailureLocked());

    assertNull(state.getPasswordExpirationWarnedTime());

    assertNotNull(state.getMustChangePassword());
    assertTrue(state.getMustChangePassword());


    state = createState(StaticUtils.mapOf(
         MUST_CHANGE_PASSWORD, false));

    assertNull(state.getPasswordChangedTime());

    assertNull(state.getAccountIsDisabled());

    assertNull(state.getAccountActivationTime());

    assertNull(state.getAccountExpirationTime());

    assertNull(state.getAccountIsFailureLocked());

    assertNull(state.getPasswordExpirationWarnedTime());

    assertNotNull(state.getMustChangePassword());
    assertFalse(state.getMustChangePassword());
  }



  /**
   * Creates a password policy state JSON object with the provided fields.
   *
   * @param  fields  The fields to include in the JSON object.
   *
   * @return  The password policy state JSON object that was created.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private ModifiablePasswordPolicyStateJSON createState(
               final Map<ModifiablePasswordPolicyStateJSONField,?> fields)
          throws Exception
  {
    final Map<String,JSONValue> jsonFields = new LinkedHashMap<>();
    for (final ModifiablePasswordPolicyStateJSONField field : fields.keySet())
    {
      final String name = field.getFieldName();
      final Object value = fields.get(field);
      if (value instanceof Boolean)
      {
        final Boolean b = (Boolean) value;
        jsonFields.put(name, new JSONBoolean(b));
      }
      else if (value instanceof String)
      {
        final String s = (String) value;
        jsonFields.put(name, new JSONString(s));
      }
      else if (value instanceof Date)
      {
        final Date d = (Date) value;
        jsonFields.put(name, new JSONString(StaticUtils.encodeRFC3339Time(d)));
      }
      else if ( value instanceof JSONValue)
      {
        jsonFields.put(name, (JSONValue) value);
      }
      else
      {
        fail("Unexpected field value " + value + " of type " +
             value.getClass().getName());
      }
    }

    final JSONObject o = new JSONObject(jsonFields);

    final Entry entry = new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User");
    entry.addAttribute("ds-pwp-modifiable-state-json", o.toSingleLineString());

    final ModifiablePasswordPolicyStateJSON state =
         ModifiablePasswordPolicyStateJSON.get(entry);
    assertNotNull(state);

    assertNotNull(state.getModifiablePasswordPolicyStateJSONObject());
    assertFalse(state.getModifiablePasswordPolicyStateJSONObject().
         getFields().isEmpty());
    assertEquals(
         state.getModifiablePasswordPolicyStateJSONObject().getFields().size(),
         jsonFields.size());

    assertNotNull(state.toString());
    assertFalse(state.toString().isEmpty());

    return state;
  }
}
