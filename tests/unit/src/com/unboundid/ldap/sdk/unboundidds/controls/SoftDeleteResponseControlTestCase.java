/*
 * Copyright 2012-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2025 Ping Identity Corporation
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
 * Copyright (C) 2012-2025 Ping Identity Corporation
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



import java.util.UUID;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Base64;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a set of test cases for the soft delete response control.
 */
public final class SoftDeleteResponseControlTestCase
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
    SoftDeleteResponseControl c =
         new SoftDeleteResponseControl("uid=test,ou=People,dc=example,dc=com");

    final Control genericControl = Control.decode(c.getOID(), c.isCritical(),
         c.getValue());
    assertNotNull(genericControl);
    assertTrue(genericControl instanceof SoftDeleteResponseControl);
    c = (SoftDeleteResponseControl) genericControl;

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getSoftDeletedEntryDN());
    assertTrue(DN.equals(c.getSoftDeletedEntryDN(),
         "uid=test,ou=People,dc=example,dc=com"));

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the get method for a result that doesn't have any
   * controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithoutControl()
         throws Exception
  {
    final LDAPResult deleteResult = new LDAPResult(1, ResultCode.SUCCESS);
    assertNull(SoftDeleteResponseControl.get(deleteResult));
  }



  /**
   * Tests the behavior of the get method for a result that has a control that
   * is already decoded as a soft delete response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithValidSoftDeleteResponseControl()
         throws Exception
  {
    final Control[] controls =
    {
      new SoftDeleteResponseControl("uid=test,ou=People,dc=example,dc=com")
    };

    final LDAPResult deleteResult = new LDAPResult(1, ResultCode.SUCCESS, null,
         null, null, controls);
    assertNotNull(SoftDeleteResponseControl.get(deleteResult));
  }



  /**
   * Tests the behavior of the get method for a result that has a generic
   * control that is not yet decoded as a soft delete response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithValidGenericControl()
         throws Exception
  {
    final Control[] controls =
    {
      new Control(SoftDeleteResponseControl.SOFT_DELETE_RESPONSE_OID, false,
           new ASN1OctetString("uid=test,ou=People,dc=example,dc=com"))
    };

    final LDAPResult deleteResult = new LDAPResult(1, ResultCode.SUCCESS, null,
         null, null, controls);
    assertNotNull(SoftDeleteResponseControl.get(deleteResult));
  }



  /**
   * Tests the behavior of the get method for a result that has a generic
   * control that cannot be decoded as a soft delete response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetWithInvalidGenericControl()
         throws Exception
  {
    final Control[] controls =
    {
      new Control(SoftDeleteResponseControl.SOFT_DELETE_RESPONSE_OID, false,
           new ASN1OctetString("this is not a valid DN"))
    };

    final LDAPResult deleteResult = new LDAPResult(1, ResultCode.SUCCESS, null,
         null, null, controls);
    SoftDeleteResponseControl.get(deleteResult);
  }



  /**
   * Tests the behavior when attempting to decode a control without a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMissingValue()
         throws Exception
  {
    new SoftDeleteResponseControl().decodeControl(
         SoftDeleteResponseControl.SOFT_DELETE_RESPONSE_OID, false, null);
  }



  /**
   * Tests the behavior when attempting to decode a control in which the value
   * is not a valid DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotDN()
         throws Exception
  {
    new SoftDeleteResponseControl().decodeControl(
         SoftDeleteResponseControl.SOFT_DELETE_RESPONSE_OID, false,
         new ASN1OctetString("this is not a valid DN"));
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControl()
          throws Exception
  {
    final String uuidString = UUID.randomUUID().toString();
    final String softDeletedEntryDN =
         "entryUUID=" + uuidString + "+uid=jdoe,ou=People,dc=example,dc=com";
    final SoftDeleteResponseControl c =
         new SoftDeleteResponseControl(softDeletedEntryDN);

    final JSONObject controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.FALSE);

    assertFalse(controlObject.hasField("value-base64"));

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("soft-deleted-entry-dn", softDeletedEntryDN)));


    SoftDeleteResponseControl decodedControl =
         SoftDeleteResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getSoftDeletedEntryDN(), softDeletedEntryDN);


    decodedControl =
         (SoftDeleteResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getSoftDeletedEntryDN(), softDeletedEntryDN);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is base64-encoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueBase64()
          throws Exception
  {
    final String uuidString = UUID.randomUUID().toString();
    final String softDeletedEntryDN =
         "entryUUID=" + uuidString + "+uid=jdoe,ou=People,dc=example,dc=com";
    final SoftDeleteResponseControl c =
         new SoftDeleteResponseControl(softDeletedEntryDN);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    SoftDeleteResponseControl decodedControl =
         SoftDeleteResponseControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getSoftDeletedEntryDN(), softDeletedEntryDN);


    decodedControl =
         (SoftDeleteResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getSoftDeletedEntryDN(), softDeletedEntryDN);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is missing the soft-deleted entry DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueMissingSoftDeletedEntryDN()
          throws Exception
  {
    final String uuidString = UUID.randomUUID().toString();
    final String softDeletedEntryDN =
         "entryUUID=" + uuidString + "+uid=jdoe,ou=People,dc=example,dc=com";
    final SoftDeleteResponseControl c =
         new SoftDeleteResponseControl(softDeletedEntryDN);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", JSONObject.EMPTY_OBJECT));

    SoftDeleteResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value includes an unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueUnrecognizedFieldStrict()
          throws Exception
  {
    final String uuidString = UUID.randomUUID().toString();
    final String softDeletedEntryDN =
         "entryUUID=" + uuidString + "+uid=jdoe,ou=People,dc=example,dc=com";
    final SoftDeleteResponseControl c =
         new SoftDeleteResponseControl(softDeletedEntryDN);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("soft-deleted-entry-dn", softDeletedEntryDN),
              new JSONField("unrecognized", "foo"))));

    SoftDeleteResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value includes an unrecognized field in non-strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueUnrecognizedFieldNonStrict()
          throws Exception
  {
    final String uuidString = UUID.randomUUID().toString();
    final String softDeletedEntryDN =
         "entryUUID=" + uuidString + "+uid=jdoe,ou=People,dc=example,dc=com";
    final SoftDeleteResponseControl c =
         new SoftDeleteResponseControl(softDeletedEntryDN);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("soft-deleted-entry-dn", softDeletedEntryDN),
              new JSONField("unrecognized", "foo"))));


    SoftDeleteResponseControl decodedControl =
         SoftDeleteResponseControl.decodeJSONControl(controlObject, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getSoftDeletedEntryDN(), softDeletedEntryDN);


    decodedControl =
         (SoftDeleteResponseControl)
         Control.decodeJSONControl(controlObject, false, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getSoftDeletedEntryDN(), softDeletedEntryDN);
  }
}
