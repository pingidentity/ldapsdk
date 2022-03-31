/*
 * Copyright 2010-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2022 Ping Identity Corporation
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
 * Copyright (C) 2010-2022 Ping Identity Corporation
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
import java.util.Collections;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.Base64;
import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;



/**
 * This class provides a set of test cases for the
 * {@code ExcludeBranchRequestControl} class.
 */
public class ExcludeBranchRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the control with a single base DN when provided as an
   * array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleBaseDNArray()
         throws Exception
  {
    ExcludeBranchRequestControl c =
         new ExcludeBranchRequestControl("ou=People,dc=example,dc=com");
    c = new ExcludeBranchRequestControl(c);

    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(),"1.3.6.1.4.1.30221.2.5.17");

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getBaseDNs());
    assertFalse(c.getBaseDNs().isEmpty());
    assertEquals(c.getBaseDNs().size(), 1);
    assertEquals(new DN(c.getBaseDNs().get(0)),
         new DN("ou=People,dc=example,dc=com"));

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the control with multiple base DNs when provided as
   * an array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleBaseDNArray()
         throws Exception
  {
    ExcludeBranchRequestControl c = new ExcludeBranchRequestControl(
         "ou=East,dc=example,dc=com",
         "ou=West,dc=example,dc=com");
    c = new ExcludeBranchRequestControl(c);

    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(),"1.3.6.1.4.1.30221.2.5.17");

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getBaseDNs());
    assertFalse(c.getBaseDNs().isEmpty());
    assertEquals(c.getBaseDNs().size(), 2);
    assertEquals(new DN(c.getBaseDNs().get(0)),
         new DN("ou=East,dc=example,dc=com"));
    assertEquals(new DN(c.getBaseDNs().get(1)),
         new DN("ou=West,dc=example,dc=com"));

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the control with an empty set of base DNs when
   * provided as an array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testEmptyBaseDNArray()
         throws Exception
  {
    new ExcludeBranchRequestControl();
  }



  /**
   * Tests the behavior of the control with an empty set of base DNs when
   * provided as an array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNullBaseDNArray()
         throws Exception
  {
    new ExcludeBranchRequestControl((String[]) null);
  }



  /**
   * Tests the behavior of the control with a single base DN when provided as an
   * array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleBaseDNList()
         throws Exception
  {
    ExcludeBranchRequestControl c = new ExcludeBranchRequestControl(
         Arrays.asList("ou=People,dc=example,dc=com"));
    c = new ExcludeBranchRequestControl(c);

    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(),"1.3.6.1.4.1.30221.2.5.17");

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getBaseDNs());
    assertFalse(c.getBaseDNs().isEmpty());
    assertEquals(c.getBaseDNs().size(), 1);
    assertEquals(new DN(c.getBaseDNs().get(0)),
         new DN("ou=People,dc=example,dc=com"));

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the control with multiple base DNs when provided as
   * a list.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleBaseDNList()
         throws Exception
  {
    ExcludeBranchRequestControl c = new ExcludeBranchRequestControl(
         Arrays.asList("ou=East,dc=example,dc=com",
              "ou=West,dc=example,dc=com"));
    c = new ExcludeBranchRequestControl(c);

    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(),"1.3.6.1.4.1.30221.2.5.17");

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getBaseDNs());
    assertFalse(c.getBaseDNs().isEmpty());
    assertEquals(c.getBaseDNs().size(), 2);
    assertEquals(new DN(c.getBaseDNs().get(0)),
         new DN("ou=East,dc=example,dc=com"));
    assertEquals(new DN(c.getBaseDNs().get(1)),
         new DN("ou=West,dc=example,dc=com"));

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the control with an empty set of base DNs when
   * provided as an array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testEmptyBaseDNList()
         throws Exception
  {
    new ExcludeBranchRequestControl(Arrays.<String>asList());
  }



  /**
   * Tests the behavior of the control with an empty set of base DNs when
   * provided as an array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNullBaseDNList()
         throws Exception
  {
    new ExcludeBranchRequestControl((List<String>) null);
  }



  /**
   * Tests the behavior when trying to decode an exclude branch request control
   * with no value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeWithoutValue()
         throws Exception
  {
    new ExcludeBranchRequestControl(new Control("1.3.6.1.4.1.30221.2.5.17",
         true));
  }



  /**
   * Tests the behavior when trying to decode an exclude branch request control
   * with a value that is not a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new ExcludeBranchRequestControl(new Control("1.3.6.1.4.1.30221.2.5.17",
         true, new ASN1OctetString("foo")));
  }



  /**
   * Tests the behavior when trying to decode an exclude branch request control
   * with a value that is an empty sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueEmptySequence()
         throws Exception
  {
    new ExcludeBranchRequestControl(new Control("1.3.6.1.4.1.30221.2.5.17",
         true, new ASN1OctetString(new ASN1Sequence().encode())));
  }



  /**
   * Tests the behavior when trying to decode an exclude branch request control
   * with a value containing a base DNs element that is not a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueBaseDNElementNotSequence()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0xA0, "ou=People,dc=example,dc=com"));
    new ExcludeBranchRequestControl(new Control("1.3.6.1.4.1.30221.2.5.17",
         true, new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Tests the behavior when trying to decode an exclude branch request control
   * with a value that is an empty sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueEmptyBaseDNSet()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Sequence((byte) 0xA0));
    new ExcludeBranchRequestControl(new Control("1.3.6.1.4.1.30221.2.5.17",
         true, new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when only a single exclude branch is specified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlOneExcludeBranch()
          throws Exception
  {
    final ExcludeBranchRequestControl c =
         new ExcludeBranchRequestControl("ou=branch1,dc=example,dc=com");

    final JSONObject controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.TRUE);

    assertFalse(controlObject.hasField("value-base64"));

    final JSONObject valueObject = controlObject.getFieldAsObject("value-json");
    assertNotNull(valueObject);
    assertEquals(valueObject.getFields().size(), 1);

    final List<JSONValue> baseDNValues =
         valueObject.getFieldAsArray("base-dns");
    assertNotNull(baseDNValues);
    assertEquals(baseDNValues.size(), 1);
    assertTrue(baseDNValues.get(0) instanceof JSONString);
    assertEquals(((JSONString) baseDNValues.get(0)).stringValue(),
         "ou=branch1,dc=example,dc=com");


    ExcludeBranchRequestControl decodedControl =
         ExcludeBranchRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getBaseDNs(),
         Collections.singletonList("ou=branch1,dc=example,dc=com"));


    decodedControl =
         (ExcludeBranchRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getBaseDNs(),
         Collections.singletonList("ou=branch1,dc=example,dc=com"));
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when multiple exclude branches are specified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlMultipleExcludeBranches()
          throws Exception
  {
    final ExcludeBranchRequestControl c =
         new ExcludeBranchRequestControl(false, "ou=branch1,dc=example,dc=com",
              "ou=branch2,dc=example,dc=com", "ou=branch3,dc=example,dc=com");

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

    final JSONObject valueObject = controlObject.getFieldAsObject("value-json");
    assertNotNull(valueObject);
    assertEquals(valueObject.getFields().size(), 1);

    final List<JSONValue> baseDNValues =
         valueObject.getFieldAsArray("base-dns");
    assertNotNull(baseDNValues);
    assertEquals(baseDNValues.size(), 3);
    assertTrue(baseDNValues.get(0) instanceof JSONString);
    assertEquals(((JSONString) baseDNValues.get(0)).stringValue(),
         "ou=branch1,dc=example,dc=com");
    assertTrue(baseDNValues.get(1) instanceof JSONString);
    assertEquals(((JSONString) baseDNValues.get(1)).stringValue(),
         "ou=branch2,dc=example,dc=com");
    assertTrue(baseDNValues.get(2) instanceof JSONString);
    assertEquals(((JSONString) baseDNValues.get(2)).stringValue(),
         "ou=branch3,dc=example,dc=com");


    ExcludeBranchRequestControl decodedControl =
         ExcludeBranchRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getBaseDNs(),
         Arrays.asList("ou=branch1,dc=example,dc=com",
              "ou=branch2,dc=example,dc=com", "ou=branch3,dc=example,dc=com"));


    decodedControl =
         (ExcludeBranchRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getBaseDNs(),
         Arrays.asList("ou=branch1,dc=example,dc=com",
              "ou=branch2,dc=example,dc=com", "ou=branch3,dc=example,dc=com"));
  }



  /**
   * Tests the behavior when trying to decode a control from a JSON object when
   * the value is base64-encoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueBase64()
          throws Exception
  {
    final ExcludeBranchRequestControl c =
         new ExcludeBranchRequestControl("ou=branch1,dc=example,dc=com");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    ExcludeBranchRequestControl decodedControl =
         ExcludeBranchRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getBaseDNs(),
         Collections.singletonList("ou=branch1,dc=example,dc=com"));


    decodedControl =
         (ExcludeBranchRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getBaseDNs(),
         Collections.singletonList("ou=branch1,dc=example,dc=com"));
  }



  /**
   * Tests the behavior when trying to decode a control from a JSON object when
   * the value object is missing the base-dns field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueMissingBaseDNs()
          throws Exception
  {
    final ExcludeBranchRequestControl c =
         new ExcludeBranchRequestControl("ou=branch1,dc=example,dc=com");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", JSONObject.EMPTY_OBJECT));

    ExcludeBranchRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a control from a JSON object when
   * the value object has an empty set of base DNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueEmptyBaseDNs()
          throws Exception
  {
    final ExcludeBranchRequestControl c =
         new ExcludeBranchRequestControl("ou=branch1,dc=example,dc=com");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("base-dns", JSONArray.EMPTY_ARRAY))));

    ExcludeBranchRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a control from a JSON object when
   * the value object has a value that is not a string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueNonStringBaseDN()
          throws Exception
  {
    final ExcludeBranchRequestControl c =
         new ExcludeBranchRequestControl("ou=branch1,dc=example,dc=com");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("base-dns", new JSONArray(
                   new JSONNumber(12345))))));

    ExcludeBranchRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a control from a JSON object when
   * the value object has an unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueUnrecognizedFieldStrict()
          throws Exception
  {
    final ExcludeBranchRequestControl c =
         new ExcludeBranchRequestControl("ou=branch1,dc=example,dc=com");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("base-dns", new JSONArray(
                   new JSONString("ou=branch1,dc=example,dc=com"))),
              new JSONField("unrecognized", "foo"))));

    ExcludeBranchRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a control from a JSON object when
   * the value object has an unrecognized field in non-strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueUnrecognizedFieldNonStrict()
          throws Exception
  {
    final ExcludeBranchRequestControl c =
         new ExcludeBranchRequestControl("ou=branch1,dc=example,dc=com");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("base-dns", new JSONArray(
                   new JSONString("ou=branch1,dc=example,dc=com"))),
              new JSONField("unrecognized", "foo"))));


    ExcludeBranchRequestControl decodedControl =
         ExcludeBranchRequestControl.decodeJSONControl(controlObject, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getBaseDNs(),
         Collections.singletonList("ou=branch1,dc=example,dc=com"));


    decodedControl =
         (ExcludeBranchRequestControl)
         Control.decodeJSONControl(controlObject, false, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getBaseDNs(),
         Collections.singletonList("ou=branch1,dc=example,dc=com"));
  }
}
