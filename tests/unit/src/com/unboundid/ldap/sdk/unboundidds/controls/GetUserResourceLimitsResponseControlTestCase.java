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



import java.util.Arrays;
import java.util.Collections;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Base64;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;



/**
 * This class provides a set of test cases for the get user resource limits
 * response control.
 */
public final class GetUserResourceLimitsResponseControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a response control with values for all elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllValues()
         throws Exception
  {
    GetUserResourceLimitsResponseControl c =
         new GetUserResourceLimitsResponseControl(1L, 2L, 3L, 4L,
              "cn=Equivalent Authz User,ou=People,dc=example,dc=com",
              "Test Client Connection Policy",
              Arrays.asList("cn=Group 1,ou=Groups,dc=example,dc=com",
                   "cn=Group 2,ou=Groups,dc=example,dc=com"),
              Arrays.asList("password-reset", "config-read"),
              Arrays.asList(new Attribute("foo", "a"),
                   new Attribute("bar", "b")));

    c = new GetUserResourceLimitsResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());
    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.26");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getSizeLimit());
    assertEquals(c.getSizeLimit(), Long.valueOf(1L));

    assertNotNull(c.getTimeLimitSeconds());
    assertEquals(c.getTimeLimitSeconds(), Long.valueOf(2L));

    assertNotNull(c.getIdleTimeLimitSeconds());
    assertEquals(c.getIdleTimeLimitSeconds(), Long.valueOf(3L));

    assertNotNull(c.getLookthroughLimit());
    assertEquals(c.getLookthroughLimit(), Long.valueOf(4L));

    assertNotNull(c.getEquivalentAuthzUserDN());
    assertEquals(new DN(c.getEquivalentAuthzUserDN()),
         new DN("cn=Equivalent Authz User,ou=People,dc=example,dc=com"));

    assertNotNull(c.getClientConnectionPolicyName());
    assertEquals(c.getClientConnectionPolicyName(),
         "Test Client Connection Policy");

    assertNotNull(c.getGroupDNs());
    assertEquals(c.getGroupDNs(), Arrays.asList(
         "cn=Group 1,ou=Groups,dc=example,dc=com",
         "cn=Group 2,ou=Groups,dc=example,dc=com"));

    assertNotNull(c.getPrivilegeNames());
    assertEquals(c.getPrivilegeNames(),
         Arrays.asList("password-reset", "config-read"));

    assertNotNull(c.getOtherAttributes());
    assertEquals(c.getOtherAttributes(), Arrays.asList(
         new Attribute("foo", "a"),
         new Attribute("bar", "b")));

    assertNotNull(c.getOtherAttribute("foo"));
    assertEquals(c.getOtherAttribute("foo"), new Attribute("foo", "a"));

    assertNotNull(c.getOtherAttribute("FoO"));
    assertEquals(c.getOtherAttribute("FoO"), new Attribute("foo", "a"));

    assertNotNull(c.getOtherAttribute("bar"));
    assertEquals(c.getOtherAttribute("bar"), new Attribute("bar", "b"));

    assertNotNull(c.getOtherAttribute("Bar"));
    assertEquals(c.getOtherAttribute("baR"), new Attribute("bar", "b"));

    assertNull(c.getOtherAttribute("baz"));

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests a response control with alternate values for all elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAlternateValues()
         throws Exception
  {
    GetUserResourceLimitsResponseControl c =
         new GetUserResourceLimitsResponseControl(0L, -1L, -2L, -3L, "",
              "A Different Client Connection Policy",
              Collections.<String>emptyList(), Collections.<String>emptyList(),
              Collections.<Attribute>emptyList());

    c = new GetUserResourceLimitsResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());
    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.26");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getSizeLimit());
    assertEquals(c.getSizeLimit(), Long.valueOf(-1L));

    assertNotNull(c.getTimeLimitSeconds());
    assertEquals(c.getTimeLimitSeconds(), Long.valueOf(-1L));

    assertNotNull(c.getIdleTimeLimitSeconds());
    assertEquals(c.getIdleTimeLimitSeconds(), Long.valueOf(-1L));

    assertNotNull(c.getLookthroughLimit());
    assertEquals(c.getLookthroughLimit(), Long.valueOf(-1L));

    assertNotNull(c.getEquivalentAuthzUserDN());
    assertEquals(new DN(c.getEquivalentAuthzUserDN()), DN.NULL_DN);

    assertNotNull(c.getClientConnectionPolicyName());
    assertEquals(c.getClientConnectionPolicyName(),
         "A Different Client Connection Policy");

    assertNotNull(c.getGroupDNs());
    assertTrue(c.getGroupDNs().isEmpty());

    assertNotNull(c.getPrivilegeNames());
    assertTrue(c.getPrivilegeNames().isEmpty());

    assertNotNull(c.getOtherAttributes());
    assertTrue(c.getOtherAttributes().isEmpty());

    assertNull(c.getOtherAttribute("foo"));

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests a response control with no values for any elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoValues()
         throws Exception
  {
    GetUserResourceLimitsResponseControl c =
         new GetUserResourceLimitsResponseControl(null, null, null, null, null,
              null);

    c = new GetUserResourceLimitsResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());
    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.26");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNull(c.getSizeLimit());

    assertNull(c.getTimeLimitSeconds());

    assertNull(c.getIdleTimeLimitSeconds());

    assertNull(c.getLookthroughLimit());

    assertNull(c.getEquivalentAuthzUserDN());

    assertNull(c.getClientConnectionPolicyName());

    assertNull(c.getGroupDNs());

    assertNull(c.getPrivilegeNames());

    assertNotNull(c.getControlName());

    assertNotNull(c.getOtherAttributes());
    assertTrue(c.getOtherAttributes().isEmpty());

    assertNull(c.getOtherAttribute("foo"));

    assertNotNull(c.toString());
  }



  /**
   * Tests the get method on a bind result that doesn't include any controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithoutControls()
         throws Exception
  {
    final BindResult bindResult = new BindResult(1, ResultCode.SUCCESS, null,
         null, null, null);

    assertNull(GetUserResourceLimitsResponseControl.get(bindResult));
  }



  /**
   * Tests the get method on a bind result that has controls, but not a get user
   * resource limits response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithoutGetUserResourceLimitsControl()
         throws Exception
  {
    final Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", false, new ASN1OctetString("foo")),
    };

    final BindResult bindResult = new BindResult(1, ResultCode.SUCCESS, null,
         null, null, controls);

    assertNull(GetUserResourceLimitsResponseControl.get(bindResult));
  }



  /**
   * Tests the get method on a bind result that includes a get user resource
   * limits response control already cast to the appropriate type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithTypedGetUserResourceLimitsControl()
         throws Exception
  {
    final Control[] controls =
    {
      new GetUserResourceLimitsResponseControl(null, null, null, null, null,
           null)
    };

    final BindResult bindResult = new BindResult(1, ResultCode.SUCCESS, null,
         null, null, controls);

    final GetUserResourceLimitsResponseControl c =
         GetUserResourceLimitsResponseControl.get(bindResult);
    assertNotNull(c);
  }



  /**
   * Tests the get method on a bind result that includes a get user resource
   * limits response control as a generic control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithGenericGetUserResourceLimitsControl()
         throws Exception
  {
    final GetUserResourceLimitsResponseControl rc =
         new GetUserResourceLimitsResponseControl(null, null, null, null, null,
              null);

    final Control[] controls =
    {
      new Control(rc.getOID(), rc.isCritical(), rc.getValue())
    };

    final BindResult bindResult = new BindResult(1, ResultCode.SUCCESS, null,
         null, null, controls);

    final GetUserResourceLimitsResponseControl c =
         GetUserResourceLimitsResponseControl.get(bindResult);
    assertNotNull(c);
  }



  /**
   * Tests the get method on a bind result that includes a control with the
   * expected OID but no value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetWithControlMissingValue()
         throws Exception
  {
    final Control[] controls =
    {
      new Control("1.3.6.1.4.1.30221.2.5.26")
    };

    final BindResult bindResult = new BindResult(1, ResultCode.SUCCESS, null,
         null, null, controls);

    GetUserResourceLimitsResponseControl.get(bindResult);
  }



  /**
   * Tests the get method on a bind result that includes a control with the
   * expected OID and a value that can't be parsed as a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetWithControlMalformedValue()
         throws Exception
  {
    final Control[] controls =
    {
      new Control("1.3.6.1.4.1.30221.2.5.26", false, new ASN1OctetString("foo"))
    };

    final BindResult bindResult = new BindResult(1, ResultCode.SUCCESS, null,
         null, null, controls);

    GetUserResourceLimitsResponseControl.get(bindResult);
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when no values are specified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlNoElements()
          throws Exception
  {
    final GetUserResourceLimitsResponseControl c =
         new GetUserResourceLimitsResponseControl(null, null, null, null, null,
              null,null, null, null);

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
         JSONObject.EMPTY_OBJECT);


    GetUserResourceLimitsResponseControl decodedControl =
         GetUserResourceLimitsResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertNull(decodedControl.getSizeLimit());

    assertNull(decodedControl.getTimeLimitSeconds());

    assertNull(decodedControl.getIdleTimeLimitSeconds());

    assertNull(decodedControl.getLookthroughLimit());

    assertNull(decodedControl.getEquivalentAuthzUserDN());

    assertNull(decodedControl.getClientConnectionPolicyName());

    assertNull(decodedControl.getGroupDNs());

    assertNull(decodedControl.getPrivilegeNames());

    assertEquals(decodedControl.getOtherAttributes(), Collections.emptyList());


    decodedControl =
         (GetUserResourceLimitsResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertNull(decodedControl.getSizeLimit());

    assertNull(decodedControl.getTimeLimitSeconds());

    assertNull(decodedControl.getIdleTimeLimitSeconds());

    assertNull(decodedControl.getLookthroughLimit());

    assertNull(decodedControl.getEquivalentAuthzUserDN());

    assertNull(decodedControl.getClientConnectionPolicyName());

    assertNull(decodedControl.getGroupDNs());

    assertNull(decodedControl.getPrivilegeNames());

    assertEquals(decodedControl.getOtherAttributes(), Collections.emptyList());
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when all values are specified, but arrays are empty.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlAllElementsEmptyArrays()
          throws Exception
  {
    final GetUserResourceLimitsResponseControl c =
         new GetUserResourceLimitsResponseControl(12L, 34L, 56L, 78L,
              "uid=authz-user,ou=People,dc=example,dc=com", "ccpName",
              Collections.<String>emptyList(), Collections.<String>emptyList(),
              Collections.<Attribute>emptyList());

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
              new JSONField("size-limit", 12),
              new JSONField("time-limit-seconds", 34),
              new JSONField("idle-time-limit-seconds", 56),
              new JSONField("lookthrough-limit", 78),
              new JSONField("equivalent-authorization-user-dn",
                   "uid=authz-user,ou=People,dc=example,dc=com"),
              new JSONField("client-connection-policy-name", "ccpName"),
              new JSONField("group-dns", JSONArray.EMPTY_ARRAY),
              new JSONField("privilege-names", JSONArray.EMPTY_ARRAY)));


    GetUserResourceLimitsResponseControl decodedControl =
         GetUserResourceLimitsResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getSizeLimit(), Long.valueOf(12L));

    assertEquals(decodedControl.getTimeLimitSeconds(), Long.valueOf(34L));

    assertEquals(decodedControl.getIdleTimeLimitSeconds(), Long.valueOf(56L));

    assertEquals(decodedControl.getLookthroughLimit(), Long.valueOf(78L));

    assertEquals(decodedControl.getEquivalentAuthzUserDN(),
         "uid=authz-user,ou=People,dc=example,dc=com");

    assertEquals(decodedControl.getClientConnectionPolicyName(), "ccpName");

    assertEquals(decodedControl.getGroupDNs(), Collections.emptyList());

    assertEquals(decodedControl.getPrivilegeNames(), Collections.emptyList());

    assertEquals(decodedControl.getOtherAttributes(), Collections.emptyList());


    decodedControl =
         (GetUserResourceLimitsResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getSizeLimit(), Long.valueOf(12L));

    assertEquals(decodedControl.getTimeLimitSeconds(), Long.valueOf(34L));

    assertEquals(decodedControl.getIdleTimeLimitSeconds(), Long.valueOf(56L));

    assertEquals(decodedControl.getLookthroughLimit(), Long.valueOf(78L));

    assertEquals(decodedControl.getEquivalentAuthzUserDN(),
         "uid=authz-user,ou=People,dc=example,dc=com");

    assertEquals(decodedControl.getClientConnectionPolicyName(), "ccpName");

    assertEquals(decodedControl.getGroupDNs(), Collections.emptyList());

    assertEquals(decodedControl.getPrivilegeNames(), Collections.emptyList());

    assertEquals(decodedControl.getOtherAttributes(), Collections.emptyList());
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when all values are specified, and arrays are non-empty.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlAllElementsNonEmptyArrays()
          throws Exception
  {
    final GetUserResourceLimitsResponseControl c =
         new GetUserResourceLimitsResponseControl(12L, 34L, 56L, 78L,
              "uid=authz-user,ou=People,dc=example,dc=com", "ccpName",
              Arrays.asList(
                   "cn=Group 1,ou=Groups,dc=example,dc=com",
                   "cn=Group 2,ou=Groups,dc=example,dc=com"),
              Collections.singletonList(
                   "password-reset"),
              Arrays.asList(
                   new Attribute("attr1", "value1", "value2"),
                   new Attribute("attr2", "value3")));

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
              new JSONField("size-limit", 12),
              new JSONField("time-limit-seconds", 34),
              new JSONField("idle-time-limit-seconds", 56),
              new JSONField("lookthrough-limit", 78),
              new JSONField("equivalent-authorization-user-dn",
                   "uid=authz-user,ou=People,dc=example,dc=com"),
              new JSONField("client-connection-policy-name", "ccpName"),
              new JSONField("group-dns", new JSONArray(
                   new JSONString("cn=Group 1,ou=Groups,dc=example,dc=com"),
                   new JSONString("cn=Group 2,ou=Groups,dc=example,dc=com"))),
              new JSONField("privilege-names", new JSONArray(
                   new JSONString("password-reset"))),
              new JSONField("other-attributes", new JSONArray(
                   new JSONObject(
                        new JSONField("name", "attr1"),
                        new JSONField("values", new JSONArray(
                             new JSONString("value1"),
                             new JSONString("value2")))),
                   new JSONObject(
                        new JSONField("name", "attr2"),
                        new JSONField("values", new JSONArray(
                             new JSONString("value3"))))))));


    GetUserResourceLimitsResponseControl decodedControl =
         GetUserResourceLimitsResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getSizeLimit(), Long.valueOf(12L));

    assertEquals(decodedControl.getTimeLimitSeconds(), Long.valueOf(34L));

    assertEquals(decodedControl.getIdleTimeLimitSeconds(), Long.valueOf(56L));

    assertEquals(decodedControl.getLookthroughLimit(), Long.valueOf(78L));

    assertEquals(decodedControl.getEquivalentAuthzUserDN(),
         "uid=authz-user,ou=People,dc=example,dc=com");

    assertEquals(decodedControl.getClientConnectionPolicyName(), "ccpName");

    assertEquals(decodedControl.getGroupDNs(),
         Arrays.asList(
              "cn=Group 1,ou=Groups,dc=example,dc=com",
              "cn=Group 2,ou=Groups,dc=example,dc=com"));

    assertEquals(decodedControl.getPrivilegeNames(),
         Collections.singletonList("password-reset"));

    assertEquals(decodedControl.getOtherAttributes(),
         Arrays.asList(
              new Attribute("attr1", "value1", "value2"),
              new Attribute("attr2", "value3")));


    decodedControl =
         (GetUserResourceLimitsResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getSizeLimit(), Long.valueOf(12L));

    assertEquals(decodedControl.getTimeLimitSeconds(), Long.valueOf(34L));

    assertEquals(decodedControl.getIdleTimeLimitSeconds(), Long.valueOf(56L));

    assertEquals(decodedControl.getLookthroughLimit(), Long.valueOf(78L));

    assertEquals(decodedControl.getEquivalentAuthzUserDN(),
         "uid=authz-user,ou=People,dc=example,dc=com");

    assertEquals(decodedControl.getClientConnectionPolicyName(), "ccpName");

    assertEquals(decodedControl.getGroupDNs(),
         Arrays.asList(
              "cn=Group 1,ou=Groups,dc=example,dc=com",
              "cn=Group 2,ou=Groups,dc=example,dc=com"));

    assertEquals(decodedControl.getPrivilegeNames(),
         Collections.singletonList("password-reset"));

    assertEquals(decodedControl.getOtherAttributes(),
         Arrays.asList(
              new Attribute("attr1", "value1", "value2"),
              new Attribute("attr2", "value3")));
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
    final GetUserResourceLimitsResponseControl c =
         new GetUserResourceLimitsResponseControl(12L, 34L, 56L, 78L,
              "uid=authz-user,ou=People,dc=example,dc=com", "ccpName",
              Arrays.asList(
                   "cn=Group 1,ou=Groups,dc=example,dc=com",
                   "cn=Group 2,ou=Groups,dc=example,dc=com"),
              Collections.singletonList(
                   "password-reset"),
              Arrays.asList(
                   new Attribute("attr1", "value1", "value2"),
                   new Attribute("attr2", "value3")));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    GetUserResourceLimitsResponseControl decodedControl =
         GetUserResourceLimitsResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getSizeLimit(), Long.valueOf(12L));

    assertEquals(decodedControl.getTimeLimitSeconds(), Long.valueOf(34L));

    assertEquals(decodedControl.getIdleTimeLimitSeconds(), Long.valueOf(56L));

    assertEquals(decodedControl.getLookthroughLimit(), Long.valueOf(78L));

    assertEquals(decodedControl.getEquivalentAuthzUserDN(),
         "uid=authz-user,ou=People,dc=example,dc=com");

    assertEquals(decodedControl.getClientConnectionPolicyName(), "ccpName");

    assertEquals(decodedControl.getGroupDNs(),
         Arrays.asList(
              "cn=Group 1,ou=Groups,dc=example,dc=com",
              "cn=Group 2,ou=Groups,dc=example,dc=com"));

    assertEquals(decodedControl.getPrivilegeNames(),
         Collections.singletonList("password-reset"));

    assertEquals(decodedControl.getOtherAttributes(),
         Arrays.asList(
              new Attribute("attr1", "value1", "value2"),
              new Attribute("attr2", "value3")));


    decodedControl =
         (GetUserResourceLimitsResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getSizeLimit(), Long.valueOf(12L));

    assertEquals(decodedControl.getTimeLimitSeconds(), Long.valueOf(34L));

    assertEquals(decodedControl.getIdleTimeLimitSeconds(), Long.valueOf(56L));

    assertEquals(decodedControl.getLookthroughLimit(), Long.valueOf(78L));

    assertEquals(decodedControl.getEquivalentAuthzUserDN(),
         "uid=authz-user,ou=People,dc=example,dc=com");

    assertEquals(decodedControl.getClientConnectionPolicyName(), "ccpName");

    assertEquals(decodedControl.getGroupDNs(),
         Arrays.asList(
              "cn=Group 1,ou=Groups,dc=example,dc=com",
              "cn=Group 2,ou=Groups,dc=example,dc=com"));

    assertEquals(decodedControl.getPrivilegeNames(),
         Collections.singletonList("password-reset"));

    assertEquals(decodedControl.getOtherAttributes(),
         Arrays.asList(
              new Attribute("attr1", "value1", "value2"),
              new Attribute("attr2", "value3")));
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value contains a group-dns value that is not a string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlGroupDNNotString()
          throws Exception
  {
    final GetUserResourceLimitsResponseControl c =
         new GetUserResourceLimitsResponseControl(12L, 34L, 56L, 78L,
              "uid=authz-user,ou=People,dc=example,dc=com", "ccpName",
              Arrays.asList(
                   "cn=Group 1,ou=Groups,dc=example,dc=com",
                   "cn=Group 2,ou=Groups,dc=example,dc=com"),
              Collections.singletonList(
                   "password-reset"),
              Arrays.asList(
                   new Attribute("attr1", "value1", "value2"),
                   new Attribute("attr2", "value3")));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("size-limit", 12),
              new JSONField("time-limit-seconds", 34),
              new JSONField("idle-time-limit-seconds", 56),
              new JSONField("lookthrough-limit", 78),
              new JSONField("equivalent-authorization-user-dn",
                   "uid=authz-user,ou=People,dc=example,dc=com"),
              new JSONField("client-connection-policy-name", "ccpName"),
              new JSONField("group-dns", new JSONArray(
                   new JSONNumber(1234),
                   new JSONString("cn=Group 2,ou=Groups,dc=example,dc=com"))),
              new JSONField("privilege-names", new JSONArray(
                   new JSONString("password-reset"))),
              new JSONField("other-attributes", new JSONArray(
                   new JSONObject(
                        new JSONField("name", "attr1"),
                        new JSONField("values", new JSONArray(
                             new JSONString("value1"),
                             new JSONString("value2")))),
                   new JSONObject(
                        new JSONField("name", "attr2"),
                        new JSONField("values", new JSONArray(
                             new JSONString("value3")))))))));

    GetUserResourceLimitsResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value contains a privilege-names value that is not a string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlPrivilegeNameNotString()
          throws Exception
  {
    final GetUserResourceLimitsResponseControl c =
         new GetUserResourceLimitsResponseControl(12L, 34L, 56L, 78L,
              "uid=authz-user,ou=People,dc=example,dc=com", "ccpName",
              Arrays.asList(
                   "cn=Group 1,ou=Groups,dc=example,dc=com",
                   "cn=Group 2,ou=Groups,dc=example,dc=com"),
              Collections.singletonList(
                   "password-reset"),
              Arrays.asList(
                   new Attribute("attr1", "value1", "value2"),
                   new Attribute("attr2", "value3")));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("size-limit", 12),
              new JSONField("time-limit-seconds", 34),
              new JSONField("idle-time-limit-seconds", 56),
              new JSONField("lookthrough-limit", 78),
              new JSONField("equivalent-authorization-user-dn",
                   "uid=authz-user,ou=People,dc=example,dc=com"),
              new JSONField("client-connection-policy-name", "ccpName"),
              new JSONField("group-dns", new JSONArray(
                   new JSONString("cn=Group 1,ou=Groups,dc=example,dc=com"),
                   new JSONString("cn=Group 2,ou=Groups,dc=example,dc=com"))),
              new JSONField("privilege-names", new JSONArray(
                   new JSONNumber(1234))),
              new JSONField("other-attributes", new JSONArray(
                   new JSONObject(
                        new JSONField("name", "attr1"),
                        new JSONField("values", new JSONArray(
                             new JSONString("value1"),
                             new JSONString("value2")))),
                   new JSONObject(
                        new JSONField("name", "attr2"),
                        new JSONField("values", new JSONArray(
                             new JSONString("value3")))))))));

    GetUserResourceLimitsResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value contains an other-attributes value that is not an object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlOtherAttributeNameNotObject()
          throws Exception
  {
    final GetUserResourceLimitsResponseControl c =
         new GetUserResourceLimitsResponseControl(12L, 34L, 56L, 78L,
              "uid=authz-user,ou=People,dc=example,dc=com", "ccpName",
              Arrays.asList(
                   "cn=Group 1,ou=Groups,dc=example,dc=com",
                   "cn=Group 2,ou=Groups,dc=example,dc=com"),
              Collections.singletonList(
                   "password-reset"),
              Arrays.asList(
                   new Attribute("attr1", "value1", "value2"),
                   new Attribute("attr2", "value3")));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("size-limit", 12),
              new JSONField("time-limit-seconds", 34),
              new JSONField("idle-time-limit-seconds", 56),
              new JSONField("lookthrough-limit", 78),
              new JSONField("equivalent-authorization-user-dn",
                   "uid=authz-user,ou=People,dc=example,dc=com"),
              new JSONField("client-connection-policy-name", "ccpName"),
              new JSONField("group-dns", new JSONArray(
                   new JSONString("cn=Group 1,ou=Groups,dc=example,dc=com"),
                   new JSONString("cn=Group 2,ou=Groups,dc=example,dc=com"))),
              new JSONField("privilege-names", new JSONArray(
                   new JSONString("password-reset"))),
              new JSONField("other-attributes", new JSONArray(
                   new JSONString("foo"),
                   new JSONObject(
                        new JSONField("name", "attr2"),
                        new JSONField("values", new JSONArray(
                             new JSONString("value3")))))))));

    GetUserResourceLimitsResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value contains an other-attributes value that is missing the name
   * field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlOtherAttributeMissingName()
          throws Exception
  {
    final GetUserResourceLimitsResponseControl c =
         new GetUserResourceLimitsResponseControl(12L, 34L, 56L, 78L,
              "uid=authz-user,ou=People,dc=example,dc=com", "ccpName",
              Arrays.asList(
                   "cn=Group 1,ou=Groups,dc=example,dc=com",
                   "cn=Group 2,ou=Groups,dc=example,dc=com"),
              Collections.singletonList(
                   "password-reset"),
              Arrays.asList(
                   new Attribute("attr1", "value1", "value2"),
                   new Attribute("attr2", "value3")));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("size-limit", 12),
              new JSONField("time-limit-seconds", 34),
              new JSONField("idle-time-limit-seconds", 56),
              new JSONField("lookthrough-limit", 78),
              new JSONField("equivalent-authorization-user-dn",
                   "uid=authz-user,ou=People,dc=example,dc=com"),
              new JSONField("client-connection-policy-name", "ccpName"),
              new JSONField("group-dns", new JSONArray(
                   new JSONString("cn=Group 1,ou=Groups,dc=example,dc=com"),
                   new JSONString("cn=Group 2,ou=Groups,dc=example,dc=com"))),
              new JSONField("privilege-names", new JSONArray(
                   new JSONString("password-reset"))),
              new JSONField("other-attributes", new JSONArray(
                   new JSONObject(
                        new JSONField("values", new JSONArray(
                             new JSONString("value1"),
                             new JSONString("value2")))),
                   new JSONObject(
                        new JSONField("name", "attr2"),
                        new JSONField("values", new JSONArray(
                             new JSONString("value3")))))))));

    GetUserResourceLimitsResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value contains an other-attributes value that is missing the values
   * field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlOtherAttributeMissingValues()
          throws Exception
  {
    final GetUserResourceLimitsResponseControl c =
         new GetUserResourceLimitsResponseControl(12L, 34L, 56L, 78L,
              "uid=authz-user,ou=People,dc=example,dc=com", "ccpName",
              Arrays.asList(
                   "cn=Group 1,ou=Groups,dc=example,dc=com",
                   "cn=Group 2,ou=Groups,dc=example,dc=com"),
              Collections.singletonList(
                   "password-reset"),
              Arrays.asList(
                   new Attribute("attr1", "value1", "value2"),
                   new Attribute("attr2", "value3")));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("size-limit", 12),
              new JSONField("time-limit-seconds", 34),
              new JSONField("idle-time-limit-seconds", 56),
              new JSONField("lookthrough-limit", 78),
              new JSONField("equivalent-authorization-user-dn",
                   "uid=authz-user,ou=People,dc=example,dc=com"),
              new JSONField("client-connection-policy-name", "ccpName"),
              new JSONField("group-dns", new JSONArray(
                   new JSONString("cn=Group 1,ou=Groups,dc=example,dc=com"),
                   new JSONString("cn=Group 2,ou=Groups,dc=example,dc=com"))),
              new JSONField("privilege-names", new JSONArray(
                   new JSONString("password-reset"))),
              new JSONField("other-attributes", new JSONArray(
                   new JSONObject(
                        new JSONField("name", "attr1")),
                   new JSONObject(
                        new JSONField("name", "attr2"),
                        new JSONField("values", new JSONArray(
                             new JSONString("value3")))))))));

    GetUserResourceLimitsResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value contains an other-attributes value that has a values item that
   * is not a string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlOtherAttributeValueNotString()
          throws Exception
  {
    final GetUserResourceLimitsResponseControl c =
         new GetUserResourceLimitsResponseControl(12L, 34L, 56L, 78L,
              "uid=authz-user,ou=People,dc=example,dc=com", "ccpName",
              Arrays.asList(
                   "cn=Group 1,ou=Groups,dc=example,dc=com",
                   "cn=Group 2,ou=Groups,dc=example,dc=com"),
              Collections.singletonList(
                   "password-reset"),
              Arrays.asList(
                   new Attribute("attr1", "value1", "value2"),
                   new Attribute("attr2", "value3")));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("size-limit", 12),
              new JSONField("time-limit-seconds", 34),
              new JSONField("idle-time-limit-seconds", 56),
              new JSONField("lookthrough-limit", 78),
              new JSONField("equivalent-authorization-user-dn",
                   "uid=authz-user,ou=People,dc=example,dc=com"),
              new JSONField("client-connection-policy-name", "ccpName"),
              new JSONField("group-dns", new JSONArray(
                   new JSONString("cn=Group 1,ou=Groups,dc=example,dc=com"),
                   new JSONString("cn=Group 2,ou=Groups,dc=example,dc=com"))),
              new JSONField("privilege-names", new JSONArray(
                   new JSONString("password-reset"))),
              new JSONField("other-attributes", new JSONArray(
                   new JSONObject(
                        new JSONField("name", "attr1"),
                        new JSONField("values", new JSONArray(
                             new JSONNumber(1234),
                             new JSONString("value2")))),
                   new JSONObject(
                        new JSONField("name", "attr2"),
                        new JSONField("values", new JSONArray(
                             new JSONString("value3")))))))));

    GetUserResourceLimitsResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value contains an unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlUnrecognizedFieldStrict()
          throws Exception
  {
    final GetUserResourceLimitsResponseControl c =
         new GetUserResourceLimitsResponseControl(12L, 34L, 56L, 78L,
              "uid=authz-user,ou=People,dc=example,dc=com", "ccpName",
              Arrays.asList(
                   "cn=Group 1,ou=Groups,dc=example,dc=com",
                   "cn=Group 2,ou=Groups,dc=example,dc=com"),
              Collections.singletonList(
                   "password-reset"),
              Arrays.asList(
                   new Attribute("attr1", "value1", "value2"),
                   new Attribute("attr2", "value3")));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("size-limit", 12),
              new JSONField("time-limit-seconds", 34),
              new JSONField("idle-time-limit-seconds", 56),
              new JSONField("lookthrough-limit", 78),
              new JSONField("equivalent-authorization-user-dn",
                   "uid=authz-user,ou=People,dc=example,dc=com"),
              new JSONField("client-connection-policy-name", "ccpName"),
              new JSONField("group-dns", new JSONArray(
                   new JSONString("cn=Group 1,ou=Groups,dc=example,dc=com"),
                   new JSONString("cn=Group 2,ou=Groups,dc=example,dc=com"))),
              new JSONField("privilege-names", new JSONArray(
                   new JSONString("password-reset"))),
              new JSONField("other-attributes", new JSONArray(
                   new JSONObject(
                        new JSONField("name", "attr1"),
                        new JSONField("values", new JSONArray(
                             new JSONString("value1"),
                             new JSONString("value2")))),
                   new JSONObject(
                        new JSONField("name", "attr2"),
                        new JSONField("values", new JSONArray(
                             new JSONString("value3")))))),
              new JSONField("unrecognized", "foo"))));

    GetUserResourceLimitsResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value contains an unrecognized field in non-strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlUnrecognizedFieldNonStrict()
          throws Exception
  {
    final GetUserResourceLimitsResponseControl c =
         new GetUserResourceLimitsResponseControl(12L, 34L, 56L, 78L,
              "uid=authz-user,ou=People,dc=example,dc=com", "ccpName",
              Arrays.asList(
                   "cn=Group 1,ou=Groups,dc=example,dc=com",
                   "cn=Group 2,ou=Groups,dc=example,dc=com"),
              Collections.singletonList(
                   "password-reset"),
              Arrays.asList(
                   new Attribute("attr1", "value1", "value2"),
                   new Attribute("attr2", "value3")));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("size-limit", 12),
              new JSONField("time-limit-seconds", 34),
              new JSONField("idle-time-limit-seconds", 56),
              new JSONField("lookthrough-limit", 78),
              new JSONField("equivalent-authorization-user-dn",
                   "uid=authz-user,ou=People,dc=example,dc=com"),
              new JSONField("client-connection-policy-name", "ccpName"),
              new JSONField("group-dns", new JSONArray(
                   new JSONString("cn=Group 1,ou=Groups,dc=example,dc=com"),
                   new JSONString("cn=Group 2,ou=Groups,dc=example,dc=com"))),
              new JSONField("privilege-names", new JSONArray(
                   new JSONString("password-reset"))),
              new JSONField("other-attributes", new JSONArray(
                   new JSONObject(
                        new JSONField("name", "attr1"),
                        new JSONField("values", new JSONArray(
                             new JSONString("value1"),
                             new JSONString("value2")))),
                   new JSONObject(
                        new JSONField("name", "attr2"),
                        new JSONField("values", new JSONArray(
                             new JSONString("value3")))))),
              new JSONField("unrecognized", "foo"))));




    GetUserResourceLimitsResponseControl decodedControl =
         GetUserResourceLimitsResponseControl.decodeJSONControl(controlObject,
              false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getSizeLimit(), Long.valueOf(12L));

    assertEquals(decodedControl.getTimeLimitSeconds(), Long.valueOf(34L));

    assertEquals(decodedControl.getIdleTimeLimitSeconds(), Long.valueOf(56L));

    assertEquals(decodedControl.getLookthroughLimit(), Long.valueOf(78L));

    assertEquals(decodedControl.getEquivalentAuthzUserDN(),
         "uid=authz-user,ou=People,dc=example,dc=com");

    assertEquals(decodedControl.getClientConnectionPolicyName(), "ccpName");

    assertEquals(decodedControl.getGroupDNs(),
         Arrays.asList(
              "cn=Group 1,ou=Groups,dc=example,dc=com",
              "cn=Group 2,ou=Groups,dc=example,dc=com"));

    assertEquals(decodedControl.getPrivilegeNames(),
         Collections.singletonList("password-reset"));

    assertEquals(decodedControl.getOtherAttributes(),
         Arrays.asList(
              new Attribute("attr1", "value1", "value2"),
              new Attribute("attr2", "value3")));


    decodedControl =
         (GetUserResourceLimitsResponseControl)
         Control.decodeJSONControl(controlObject, false, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getSizeLimit(), Long.valueOf(12L));

    assertEquals(decodedControl.getTimeLimitSeconds(), Long.valueOf(34L));

    assertEquals(decodedControl.getIdleTimeLimitSeconds(), Long.valueOf(56L));

    assertEquals(decodedControl.getLookthroughLimit(), Long.valueOf(78L));

    assertEquals(decodedControl.getEquivalentAuthzUserDN(),
         "uid=authz-user,ou=People,dc=example,dc=com");

    assertEquals(decodedControl.getClientConnectionPolicyName(), "ccpName");

    assertEquals(decodedControl.getGroupDNs(),
         Arrays.asList(
              "cn=Group 1,ou=Groups,dc=example,dc=com",
              "cn=Group 2,ou=Groups,dc=example,dc=com"));

    assertEquals(decodedControl.getPrivilegeNames(),
         Collections.singletonList("password-reset"));

    assertEquals(decodedControl.getOtherAttributes(),
         Arrays.asList(
              new Attribute("attr1", "value1", "value2"),
              new Attribute("attr2", "value3")));
  }
}
