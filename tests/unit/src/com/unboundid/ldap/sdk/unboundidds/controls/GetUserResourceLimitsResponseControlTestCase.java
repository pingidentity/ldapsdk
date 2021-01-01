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
}
