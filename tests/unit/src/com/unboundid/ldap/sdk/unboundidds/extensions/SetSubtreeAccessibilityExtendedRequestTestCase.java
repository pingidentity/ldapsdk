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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the set subtree accessibility
 * extended request.
 */
public final class SetSubtreeAccessibilityExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the request intended to make a single subtree
   * accessible.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAccessibleRequestSingleSubtree()
         throws Exception
  {
    SetSubtreeAccessibilityExtendedRequest r =
         SetSubtreeAccessibilityExtendedRequest.createSetAccessibleRequest(
              "ou=subtree,dc=example,dc=com");

    r = new SetSubtreeAccessibilityExtendedRequest(r);
    assertNotNull(r);

    r = r.duplicate();
    assertNotNull(r);

    assertNotNull(r.getSubtreeBaseDN());
    assertEquals(new DN(r.getSubtreeBaseDN()),
         new DN("ou=subtree,dc=example,dc=com"));

    assertNotNull(r.getSubtreeBaseDNs());
    assertEquals(r.getSubtreeBaseDNs().size(), 1);

    assertNotNull(r.getAccessibilityState());
    assertEquals(r.getAccessibilityState(),
         SubtreeAccessibilityState.ACCESSIBLE);

    assertNull(r.getBypassUserDN());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.19");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the request intended to make multiple subtrees
   * accessible.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAccessibleRequestMultipleSubtrees()
         throws Exception
  {
    SetSubtreeAccessibilityExtendedRequest r =
         SetSubtreeAccessibilityExtendedRequest.createSetAccessibleRequest(
              Arrays.asList("ou=subtree1,dc=example,dc=com",
                   "ou=subtree2,dc=example,dc=com"));

    r = new SetSubtreeAccessibilityExtendedRequest(r);
    assertNotNull(r);

    r = r.duplicate();
    assertNotNull(r);

    assertNotNull(r.getSubtreeBaseDN());
    assertEquals(new DN(r.getSubtreeBaseDN()),
         new DN("ou=subtree1,dc=example,dc=com"));

    assertNotNull(r.getSubtreeBaseDNs());
    assertEquals(r.getSubtreeBaseDNs().size(), 2);

    assertNotNull(r.getAccessibilityState());
    assertEquals(r.getAccessibilityState(),
         SubtreeAccessibilityState.ACCESSIBLE);

    assertNull(r.getBypassUserDN());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.19");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the request intended to make a single subtree
   * read-only with binds allowed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadOnlyWithBindsRequestSingleSubtree()
         throws Exception
  {
    SetSubtreeAccessibilityExtendedRequest r =
         SetSubtreeAccessibilityExtendedRequest.createSetReadOnlyRequest(
              "ou=subtree,dc=example,dc=com", true,
              "uid=bypass,dc=example,dc=com", new Control("1.2.3.4"));

    r = new SetSubtreeAccessibilityExtendedRequest(r);
    assertNotNull(r);

    r = r.duplicate();
    assertNotNull(r);

    assertNotNull(r.getSubtreeBaseDN());
    assertEquals(new DN(r.getSubtreeBaseDN()),
         new DN("ou=subtree,dc=example,dc=com"));

    assertNotNull(r.getSubtreeBaseDNs());
    assertEquals(r.getSubtreeBaseDNs().size(), 1);

    assertNotNull(r.getAccessibilityState());
    assertEquals(r.getAccessibilityState(),
         SubtreeAccessibilityState.READ_ONLY_BIND_ALLOWED);

    assertNotNull(r.getBypassUserDN());
    assertEquals(new DN(r.getBypassUserDN()),
         new DN("uid=bypass,dc=example,dc=com"));

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.19");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 1);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the request intended to make multiple subtrees
   * read-only with binds allowed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadOnlyWithBindsRequestMultipleSubtrees()
         throws Exception
  {
    SetSubtreeAccessibilityExtendedRequest r =
         SetSubtreeAccessibilityExtendedRequest.createSetReadOnlyRequest(
              Arrays.asList("ou=subtree1,dc=example,dc=com",
                   "ou=subtree2,dc=example,dc=com"),
              true, "uid=bypass,dc=example,dc=com", new Control("1.2.3.4"));

    r = new SetSubtreeAccessibilityExtendedRequest(r);
    assertNotNull(r);

    r = r.duplicate();
    assertNotNull(r);

    assertNotNull(r.getSubtreeBaseDN());
    assertEquals(new DN(r.getSubtreeBaseDN()),
         new DN("ou=subtree1,dc=example,dc=com"));

    assertNotNull(r.getSubtreeBaseDNs());
    assertEquals(r.getSubtreeBaseDNs().size(), 2);

    assertNotNull(r.getAccessibilityState());
    assertEquals(r.getAccessibilityState(),
         SubtreeAccessibilityState.READ_ONLY_BIND_ALLOWED);

    assertNotNull(r.getBypassUserDN());
    assertEquals(new DN(r.getBypassUserDN()),
         new DN("uid=bypass,dc=example,dc=com"));

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.19");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 1);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the request intended to make a single subtree
   * read-only with binds not allowed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadOnlyWithoutBindsRequestSingleSubtree()
         throws Exception
  {
    SetSubtreeAccessibilityExtendedRequest r =
         SetSubtreeAccessibilityExtendedRequest.createSetReadOnlyRequest(
              "ou=subtree,dc=example,dc=com", false,
              "uid=bypass,dc=example,dc=com", new Control("1.2.3.4"),
              new Control("1.2.3.5"));

    r = new SetSubtreeAccessibilityExtendedRequest(r);
    assertNotNull(r);

    r = r.duplicate();
    assertNotNull(r);

    assertNotNull(r.getSubtreeBaseDN());
    assertEquals(new DN(r.getSubtreeBaseDN()),
         new DN("ou=subtree,dc=example,dc=com"));

    assertNotNull(r.getSubtreeBaseDNs());
    assertEquals(r.getSubtreeBaseDNs().size(), 1);

    assertNotNull(r.getAccessibilityState());
    assertEquals(r.getAccessibilityState(),
         SubtreeAccessibilityState.READ_ONLY_BIND_DENIED);

    assertNotNull(r.getBypassUserDN());
    assertEquals(new DN(r.getBypassUserDN()),
         new DN("uid=bypass,dc=example,dc=com"));

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.19");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the request intended to make multiple subtrees
   * read-only with binds not allowed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadOnlyWithoutBindsRequestMultipleSubtrees()
         throws Exception
  {
    SetSubtreeAccessibilityExtendedRequest r =
         SetSubtreeAccessibilityExtendedRequest.createSetReadOnlyRequest(
              Arrays.asList("ou=subtree1,dc=example,dc=com",
                   "ou=subtree2,dc=example,dc=com"),
              false, "uid=bypass,dc=example,dc=com", new Control("1.2.3.4"),
              new Control("1.2.3.5"));

    r = new SetSubtreeAccessibilityExtendedRequest(r);
    assertNotNull(r);

    r = r.duplicate();
    assertNotNull(r);

    assertNotNull(r.getSubtreeBaseDN());
    assertEquals(new DN(r.getSubtreeBaseDN()),
         new DN("ou=subtree1,dc=example,dc=com"));

    assertNotNull(r.getSubtreeBaseDNs());
    assertEquals(r.getSubtreeBaseDNs().size(), 2);

    assertNotNull(r.getAccessibilityState());
    assertEquals(r.getAccessibilityState(),
         SubtreeAccessibilityState.READ_ONLY_BIND_DENIED);

    assertNotNull(r.getBypassUserDN());
    assertEquals(new DN(r.getBypassUserDN()),
         new DN("uid=bypass,dc=example,dc=com"));

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.19");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the request intended to make a single subtree hidden.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHiddenRequestSingleSubtree()
         throws Exception
  {
    SetSubtreeAccessibilityExtendedRequest r =
         SetSubtreeAccessibilityExtendedRequest.createSetHiddenRequest(
              "ou=subtree,dc=example,dc=com", "uid=bypass,dc=example,dc=com");

    r = new SetSubtreeAccessibilityExtendedRequest(r);
    assertNotNull(r);

    r = r.duplicate();
    assertNotNull(r);

    assertNotNull(r.getSubtreeBaseDN());
    assertEquals(new DN(r.getSubtreeBaseDN()),
         new DN("ou=subtree,dc=example,dc=com"));

    assertNotNull(r.getSubtreeBaseDNs());
    assertEquals(r.getSubtreeBaseDNs().size(), 1);

    assertNotNull(r.getAccessibilityState());
    assertEquals(r.getAccessibilityState(),
         SubtreeAccessibilityState.HIDDEN);

    assertNotNull(r.getBypassUserDN());
    assertEquals(new DN(r.getBypassUserDN()),
         new DN("uid=bypass,dc=example,dc=com"));

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.19");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the request intended to make multiple subtrees
   * hidden.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHiddenRequestMultipleSubtrees()
         throws Exception
  {
    SetSubtreeAccessibilityExtendedRequest r =
         SetSubtreeAccessibilityExtendedRequest.createSetHiddenRequest(
              Arrays.asList("ou=subtree1,dc=example,dc=com",
                   "ou=subtree2,dc=example,dc=com"),
              "uid=bypass,dc=example,dc=com");

    r = new SetSubtreeAccessibilityExtendedRequest(r);
    assertNotNull(r);

    r = r.duplicate();
    assertNotNull(r);

    assertNotNull(r.getSubtreeBaseDN());
    assertEquals(new DN(r.getSubtreeBaseDN()),
         new DN("ou=subtree1,dc=example,dc=com"));

    assertNotNull(r.getSubtreeBaseDNs());
    assertEquals(r.getSubtreeBaseDNs().size(), 2);

    assertNotNull(r.getAccessibilityState());
    assertEquals(r.getAccessibilityState(),
         SubtreeAccessibilityState.HIDDEN);

    assertNotNull(r.getBypassUserDN());
    assertEquals(new DN(r.getBypassUserDN()),
         new DN("uid=bypass,dc=example,dc=com"));

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.19");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to decode a generic extended request when it
   * does not have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNoValue()
         throws Exception
  {
    new SetSubtreeAccessibilityExtendedRequest(
         new ExtendedRequest("1.3.6.1.4.1.30221.2.6.19"));
  }



  /**
   * Tests the behavior when trying to decode a generic extended request when
   * the request value cannot be parsed as a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new SetSubtreeAccessibilityExtendedRequest(
         new ExtendedRequest("1.3.6.1.4.1.30221.2.6.19",
              new ASN1OctetString("not-a-sequence")));
  }



  /**
   * Tests the behavior when trying to decode a generic extended request when
   * the value sequence specifies an invalid accessibility type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidAccessibilityType()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString("ou=subtree,dc=example,dc=com"),
         new ASN1Enumerated(1234),
         new ASN1OctetString((byte) 0x80, "uid=bypass,dc=example,dc=com"));

    new SetSubtreeAccessibilityExtendedRequest(
         new ExtendedRequest("1.3.6.1.4.1.30221.2.6.19",
              new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Tests the behavior when trying to decode a generic extended request when
   * the value sequence specifies an invalid accessibility type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidElementType()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString("ou=subtree,dc=example,dc=com"),
         new ASN1Enumerated(1),
         new ASN1OctetString((byte) 0x8F, "invalid-element-type"));

    new SetSubtreeAccessibilityExtendedRequest(
         new ExtendedRequest("1.3.6.1.4.1.30221.2.6.19",
              new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Tests the behavior when trying to decode a generic extended request when
   * the value sequence contains a prohibited bypass DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeContainsProhibitedBypassDN()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString("ou=subtree,dc=example,dc=com"),
         new ASN1Enumerated(0),
         new ASN1OctetString((byte) 0x80, "uid=bypass,dc=example,dc=com"));

    new SetSubtreeAccessibilityExtendedRequest(
         new ExtendedRequest("1.3.6.1.4.1.30221.2.6.19",
              new ASN1OctetString(valueSequence.encode())));
  }
}
