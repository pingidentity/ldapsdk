/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the get authorization entry
 * response control.
 */
public class GetAuthorizationEntryResponseControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the first constructor.  This constructor isn't
   * meant to create useful entries, so we'll just make sure the constructor is
   * called and doesn't itself throw an exception.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    new GetAuthorizationEntryResponseControl();
  }



  /**
   * Provides test coverage for the second constructor for an unauthenticated
   * user.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Unauthenticated()
         throws Exception
  {
    GetAuthorizationEntryResponseControl c =
         new GetAuthorizationEntryResponseControl(false, true, null, null, null,
                                                  null);
    c = new GetAuthorizationEntryResponseControl().decodeControl(
                 c.getOID(), c.isCritical(), c.getValue());

    assertFalse(c.isAuthenticated());

    assertTrue(c.identitiesMatch());

    assertNull(c.getAuthNID());

    assertNull(c.getAuthNEntry());

    assertNull(c.getAuthZID());

    assertNull(c.getAuthZEntry());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the second constructor for an authenticated
   * user with the same authentication and authorization identities and the
   * authentication identity is provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2AuthenticatedIdentitiesMatchAuthN()
         throws Exception
  {
    ReadOnlyEntry e = new ReadOnlyEntry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User");

    GetAuthorizationEntryResponseControl c =
         new GetAuthorizationEntryResponseControl(true, true, "u:test.user", e,
                                                  null, null);
    c = new GetAuthorizationEntryResponseControl().decodeControl(
                 c.getOID(), c.isCritical(), c.getValue());

    assertTrue(c.isAuthenticated());

    assertTrue(c.identitiesMatch());

    assertNotNull(c.getAuthNID());
    assertEquals(c.getAuthNID(), "u:test.user");

    assertNotNull(c.getAuthNEntry());
    assertTrue(c.getAuthNEntry().hasAttributeValue("sn", "user"));

    assertNotNull(c.getAuthZID());
    assertEquals(c.getAuthZID(), c.getAuthNID());

    assertNotNull(c.getAuthZEntry());
    assertEquals(c.getAuthZEntry(), c.getAuthNEntry());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the second constructor for an authenticated
   * user with the same authentication and authorization identities and the
   * authorization identity is provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2AuthenticatedIdentitiesMatchAuthZ()
         throws Exception
  {
    ReadOnlyEntry e = new ReadOnlyEntry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User");

    GetAuthorizationEntryResponseControl c =
         new GetAuthorizationEntryResponseControl(true, true, null, null,
                                                  "u:test.user", e);
    c = new GetAuthorizationEntryResponseControl().decodeControl(
                 c.getOID(), c.isCritical(), c.getValue());

    assertTrue(c.isAuthenticated());

    assertTrue(c.identitiesMatch());

    assertNotNull(c.getAuthNID());
    assertEquals(c.getAuthNID(), "u:test.user");

    assertNotNull(c.getAuthNEntry());
    assertTrue(c.getAuthNEntry().hasAttributeValue("sn", "user"));

    assertNotNull(c.getAuthZID());
    assertEquals(c.getAuthZID(), c.getAuthNID());

    assertNotNull(c.getAuthZEntry());
    assertEquals(c.getAuthZEntry(), c.getAuthNEntry());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the second constructor for an authenticated
   * user with different authentication and authorization identities.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2AuthenticatedDifferentIdentities()
         throws Exception
  {
    ReadOnlyEntry nEntry = new ReadOnlyEntry(
         "dn: uid=n.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: n.user",
         "givenName: N",
         "sn: User",
         "cn: N User");

    ReadOnlyEntry zEntry = new ReadOnlyEntry(
         "dn: uid=z.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: z.user",
         "givenName: Z",
         "sn: User",
         "cn: Z User");

    GetAuthorizationEntryResponseControl c =
         new GetAuthorizationEntryResponseControl(true, false, "u:n.user",
                                                  nEntry, "u:z.user", zEntry);
    c = new GetAuthorizationEntryResponseControl().decodeControl(
                 c.getOID(), c.isCritical(), c.getValue());

    assertTrue(c.isAuthenticated());

    assertFalse(c.identitiesMatch());

    assertNotNull(c.getAuthNID());
    assertEquals(c.getAuthNID(), "u:n.user");

    assertNotNull(c.getAuthNEntry());
    assertEquals(c.getAuthNEntry(), nEntry);

    assertNotNull(c.getAuthZID());
    assertEquals(c.getAuthZID(), "u:z.user");

    assertNotNull(c.getAuthZEntry());
    assertEquals(c.getAuthZEntry(), zEntry);

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with a null value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3NullValue()
         throws Exception
  {
    new GetAuthorizationEntryResponseControl("1.2.3.4", false, null);
  }



  /**
   * Tests the third constructor with a value that isn't a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueNotSequence()
         throws Exception
  {
    new GetAuthorizationEntryResponseControl("1.2.3.4", false,
                                             new ASN1OctetString(new byte[1]));
  }



  /**
   * Tests the third constructor with a value sequence that contains an invalid
   * element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueSequenceInvalidType()
         throws Exception
  {
    ASN1Sequence s = new ASN1Sequence(new ASN1OctetString((byte) 0x00));
    new GetAuthorizationEntryResponseControl("1.2.3.4", false,
                                             new ASN1OctetString(s.encode()));
  }



  /**
   * Tests the third constructor with a value sequence that contains an entry
   * with an invalid element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueInvalidEntryElementType()
         throws Exception
  {
    ASN1Sequence eS = new ASN1Sequence(new ASN1OctetString((byte) 0x00));
    ASN1Sequence vS = new ASN1Sequence(new ASN1Sequence((byte) 0xA2, eS));

    new GetAuthorizationEntryResponseControl("1.2.3.4", false,
                                             new ASN1OctetString(vS.encode()));
  }



  /**
   * Tests the {@code get} method with a result that does not contain a get
   * authorization entry response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetMissing()
         throws Exception
  {
    final Control[] controls = new Control[0];

    final BindResult r = new BindResult(1, ResultCode.SUCCESS, null, null, null,
         controls);

    final GetAuthorizationEntryResponseControl c =
         GetAuthorizationEntryResponseControl.get(r);
    assertNull(c);
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is already of the appropriate type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValidCorrectType()
         throws Exception
  {
    final ReadOnlyEntry e = new ReadOnlyEntry(generateUserEntry("test.user",
         "ou=People,dc=example,dc=com", "Test", "User", "password"));

    final Control[] controls =
    {
      new GetAuthorizationEntryResponseControl(true, true, "u:test.user", e,
           null, null)
    };

    final BindResult r = new BindResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    final GetAuthorizationEntryResponseControl c =
         GetAuthorizationEntryResponseControl.get(r);
    assertNotNull(c);

    assertTrue(c.isAuthenticated());

    assertTrue(c.identitiesMatch());

    assertNotNull(c.getAuthNID());
    assertEquals(c.getAuthNID(), "u:test.user");

    assertNotNull(c.getAuthNEntry());
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that can be parsed as a get authorization entry
   * control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValidGenericType()
         throws Exception
  {
    final ReadOnlyEntry e = new ReadOnlyEntry(generateUserEntry("test.user",
         "ou=People,dc=example,dc=com", "Test", "User", "password"));

    final Control tmp = new GetAuthorizationEntryResponseControl(true, true,
         "u:test.user", e, null, null);

    final Control[] controls =
    {
      new Control(tmp.getOID(), tmp.isCritical(), tmp.getValue())
    };

    final BindResult r = new BindResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    final GetAuthorizationEntryResponseControl c =
         GetAuthorizationEntryResponseControl.get(r);
    assertNotNull(c);

    assertTrue(c.isAuthenticated());

    assertTrue(c.identitiesMatch());

    assertNotNull(c.getAuthNID());
    assertEquals(c.getAuthNID(), "u:test.user");

    assertNotNull(c.getAuthNEntry());
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that cannot be parsed as a get authorization
   * entry control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetInvalidGenericType()
         throws Exception
  {
    final Control[] controls =
    {
      new Control(GetAuthorizationEntryResponseControl.
           GET_AUTHORIZATION_ENTRY_RESPONSE_OID, false, null)
    };

    final BindResult r = new BindResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    GetAuthorizationEntryResponseControl.get(r);
  }
}
