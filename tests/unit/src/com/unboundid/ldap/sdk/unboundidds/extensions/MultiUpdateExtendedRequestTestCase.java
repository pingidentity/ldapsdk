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



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1Null;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.CompareRequest;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ModifyDNRequest;
import com.unboundid.ldap.sdk.LDAPRequest;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.controls.ManageDsaITRequestControl;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedRequest;



/**
 * This class provides a set of test cases for the multi-update extended
 * request.
 */
public final class MultiUpdateExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic test coverage for the multi-update extended request without
   * any controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicWithoutControls()
         throws Exception
  {
    final Control[] modDNControls =
    {
      new ManageDsaITRequestControl()
    };

    MultiUpdateExtendedRequest r = new MultiUpdateExtendedRequest(
         MultiUpdateErrorBehavior.ATOMIC,
         new AddRequest(
              "dn: uid=test.user,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: test.user",
              "givenName: Test",
              "sn: User",
              "cn: Test User",
              "userPassword: password"),
         new ModifyRequest(
              "dn: uid=test.user,ou=People,dc=example,dc=com",
              "changetype: modify",
              "replace: description",
              "description: foo"),
         new ModifyDNRequest(
              "uid=test.user,ou=People,dc=example,dc=com",
              "cn=Test User",
              false,
              modDNControls),
         new PasswordModifyExtendedRequest(
              "dn:cn=Test User,ou=People,dc=example,dc=com",
              "password",
              "newPassword"),
         new DeleteRequest(
              "cn=Test User,ou=People,dc=example,dc=com"));

    r = new MultiUpdateExtendedRequest(r);

    r = r.duplicate();

    assertNotNull(r.getErrorBehavior());
    assertEquals(r.getErrorBehavior(), MultiUpdateErrorBehavior.ATOMIC);

    assertNotNull(r.getRequests());
    assertEquals(r.getRequests().size(), 5);

    assertEquals(r.getRequests().get(0).getOperationType(),
         OperationType.ADD);
    assertNotNull(r.getRequests().get(0).getControls());
    assertEquals(r.getRequests().get(0).getControls().length, 0);

    assertEquals(r.getRequests().get(1).getOperationType(),
         OperationType.MODIFY);
    assertNotNull(r.getRequests().get(1).getControls());
    assertEquals(r.getRequests().get(1).getControls().length, 0);

    assertEquals(r.getRequests().get(2).getOperationType(),
         OperationType.MODIFY_DN);
    assertNotNull(r.getRequests().get(2).getControls());
    assertEquals(r.getRequests().get(2).getControls().length, 1);

    assertEquals(r.getRequests().get(3).getOperationType(),
         OperationType.EXTENDED);
    assertNotNull(r.getRequests().get(3).getControls());
    assertEquals(r.getRequests().get(3).getControls().length, 0);

    assertEquals(r.getRequests().get(4).getOperationType(),
         OperationType.DELETE);
    assertNotNull(r.getRequests().get(4).getControls());
    assertEquals(r.getRequests().get(4).getControls().length, 0);

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Provides basic test coverage for the multi-update extended request with
   * controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicWithControls()
         throws Exception
  {
    final Control[] modDNControls =
    {
      new ManageDsaITRequestControl()
    };

    final LDAPRequest[] requests =
    {
      new AddRequest(
           "dn: uid=test.user,ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: test.user",
           "givenName: Test",
           "sn: User",
           "cn: Test User",
           "userPassword: password"),
      new ModifyRequest(
           "dn: uid=test.user,ou=People,dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: foo"),
      new ModifyDNRequest(
           "uid=test.user,ou=People,dc=example,dc=com",
           "cn=Test User",
           false,
           modDNControls),
      new PasswordModifyExtendedRequest(
           "dn:cn=Test User,ou=People,dc=example,dc=com",
           "password",
           "newPassword"),
      new DeleteRequest(
           "cn=Test User,ou=People,dc=example,dc=com")
    };

    final Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true)
    };

    MultiUpdateExtendedRequest r = new MultiUpdateExtendedRequest(
         MultiUpdateErrorBehavior.ATOMIC,
         requests,
         controls);

    r = new MultiUpdateExtendedRequest(r);

    r = r.duplicate();

    assertNotNull(r.getErrorBehavior());
    assertEquals(r.getErrorBehavior(), MultiUpdateErrorBehavior.ATOMIC);

    assertNotNull(r.getRequests());
    assertEquals(r.getRequests().size(), 5);

    assertEquals(r.getRequests().get(0).getOperationType(),
         OperationType.ADD);
    assertNotNull(r.getRequests().get(0).getControls());
    assertEquals(r.getRequests().get(0).getControls().length, 0);

    assertEquals(r.getRequests().get(1).getOperationType(),
         OperationType.MODIFY);
    assertNotNull(r.getRequests().get(1).getControls());
    assertEquals(r.getRequests().get(1).getControls().length, 0);

    assertEquals(r.getRequests().get(2).getOperationType(),
         OperationType.MODIFY_DN);
    assertNotNull(r.getRequests().get(2).getControls());
    assertEquals(r.getRequests().get(2).getControls().length, 1);

    assertEquals(r.getRequests().get(3).getOperationType(),
         OperationType.EXTENDED);
    assertNotNull(r.getRequests().get(3).getControls());
    assertEquals(r.getRequests().get(3).getControls().length, 0);

    assertEquals(r.getRequests().get(4).getOperationType(),
         OperationType.DELETE);
    assertNotNull(r.getRequests().get(4).getControls());
    assertEquals(r.getRequests().get(4).getControls().length, 0);

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for the process method using the in-memory directory
   * server.  Since the server doesn't support this operation, it will return
   * a failure response, but that's good enough to provide test coverage.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProcess()
         throws Exception
  {
    final LDAPConnection connection = getTestDS(true, true).getConnection();

    final MultiUpdateExtendedRequest req = new MultiUpdateExtendedRequest(
         MultiUpdateErrorBehavior.ATOMIC,
         new AddRequest(
              "dn: uid=test.user,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: test.user",
              "givenName: Test",
              "sn: User",
              "cn: Test User",
              "userPassword: password"));

    final MultiUpdateExtendedResult res =
         (MultiUpdateExtendedResult) connection.processExtendedOperation(req);
    assertNotNull(res);
    assertResultCodeEquals(res, ResultCode.UNWILLING_TO_PERFORM);

    connection.close();
  }



  /**
   * Tests the behavior when trying to create a multi-update request that
   * includes a non-update operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testCreateWithInvalidRequestType()
         throws Exception
  {
    new MultiUpdateExtendedRequest(MultiUpdateErrorBehavior.ATOMIC,
         new CompareRequest("dn: uid=test.user,ou=People,dc=example,dc=com",
              "givenName", "Test"));
  }



  /**
   * Tests the behavior when trying to decode a multi-update extended request
   * that does not have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeRequestWithoutValue()
         throws Exception
  {
    new MultiUpdateExtendedRequest(new ExtendedRequest(
         MultiUpdateExtendedRequest.MULTI_UPDATE_REQUEST_OID,
         (ASN1OctetString) null));
  }



  /**
   * Tests the behavior when trying to decode a multi-update extended request
   * whose value cannot be decoded as an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeRequestValueNotSequence()
         throws Exception
  {
    new MultiUpdateExtendedRequest(new ExtendedRequest(
         MultiUpdateExtendedRequest.MULTI_UPDATE_REQUEST_OID,
         new ASN1OctetString("foo")));
  }



  /**
   * Tests the behavior when trying to decode a multi-update extended request
   * that contains an invalid error behavior value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidErrorBehavior()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Enumerated(1234),
         new ASN1Sequence(
              new ASN1Sequence(
                   new ASN1OctetString(
                        LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST,
                        "uid=test.user,ou=People,dc=example,dc=com"))));

    new MultiUpdateExtendedRequest(new ExtendedRequest(
         MultiUpdateExtendedRequest.MULTI_UPDATE_REQUEST_OID,
         new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Tests the behavior when trying to decode a multi-update extended request
   * that contains an invalid request element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidRequestType()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Enumerated(0),
         new ASN1Sequence(
              new ASN1Sequence(
                   new ASN1Null(LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST))));

    new MultiUpdateExtendedRequest(new ExtendedRequest(
         MultiUpdateExtendedRequest.MULTI_UPDATE_REQUEST_OID,
         new ASN1OctetString(valueSequence.encode())));
  }
}
