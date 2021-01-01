/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1Null;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the
 * {@code GeneratePasswordExtendedRequest} class.
 */
public final class GeneratePasswordExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests an instance of the extended request that uses all the default
   * settings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultRequest()
         throws Exception
  {
    GeneratePasswordExtendedRequest r = new GeneratePasswordExtendedRequest();

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.62");

    assertNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getPasswordPolicySelectionType());
    assertEquals(r.getPasswordPolicySelectionType(),
         GeneratePasswordPolicySelectionType.DEFAULT_POLICY);

    assertNull(r.getPasswordPolicyDN());

    assertNull(r.getTargetEntryDN());

    assertEquals(r.getNumberOfPasswords(), 1);

    assertEquals(r.getNumberOfValidationAttempts(), 5);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());


    r = new GeneratePasswordExtendedRequest(r);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.62");

    assertNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getPasswordPolicySelectionType());
    assertEquals(r.getPasswordPolicySelectionType(),
         GeneratePasswordPolicySelectionType.DEFAULT_POLICY);

    assertNull(r.getPasswordPolicyDN());

    assertNull(r.getTargetEntryDN());

    assertEquals(r.getNumberOfPasswords(), 1);

    assertEquals(r.getNumberOfValidationAttempts(), 5);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());


    r = r.duplicate();

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.62");

    assertNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getPasswordPolicySelectionType());
    assertEquals(r.getPasswordPolicySelectionType(),
         GeneratePasswordPolicySelectionType.DEFAULT_POLICY);

    assertNull(r.getPasswordPolicyDN());

    assertNull(r.getTargetEntryDN());

    assertEquals(r.getNumberOfPasswords(), 1);

    assertEquals(r.getNumberOfValidationAttempts(), 5);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior for an extended request that uses the default password
   * policy.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateRequestWithDefaultPolicy()
         throws Exception
  {
    GeneratePasswordExtendedRequest r =
         GeneratePasswordExtendedRequest.createDefaultPolicyRequest(5, 10,
              new Control("1.2.3.4"), new Control("5.6.7.8"));

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.62");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getPasswordPolicySelectionType());
    assertEquals(r.getPasswordPolicySelectionType(),
         GeneratePasswordPolicySelectionType.DEFAULT_POLICY);

    assertNull(r.getPasswordPolicyDN());

    assertNull(r.getTargetEntryDN());

    assertEquals(r.getNumberOfPasswords(), 5);

    assertEquals(r.getNumberOfValidationAttempts(), 10);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());


    r = new GeneratePasswordExtendedRequest(r);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.62");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getPasswordPolicySelectionType());
    assertEquals(r.getPasswordPolicySelectionType(),
         GeneratePasswordPolicySelectionType.DEFAULT_POLICY);

    assertNull(r.getPasswordPolicyDN());

    assertNull(r.getTargetEntryDN());

    assertEquals(r.getNumberOfPasswords(), 5);

    assertEquals(r.getNumberOfValidationAttempts(), 10);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());


    r = r.duplicate();

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.62");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getPasswordPolicySelectionType());
    assertEquals(r.getPasswordPolicySelectionType(),
         GeneratePasswordPolicySelectionType.DEFAULT_POLICY);

    assertNull(r.getPasswordPolicyDN());

    assertNull(r.getTargetEntryDN());

    assertEquals(r.getNumberOfPasswords(), 5);

    assertEquals(r.getNumberOfValidationAttempts(), 10);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior for an extended request that uses a specified password
   * policy.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateRequestWithSpecifiedPolicy()
         throws Exception
  {
    GeneratePasswordExtendedRequest r =
         GeneratePasswordExtendedRequest.createPasswordPolicyDNRequest(
              "cn=Test,cn=Password Policies,cn=config",  10, 5,
              new Control("1.2.3.4"));

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.62");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 1);

    assertNotNull(r.getPasswordPolicySelectionType());
    assertEquals(r.getPasswordPolicySelectionType(),
         GeneratePasswordPolicySelectionType.PASSWORD_POLICY_DN);

    assertNotNull(r.getPasswordPolicyDN());
    assertDNsEqual(r.getPasswordPolicyDN(),
         "cn=Test,cn=Password Policies,cn=config");

    assertNull(r.getTargetEntryDN());

    assertEquals(r.getNumberOfPasswords(), 10);

    assertEquals(r.getNumberOfValidationAttempts(), 5);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());


    r = new GeneratePasswordExtendedRequest(r);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.62");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 1);

    assertNotNull(r.getPasswordPolicySelectionType());
    assertEquals(r.getPasswordPolicySelectionType(),
         GeneratePasswordPolicySelectionType.PASSWORD_POLICY_DN);

    assertNotNull(r.getPasswordPolicyDN());
    assertDNsEqual(r.getPasswordPolicyDN(),
         "cn=Test,cn=Password Policies,cn=config");

    assertNull(r.getTargetEntryDN());

    assertEquals(r.getNumberOfPasswords(), 10);

    assertEquals(r.getNumberOfValidationAttempts(), 5);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());


    r = r.duplicate();

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.62");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 1);

    assertNotNull(r.getPasswordPolicySelectionType());
    assertEquals(r.getPasswordPolicySelectionType(),
         GeneratePasswordPolicySelectionType.PASSWORD_POLICY_DN);

    assertNotNull(r.getPasswordPolicyDN());
    assertDNsEqual(r.getPasswordPolicyDN(),
         "cn=Test,cn=Password Policies,cn=config");

    assertNull(r.getTargetEntryDN());

    assertEquals(r.getNumberOfPasswords(), 10);

    assertEquals(r.getNumberOfValidationAttempts(), 5);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior for an extended request that uses the password policy
   * that governs a specified entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateRequestWithTargetEntryDN()
         throws Exception
  {
    GeneratePasswordExtendedRequest r =
         GeneratePasswordExtendedRequest.createTargetEntryDNRequest(
              "uid=test.user,ou=People,dc=example,dc=com",  1, 0);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.62");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getPasswordPolicySelectionType());
    assertEquals(r.getPasswordPolicySelectionType(),
         GeneratePasswordPolicySelectionType.TARGET_ENTRY_DN);

    assertNull(r.getPasswordPolicyDN());

    assertNotNull(r.getTargetEntryDN());
    assertDNsEqual(r.getTargetEntryDN(),
         "uid=test.user,ou=People,dc=example,dc=com");

    assertEquals(r.getNumberOfPasswords(), 1);

    assertEquals(r.getNumberOfValidationAttempts(), 0);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());


    r = new GeneratePasswordExtendedRequest(r);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.62");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getPasswordPolicySelectionType());
    assertEquals(r.getPasswordPolicySelectionType(),
         GeneratePasswordPolicySelectionType.TARGET_ENTRY_DN);

    assertNull(r.getPasswordPolicyDN());

    assertNotNull(r.getTargetEntryDN());
    assertDNsEqual(r.getTargetEntryDN(),
         "uid=test.user,ou=People,dc=example,dc=com");

    assertEquals(r.getNumberOfPasswords(), 1);

    assertEquals(r.getNumberOfValidationAttempts(), 0);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());


    r = r.duplicate();

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.62");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getPasswordPolicySelectionType());
    assertEquals(r.getPasswordPolicySelectionType(),
         GeneratePasswordPolicySelectionType.TARGET_ENTRY_DN);

    assertNull(r.getPasswordPolicyDN());

    assertNotNull(r.getTargetEntryDN());
    assertDNsEqual(r.getTargetEntryDN(),
         "uid=test.user,ou=People,dc=example,dc=com");

    assertEquals(r.getNumberOfPasswords(), 1);

    assertEquals(r.getNumberOfValidationAttempts(), 0);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to decode an extended request whose value is
   * not an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new GeneratePasswordExtendedRequest(new ExtendedRequest(
         "1.3.6.1.4.1.30221.2.6.62", new ASN1OctetString("not a sequence")));
  }



  /**
   * Tests the behavior when trying to decode an extended request whose encoding
   * uses an unrecognized password policy selection type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeUnrecognizedPasswordPolicySelectionType()
         throws Exception
  {
    new GeneratePasswordExtendedRequest(new ExtendedRequest(
         "1.3.6.1.4.1.30221.2.6.62",
         new ASN1OctetString(new ASN1Sequence(
              new ASN1Null((byte) 0xFF),
              new ASN1Integer((byte) 0x83, 1),
              new ASN1Integer((byte) 0x84, 1)).encode())));
  }



  /**
   * Tests the behavior when trying to decode an extended request whose encoding
   * suggests that the server should generate zero passwords.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueZeroPasswords()
         throws Exception
  {
    new GeneratePasswordExtendedRequest(new ExtendedRequest(
         "1.3.6.1.4.1.30221.2.6.62",
         new ASN1OctetString(new ASN1Sequence(
              new ASN1Null((byte) 0x80),
              new ASN1Integer((byte) 0x83, 0),
              new ASN1Integer((byte) 0x84, 1)).encode())));
  }



  /**
   * Tests the behavior when trying to decode an extended request whose encoding
   * suggests that the server should use a negative number of validation
   * attempts.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNegativeValidationAttempts()
         throws Exception
  {
    new GeneratePasswordExtendedRequest(new ExtendedRequest(
         "1.3.6.1.4.1.30221.2.6.62",
         new ASN1OctetString(new ASN1Sequence(
              new ASN1Null((byte) 0x80),
              new ASN1Integer((byte) 0x83, 1),
              new ASN1Integer((byte) 0x84, -1)).encode())));
  }



  /**
   * Tests the behavior when trying to process the operation.  We'll use the
   * in-memory directory server, which doesn't support the extended operation,
   * but at least we'll get coverage for the request code.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProcess()
         throws Exception
  {
    try (LDAPConnection conn = getTestDS().getConnection())
    {
      GeneratePasswordExtendedResult result =
           (GeneratePasswordExtendedResult)
           conn.processExtendedOperation(new GeneratePasswordExtendedRequest());

      assertNotNull(result);
      assertResultCodeNot(result, ResultCode.SUCCESS);
    }
  }
}
