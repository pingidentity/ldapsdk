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



import java.util.Arrays;
import java.util.Collections;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the
 * {@code GeneratePasswordExtendedResult} class.
 */
public final class GeneratePasswordExtendedResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the constructor that is intended for use with a successful response
   * using a single generated password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessConstructorSinglePassword()
         throws Exception
  {
    GeneratePasswordExtendedResult r = new GeneratePasswordExtendedResult(1,
         "cn=Default,cn=Password Policies,cn=config",
         Collections.singletonList(new GeneratedPassword("generatedPassword",
              true, null)));

    assertEquals(r.getMessageID(), 1);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.63");

    assertNotNull(r.getValue());

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(r.getPasswordPolicyDN());
    assertDNsEqual(r.getPasswordPolicyDN(),
         "cn=Default,cn=Password Policies,cn=config");

    assertNotNull(r.getGeneratedPasswords());
    assertFalse(r.getGeneratedPasswords().isEmpty());
    assertEquals(r.getGeneratedPasswords().size(), 1);
    assertEquals(r.getGeneratedPasswords().get(0).getPasswordString(),
         "generatedPassword");

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());


    r = new GeneratePasswordExtendedResult(r);

    assertEquals(r.getMessageID(), 1);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.63");

    assertNotNull(r.getValue());

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(r.getPasswordPolicyDN());
    assertDNsEqual(r.getPasswordPolicyDN(),
         "cn=Default,cn=Password Policies,cn=config");

    assertNotNull(r.getGeneratedPasswords());
    assertFalse(r.getGeneratedPasswords().isEmpty());
    assertEquals(r.getGeneratedPasswords().size(), 1);
    assertEquals(r.getGeneratedPasswords().get(0).getPasswordString(),
         "generatedPassword");

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the constructor that takes all of the result arguments with a set of
   * values that indicates a successful response that includes multiple
   * generated passwords.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessConstructorMultiplePasswords()
         throws Exception
  {
    GeneratePasswordExtendedResult r = new GeneratePasswordExtendedResult(2,
         ResultCode.SUCCESS, "Here are the passwords", null, null,
         "cn=Custom,cn=Password Policies,cn=config",
         Arrays.asList(
              new GeneratedPassword("acceptablePassword", true, null),
              new GeneratedPassword("problematicPassword", true,
                   Collections.singletonList("Not as good"))));

    assertEquals(r.getMessageID(), 2);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    assertNotNull(r.getDiagnosticMessage());
    assertEquals(r.getDiagnosticMessage(), "Here are the passwords");

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.63");

    assertNotNull(r.getValue());

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(r.getPasswordPolicyDN());
    assertDNsEqual(r.getPasswordPolicyDN(),
         "cn=Custom,cn=Password Policies,cn=config");

    assertNotNull(r.getGeneratedPasswords());
    assertFalse(r.getGeneratedPasswords().isEmpty());
    assertEquals(r.getGeneratedPasswords().size(), 2);
    assertEquals(r.getGeneratedPasswords().get(0).getPasswordString(),
         "acceptablePassword");
    assertEquals(r.getGeneratedPasswords().get(1).getPasswordString(),
         "problematicPassword");

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());


    r = new GeneratePasswordExtendedResult(r);

    assertEquals(r.getMessageID(), 2);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    assertNotNull(r.getDiagnosticMessage());
    assertEquals(r.getDiagnosticMessage(), "Here are the passwords");

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.63");

    assertNotNull(r.getValue());

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(r.getPasswordPolicyDN());
    assertDNsEqual(r.getPasswordPolicyDN(),
         "cn=Custom,cn=Password Policies,cn=config");

    assertNotNull(r.getGeneratedPasswords());
    assertFalse(r.getGeneratedPasswords().isEmpty());
    assertEquals(r.getGeneratedPasswords().size(), 2);
    assertEquals(r.getGeneratedPasswords().get(0).getPasswordString(),
         "acceptablePassword");
    assertEquals(r.getGeneratedPasswords().get(1).getPasswordString(),
         "problematicPassword");

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the constructor that takes all of the result arguments with a set of
   * values that indicates an unsuccessful response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnsuccessfulResponse()
         throws Exception
  {
    final String[] referralURLs =
    {
      "ldap://ds1.example.com/",
      "ldap://ds2.example.com/"
    };

    final Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("5.6.7.8")
    };

    GeneratePasswordExtendedResult r = new GeneratePasswordExtendedResult(2,
         ResultCode.UNWILLING_TO_PERFORM,
         "The extended operation is not supported", "dc=matched,dc=dn",
         referralURLs, null, null, controls);

    assertEquals(r.getMessageID(), 2);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);

    assertNotNull(r.getDiagnosticMessage());
    assertEquals(r.getDiagnosticMessage(),
         "The extended operation is not supported");

    assertNotNull(r.getMatchedDN());
    assertDNsEqual(r.getMatchedDN(), "dc=matched,dc=dn");

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs(), referralURLs);

    assertNull(r.getOID());

    assertNull(r.getValue());

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls(), controls);

    assertNull(r.getPasswordPolicyDN());

    assertNotNull(r.getGeneratedPasswords());
    assertTrue(r.getGeneratedPasswords().isEmpty());

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());


    r = new GeneratePasswordExtendedResult(r);

    assertEquals(r.getMessageID(), 2);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);

    assertNotNull(r.getDiagnosticMessage());
    assertEquals(r.getDiagnosticMessage(),
         "The extended operation is not supported");

    assertNotNull(r.getMatchedDN());
    assertDNsEqual(r.getMatchedDN(), "dc=matched,dc=dn");

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs(), referralURLs);

    assertNull(r.getOID());

    assertNull(r.getValue());

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls(), controls);

    assertNull(r.getPasswordPolicyDN());

    assertNotNull(r.getGeneratedPasswords());
    assertTrue(r.getGeneratedPasswords().isEmpty());

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to decode a response that claims the
   * processing was successful but that did not include a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeSuccessResponseWithoutValue()
         throws Exception
  {
    new GeneratePasswordExtendedResult(new ExtendedResult(1,
         ResultCode.SUCCESS, null, null, null, null, null, null));
  }



  /**
   * Tests the behavior when trying to decode a response that claims the
   * processing was not successful but that does include a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNonSuccessResponseWithValue()
         throws Exception
  {
    new GeneratePasswordExtendedResult(new ExtendedResult(1,
         ResultCode.UNWILLING_TO_PERFORM, "Not supported", null, null,
         "1.3.6.1.4.1.30221.2.6.63", new ASN1OctetString("does not matter"),
         null));
  }



  /**
   * Tests the behavior when trying to decode a success response in which the
   * value cannot be decoded as an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeSuccessValueNotSequence()
         throws Exception
  {
    new GeneratePasswordExtendedResult(new ExtendedResult(1,
         ResultCode.SUCCESS, null, null, null, "1.3.6.1.4.1.30221.2.6.63",
         new ASN1OctetString("this is not an ASN.1 sequence"), null));
  }



  /**
   * Tests the behavior when trying to decode a success response that does not
   * actually contain any generated passwords.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeSuccessValueEmptyPasswords()
         throws Exception
  {
    new GeneratePasswordExtendedResult(new ExtendedResult(1,
         ResultCode.SUCCESS, null, null, null, "1.3.6.1.4.1.30221.2.6.63",
         new ASN1OctetString(
              new ASN1Sequence(
                   new ASN1OctetString("cn=Password Policy"),
                   new ASN1Sequence()).encode()),
         null));
  }
}
