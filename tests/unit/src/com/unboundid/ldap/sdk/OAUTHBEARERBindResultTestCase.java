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
package com.unboundid.ldap.sdk;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a set of test cases for the OAUTHBEARERBindResult class.
 */
public class OAUTHBEARERBindResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a success result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessResult()
         throws Exception
  {
    final BindResult initialBindResult = new BindResult(1, ResultCode.SUCCESS,
         null, null, null, null, null);

    final OAUTHBEARERBindResult bindResult =
         new OAUTHBEARERBindResult(initialBindResult);

    assertEquals(bindResult.getMessageID(), 1);

    assertNotNull(bindResult.getResultCode());
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);

    assertNull(bindResult.getDiagnosticMessage());

    assertNull(bindResult.getMatchedDN());

    assertNotNull(bindResult.getReferralURLs());
    assertEquals(bindResult.getReferralURLs().length, 0);

    assertNotNull(bindResult.getResponseControls());
    assertEquals(bindResult.getResponseControls().length, 0);

    assertNull(bindResult.getServerSASLCredentials());

    assertNotNull(bindResult.getInitialBindResult());
    assertEquals(bindResult.getInitialBindResult(), initialBindResult);

    assertNull(bindResult.getFinalBindResult());

    assertNull(bindResult.getFailureDetailsObject());

    assertNull(bindResult.getAuthorizationErrorCode());

    assertNotNull(bindResult.getScopes());
    assertTrue(bindResult.getScopes().isEmpty());

    assertNull(bindResult.getOpenIDConfigurationURL());

    assertNotNull(bindResult.toString());
  }



  /**
   * Tests the behavior for a failure result that does not include any server
   * SASL credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailureResultWithoutCredentials()
         throws Exception
  {
    final String[] referralURLs =
    {
      "ldap://ds1.example.com:389/o=no creds",
      "ldap://ds2.example.com:389/o=no creds"
    };

    final Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5")
    };

    final BindResult initialBindResult = new BindResult(2,
         ResultCode.INVALID_CREDENTIALS, "no creds diagnostic message",
         "o=no creds", referralURLs, controls, null);

    final OAUTHBEARERBindResult bindResult =
         new OAUTHBEARERBindResult(initialBindResult);

    assertEquals(bindResult.getMessageID(), 2);

    assertNotNull(bindResult.getResultCode());
    assertEquals(bindResult.getResultCode(), ResultCode.INVALID_CREDENTIALS);

    assertNotNull(bindResult.getDiagnosticMessage());
    assertEquals(bindResult.getDiagnosticMessage(),
         "no creds diagnostic message");

    assertNotNull(bindResult.getMatchedDN());
    assertDNsEqual(bindResult.getMatchedDN(), "o=no creds");

    assertNotNull(bindResult.getReferralURLs());
    assertEquals(bindResult.getReferralURLs().length, 2);

    assertNotNull(bindResult.getResponseControls());
    assertEquals(bindResult.getResponseControls().length, 2);

    assertNull(bindResult.getServerSASLCredentials());

    assertNotNull(bindResult.getInitialBindResult());
    assertEquals(bindResult.getInitialBindResult(), initialBindResult);

    assertNull(bindResult.getFinalBindResult());

    assertNull(bindResult.getFailureDetailsObject());

    assertNull(bindResult.getAuthorizationErrorCode());

    assertNotNull(bindResult.getScopes());
    assertTrue(bindResult.getScopes().isEmpty());

    assertNull(bindResult.getOpenIDConfigurationURL());

    assertNotNull(bindResult.toString());
  }



  /**
   * Tests the behavior for a failure result that includes server SASL
   * credentials with just an authorization error code.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailureResultWithCredentialsOnlyAuthzErrorCode()
         throws Exception
  {
    final String[] initialReferralURLs =
    {
      "ldap://ds1.example.com:389/o=initial"
    };

    final Control[] initialControls =
    {
      new Control("1.2.3.4")
    };

    final JSONObject initialFailureDetails = new JSONObject(
         new JSONField("status", "invalid_token"));
    final ASN1OctetString initialServerSASLCredentials =
         new ASN1OctetString(initialFailureDetails.toSingleLineString());

    final String[] finalReferralURLs =
    {
      "ldap://ds1.example.com:389/o=final"
    };

    final Control[] finalControls =
    {
      new Control("1.2.3.5")
    };



    final BindResult initialBindResult = new BindResult(3,
         ResultCode.SASL_BIND_IN_PROGRESS, "initial diagnostic message",
         "o=initial matched DN", initialReferralURLs, initialControls,
         initialServerSASLCredentials);
    final BindResult finalBindResult = new BindResult(4,
         ResultCode.INVALID_CREDENTIALS, "final diagnostic message",
         "o=final matched DN", finalReferralURLs, finalControls, null);
    final OAUTHBEARERBindResult bindResult = new OAUTHBEARERBindResult(
         initialBindResult, finalBindResult);

    assertEquals(bindResult.getMessageID(), 4);

    assertNotNull(bindResult.getResultCode());
    assertEquals(bindResult.getResultCode(), ResultCode.INVALID_CREDENTIALS);

    assertNotNull(bindResult.getDiagnosticMessage());
    assertEquals(bindResult.getDiagnosticMessage(), "final diagnostic message");

    assertNotNull(bindResult.getMatchedDN());
    assertDNsEqual(bindResult.getMatchedDN(), "o=final matched DN");

    assertNotNull(bindResult.getReferralURLs());
    assertEquals(bindResult.getReferralURLs().length, 1);
    assertEquals(bindResult.getReferralURLs()[0], finalReferralURLs[0]);

    assertNotNull(bindResult.getResponseControls());
    assertEquals(bindResult.getResponseControls().length, 1);
    assertEquals(bindResult.getResponseControls()[0], finalControls[0]);

    assertNotNull(bindResult.getServerSASLCredentials());
    assertTrue(bindResult.getServerSASLCredentials().equalsIgnoreType(
         initialServerSASLCredentials));

    assertNotNull(bindResult.getInitialBindResult());
    assertEquals(bindResult.getInitialBindResult(), initialBindResult);

    assertNotNull(bindResult.getFinalBindResult());
    assertEquals(bindResult.getFinalBindResult(), finalBindResult);

    assertNotNull(bindResult.getFailureDetailsObject());
    assertEquals(bindResult.getFailureDetailsObject(), initialFailureDetails);

    assertNotNull(bindResult.getAuthorizationErrorCode());
    assertEquals(bindResult.getAuthorizationErrorCode(), "invalid_token");

    assertNotNull(bindResult.getScopes());
    assertTrue(bindResult.getScopes().isEmpty());

    assertNull(bindResult.getOpenIDConfigurationURL());

    assertNotNull(bindResult.toString());
  }



  /**
   * Tests the behavior for a failure result that includes server SASL
   * credentials that has all elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailureResultWithCredentials()
         throws Exception
  {
    final String[] initialReferralURLs =
    {
      "ldap://ds1.example.com:389/o=initial"
    };

    final Control[] initialControls =
    {
      new Control("1.2.3.4")
    };

    final JSONObject initialFailureDetails = new JSONObject(
         new JSONField("status", "invalid_token"),
         new JSONField("scope", "scope1 scope2 scope3"),
         new JSONField("openid-configuration",
              "https://openid.example.com/config"),
         new JSONField("some-other-field", "foo"));
    final ASN1OctetString initialServerSASLCredentials =
         new ASN1OctetString(initialFailureDetails.toSingleLineString());

    final String[] finalReferralURLs =
    {
      "ldap://ds1.example.com:389/o=final"
    };

    final Control[] finalControls =
    {
      new Control("1.2.3.5")
    };



    final BindResult initialBindResult = new BindResult(3,
         ResultCode.SASL_BIND_IN_PROGRESS, "initial diagnostic message",
         "o=initial matched DN", initialReferralURLs, initialControls,
         initialServerSASLCredentials);
    final BindResult finalBindResult = new BindResult(4,
         ResultCode.INVALID_CREDENTIALS, "final diagnostic message",
         "o=final matched DN", finalReferralURLs, finalControls, null);
    final OAUTHBEARERBindResult bindResult = new OAUTHBEARERBindResult(
         initialBindResult, finalBindResult);

    assertEquals(bindResult.getMessageID(), 4);

    assertNotNull(bindResult.getResultCode());
    assertEquals(bindResult.getResultCode(), ResultCode.INVALID_CREDENTIALS);

    assertNotNull(bindResult.getDiagnosticMessage());
    assertEquals(bindResult.getDiagnosticMessage(), "final diagnostic message");

    assertNotNull(bindResult.getMatchedDN());
    assertDNsEqual(bindResult.getMatchedDN(), "o=final matched DN");

    assertNotNull(bindResult.getReferralURLs());
    assertEquals(bindResult.getReferralURLs().length, 1);
    assertEquals(bindResult.getReferralURLs()[0], finalReferralURLs[0]);

    assertNotNull(bindResult.getResponseControls());
    assertEquals(bindResult.getResponseControls().length, 1);
    assertEquals(bindResult.getResponseControls()[0], finalControls[0]);

    assertNotNull(bindResult.getServerSASLCredentials());
    assertTrue(bindResult.getServerSASLCredentials().equalsIgnoreType(
         initialServerSASLCredentials));

    assertNotNull(bindResult.getInitialBindResult());
    assertEquals(bindResult.getInitialBindResult(), initialBindResult);

    assertNotNull(bindResult.getFinalBindResult());
    assertEquals(bindResult.getFinalBindResult(), finalBindResult);

    assertNotNull(bindResult.getFailureDetailsObject());
    assertEquals(bindResult.getFailureDetailsObject(), initialFailureDetails);

    assertNotNull(bindResult.getAuthorizationErrorCode());
    assertEquals(bindResult.getAuthorizationErrorCode(), "invalid_token");

    assertNotNull(bindResult.getScopes());
    assertFalse(bindResult.getScopes().isEmpty());
    assertEquals(bindResult.getScopes(),
         StaticUtils.setOf("scope1", "scope2", "scope3"));

    assertNotNull(bindResult.getOpenIDConfigurationURL());
    assertEquals(bindResult.getOpenIDConfigurationURL(),
         "https://openid.example.com/config");

    assertNotNull(bindResult.toString());
  }



  /**
   * Tests the behavior for a failure result that includes server SASL
   * credentials that can't be parsed as a JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailureResultWithMalformedCredentials()
         throws Exception
  {
    final String[] initialReferralURLs =
    {
      "ldap://ds1.example.com:389/o=initial"
    };

    final Control[] initialControls =
    {
      new Control("1.2.3.4")
    };

    final ASN1OctetString initialServerSASLCredentials =
         new ASN1OctetString("malformed");

    final String[] finalReferralURLs =
    {
      "ldap://ds1.example.com:389/o=final"
    };

    final Control[] finalControls =
    {
      new Control("1.2.3.5")
    };



    final BindResult initialBindResult = new BindResult(3,
         ResultCode.SASL_BIND_IN_PROGRESS, "initial diagnostic message",
         "o=initial matched DN", initialReferralURLs, initialControls,
         initialServerSASLCredentials);
    final BindResult finalBindResult = new BindResult(4,
         ResultCode.INVALID_CREDENTIALS, "final diagnostic message",
         "o=final matched DN", finalReferralURLs, finalControls, null);
    final OAUTHBEARERBindResult bindResult = new OAUTHBEARERBindResult(
         initialBindResult, finalBindResult);

    assertEquals(bindResult.getMessageID(), 4);

    assertNotNull(bindResult.getResultCode());
    assertEquals(bindResult.getResultCode(), ResultCode.INVALID_CREDENTIALS);

    assertNotNull(bindResult.getDiagnosticMessage());
    assertEquals(bindResult.getDiagnosticMessage(), "final diagnostic message");

    assertNotNull(bindResult.getMatchedDN());
    assertDNsEqual(bindResult.getMatchedDN(), "o=final matched DN");

    assertNotNull(bindResult.getReferralURLs());
    assertEquals(bindResult.getReferralURLs().length, 1);
    assertEquals(bindResult.getReferralURLs()[0], finalReferralURLs[0]);

    assertNotNull(bindResult.getResponseControls());
    assertEquals(bindResult.getResponseControls().length, 1);
    assertEquals(bindResult.getResponseControls()[0], finalControls[0]);

    assertNotNull(bindResult.getServerSASLCredentials());
    assertTrue(bindResult.getServerSASLCredentials().equalsIgnoreType(
         initialServerSASLCredentials));

    assertNotNull(bindResult.getInitialBindResult());
    assertEquals(bindResult.getInitialBindResult(), initialBindResult);

    assertNotNull(bindResult.getFinalBindResult());
    assertEquals(bindResult.getFinalBindResult(), finalBindResult);

    assertNull(bindResult.getFailureDetailsObject());

    assertNull(bindResult.getAuthorizationErrorCode());

    assertNotNull(bindResult.getScopes());
    assertTrue(bindResult.getScopes().isEmpty());

    assertNull(bindResult.getOpenIDConfigurationURL());

    assertNotNull(bindResult.toString());
  }
}
