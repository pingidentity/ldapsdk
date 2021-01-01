/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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
package com.unboundid.util;



import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.ANONYMOUSBindRequest;
import com.unboundid.ldap.sdk.BindRequest;
import com.unboundid.ldap.sdk.CRAMMD5BindRequest;
import com.unboundid.ldap.sdk.DIGESTMD5BindRequest;
import com.unboundid.ldap.sdk.EXTERNALBindRequest;
import com.unboundid.ldap.sdk.GSSAPIBindRequest;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.OAUTHBEARERBindRequest;
import com.unboundid.ldap.sdk.PLAINBindRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SASLQualityOfProtection;
import com.unboundid.ldap.sdk.SCRAMSHA1BindRequest;
import com.unboundid.ldap.sdk.SCRAMSHA256BindRequest;
import com.unboundid.ldap.sdk.SCRAMSHA512BindRequest;
import com.unboundid.ldap.sdk.examples.LDAPSearch;
import com.unboundid.ldap.sdk.unboundidds.SingleUseTOTPBindRequest;
import com.unboundid.ldap.sdk.unboundidds.
            UnboundIDCertificatePlusPasswordBindRequest;
import com.unboundid.ldap.sdk.unboundidds.UnboundIDDeliveredOTPBindRequest;
import com.unboundid.ldap.sdk.unboundidds.UnboundIDTOTPBindRequest;
import com.unboundid.ldap.sdk.unboundidds.UnboundIDYubiKeyOTPBindRequest;



/**
 * This class provides a set of test cases for the {@code SASLUtils} class.
 */
public final class SASLUtilsTestCase
       extends LDAPSDKTestCase
{
  /**
   * Test the method that can be used to obtain information about the set of
   * supported SASL mechanisms.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSupportedMechanisms()
         throws Exception
  {
    final List<SASLMechanismInfo> mechList =
         SASLUtils.getSupportedSASLMechanisms();
    assertNotNull(mechList);
    assertFalse(mechList.isEmpty());

    for (final SASLMechanismInfo i : mechList)
    {
      assertNotNull(i);

      assertNotNull(i.getName());
      assertNotNull(SASLUtils.getSASLMechanismInfo(i.getName()));
      assertNotNull(SASLUtils.getSASLMechanismInfo(i.getName().toLowerCase()));
      assertNotNull(SASLUtils.getSASLMechanismInfo(i.getName().toUpperCase()));

      assertNotNull(i.getDescription());

      i.acceptsPassword();

      i.requiresPassword();

      assertNotNull(i.getOptions());
      for (final SASLOption o : i.getOptions())
      {
        assertNotNull(o);

        assertNotNull(o.getName());

        assertNotNull(o.getDescription());

        assertNotNull(o.isRequired());

        assertNotNull(o.isMultiValued());

        assertNotNull(o.toString());
      }

      assertNotNull(i.toString());
    }
  }



  /**
   * Tests the {@code getSASLMechanismInfo} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSASLMechanismInfo()
         throws Exception
  {
    final String[] mechanisms =
    {
      ANONYMOUSBindRequest.ANONYMOUS_MECHANISM_NAME,
      CRAMMD5BindRequest.CRAMMD5_MECHANISM_NAME,
      DIGESTMD5BindRequest.DIGESTMD5_MECHANISM_NAME,
      EXTERNALBindRequest.EXTERNAL_MECHANISM_NAME,
      GSSAPIBindRequest.GSSAPI_MECHANISM_NAME,
      OAUTHBEARERBindRequest.OAUTHBEARER_MECHANISM_NAME,
      PLAINBindRequest.PLAIN_MECHANISM_NAME,
      SCRAMSHA1BindRequest.SCRAM_SHA_1_MECHANISM_NAME,
      SCRAMSHA256BindRequest.SCRAM_SHA_256_MECHANISM_NAME,
      SCRAMSHA512BindRequest.SCRAM_SHA_512_MECHANISM_NAME,
      UnboundIDCertificatePlusPasswordBindRequest.
           UNBOUNDID_CERT_PLUS_PW_MECHANISM_NAME,
      UnboundIDDeliveredOTPBindRequest.UNBOUNDID_DELIVERED_OTP_MECHANISM_NAME,
      UnboundIDTOTPBindRequest.UNBOUNDID_TOTP_MECHANISM_NAME,
      UnboundIDYubiKeyOTPBindRequest.UNBOUNDID_YUBIKEY_OTP_MECHANISM_NAME
    };

    assertNotNull(SASLUtils.getSupportedSASLMechanisms());
    assertEquals(SASLUtils.getSupportedSASLMechanisms().size(),
         mechanisms.length);

    for (final String mech : mechanisms)
    {
      assertNotNull(SASLUtils.getSASLMechanismInfo(mech));
      assertEquals(SASLUtils.getSASLMechanismInfo(mech).getName(), mech);

      assertNotNull(SASLUtils.getSASLMechanismInfo(mech.toUpperCase()));
      assertEquals(SASLUtils.getSASLMechanismInfo(mech.toUpperCase()).getName(),
           mech);

      assertNotNull(SASLUtils.getSASLMechanismInfo(mech.toLowerCase()));
      assertEquals(SASLUtils.getSASLMechanismInfo(mech.toLowerCase()).getName(),
           mech);
    }

    assertNull(SASLUtils.getSASLMechanismInfo("undefined"));
    assertNull(SASLUtils.getSASLMechanismInfo("UNDEFINED"));
  }



  /**
   * Tests the case in which no mechanism is specified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testNoMechanism()
         throws Exception
  {
    SASLUtils.createBindRequest(null, (String) null, null,
         Arrays.asList("trace=foo"));
  }



  /**
   * Tests the case in which the mechanism is specified as an argument rather
   * than a SASL option.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMechNotAsOption()
         throws Exception
  {
    final BindRequest bindRequest = SASLUtils.createBindRequest(null,
         (String) null, "ANONYMOUS", (List<String>) null);

    assertNotNull(bindRequest);

    assertTrue(bindRequest instanceof ANONYMOUSBindRequest);

    final ANONYMOUSBindRequest anonymousBind =
         (ANONYMOUSBindRequest) bindRequest;
    assertNull(anonymousBind.getTraceString());
  }



  /**
   * Tests the case in which the mechanism is specified only as a SASL option.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMechOnlyAsOption()
         throws Exception
  {
    final BindRequest bindRequest = SASLUtils.createBindRequest(null,
         (String) null, null, "mech=ANONYMOUS");

    assertNotNull(bindRequest);

    assertTrue(bindRequest instanceof ANONYMOUSBindRequest);

    final ANONYMOUSBindRequest anonymousBind =
         (ANONYMOUSBindRequest) bindRequest;
    assertNull(anonymousBind.getTraceString());
  }



  /**
   * Tests the case in which the same mechanism is specified as both an argument
   * and an option.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSameMechAsArgumentAndOption()
         throws Exception
  {
    final BindRequest bindRequest = SASLUtils.createBindRequest(null,
         (String) null, "ANONYMOUS", "mech=ANONYMOUS");

    assertNotNull(bindRequest);

    assertTrue(bindRequest instanceof ANONYMOUSBindRequest);

    final ANONYMOUSBindRequest anonymousBind =
         (ANONYMOUSBindRequest) bindRequest;
    assertNull(anonymousBind.getTraceString());
  }



  /**
   * Tests the case in which different mechanisms are specified as an argument
   * and an option.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDifferentMechsAsArgumentAndOption()
         throws Exception
  {
    SASLUtils.createBindRequest(null, (String) null, "ANONYMOUS",
         "mech=EXTERNAL");
  }



  /**
   * Tests the case in which an unsupported mechanism is specified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testUnsupportedMechanism()
         throws Exception
  {
    SASLUtils.createBindRequest(null, (String) null, "UNSUPPORTED");
  }



  /**
   * Tests the case in which an option does not contain an equal sign.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testOptionWithoutEquals()
         throws Exception
  {
    SASLUtils.createBindRequest(null, (String) null, null, "mech=ANONYMOUS",
         "trace");
  }



  /**
   * Tests the case in which an option starts with an equal sign.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testOptionStartsWithEquals()
         throws Exception
  {
    SASLUtils.createBindRequest(null, (String) null, null, "mech=ANONYMOUS",
         "=foo");
  }



  /**
   * Tests the case in which multiple values are provided for the same SASL
   * option.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testMultiValuedOption()
         throws Exception
  {
    SASLUtils.createBindRequest(null, (String) null, null, "mech=ANONYMOUS",
         "mech=ANONYMOUS");
  }



  /**
   * Tests the ability to create an ANONYMOUS bind without the trace option.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testANONYMOUSWithoutTrace()
         throws Exception
  {
    final BindRequest bindRequest = SASLUtils.createBindRequest(null,
         (String) null, null, "mech=ANONYMOUS");

    assertNotNull(bindRequest);

    assertTrue(bindRequest instanceof ANONYMOUSBindRequest);

    final ANONYMOUSBindRequest anonymousBind =
         (ANONYMOUSBindRequest) bindRequest;
    assertNull(anonymousBind.getTraceString());
  }



  /**
   * Tests the ability to create an ANONYMOUS bind with the trace option.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testANONYMOUSWithTrace()
         throws Exception
  {
    final BindRequest bindRequest = SASLUtils.createBindRequest(null,
         (byte[]) null, null, "mech=ANONYMOUS", "trace=This is a test");

    assertNotNull(bindRequest);

    assertTrue(bindRequest instanceof ANONYMOUSBindRequest);

    final ANONYMOUSBindRequest anonymousBind =
         (ANONYMOUSBindRequest) bindRequest;
    assertNotNull(anonymousBind.getTraceString());
    assertEquals(anonymousBind.getTraceString(), "This is a test");
  }



  /**
   * Tests the ability to create an ANONYMOUS bind that includes a password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testANONYMOUSWithPassword()
         throws Exception
  {
    SASLUtils.createBindRequest(null, "password", null, "mech=ANONYMOUS");
  }



  /**
   * Tests the ability to create an ANONYMOUS bind that includes an invalid
   * option.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testANONYMOUSInvalidOption()
         throws Exception
  {
    SASLUtils.createBindRequest(null, (String) null, null, "mech=ANONYMOUS",
         "invalid=foo");
  }



  /**
   * Tests the ability to create a valid CRAM-MD5 bind request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidCRAMMD5()
         throws Exception
  {
    final BindRequest bindRequest = SASLUtils.createBindRequest(null,
         "password", null, "mech=CRAM-MD5", "authID=u:test.user");

    assertNotNull(bindRequest);

    assertTrue(bindRequest instanceof CRAMMD5BindRequest);

    final CRAMMD5BindRequest cramMD5Bind =
         (CRAMMD5BindRequest) bindRequest;

    assertNotNull(cramMD5Bind.getAuthenticationID());
    assertEquals(cramMD5Bind.getAuthenticationID(), "u:test.user");

    assertNotNull(cramMD5Bind.getPasswordString());
    assertEquals(cramMD5Bind.getPasswordString(), "password");
  }



  /**
   * Tests the behavior when trying to create a CRAM-MD5 bind request without a
   * password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testCRAMMD5WithoutPassword()
         throws Exception
  {
    SASLUtils.createBindRequest(null, (String) null, null, "mech=CRAM-MD5",
         "authID=u:test.user");
  }



  /**
   * Tests the behavior when trying to create a CRAM-MD5 bind request without an
   * authID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testCRAMMD5WithoutAuthID()
         throws Exception
  {
    SASLUtils.createBindRequest(null, "password", null, "mech=CRAM-MD5");
  }



  /**
   * Tests the behavior when trying to create a CRAM-MD5 bind request with an
   * unsupported option.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testCRAMMD5WithUnsupportedOption()
         throws Exception
  {
    SASLUtils.createBindRequest(null, StaticUtils.getBytes("password"), null,
         "mech=CRAM-MD5", "authID=u:test.user", "authzID=u:another.user");
  }



  /**
   * Tests the ability to create a valid DIGEST-MD5 bind request with a minimal
   * set of properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidDIGESTMD5WithMinimalProperties()
         throws Exception
  {
    final BindRequest bindRequest = SASLUtils.createBindRequest(null,
         "password", null, "mech=DIGEST-MD5", "authID=u:test.user");

    assertNotNull(bindRequest);

    assertTrue(bindRequest instanceof DIGESTMD5BindRequest);

    final DIGESTMD5BindRequest digestMD5Bind =
         (DIGESTMD5BindRequest) bindRequest;

    assertNotNull(digestMD5Bind.getAuthenticationID());
    assertEquals(digestMD5Bind.getAuthenticationID(), "u:test.user");

    assertNotNull(digestMD5Bind.getPasswordString());
    assertEquals(digestMD5Bind.getPasswordString(), "password");

    assertNull(digestMD5Bind.getAuthorizationID());

    assertNull(digestMD5Bind.getRealm());

    assertNotNull(digestMD5Bind.getAllowedQoP());
    assertEquals(digestMD5Bind.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH));
  }



  /**
   * Tests the ability to create a valid DIGEST-MD5 bind request with a full set
   * of properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidDIGESTMD5WithAllProperties()
         throws Exception
  {
    final BindRequest bindRequest = SASLUtils.createBindRequest(null,
         "password", null, "mech=DIGEST-MD5", "authID=u:test.user",
         "realm=example.com", "authzID=u:another.user",
         "qop=auth-conf,auth-int,auth");

    assertNotNull(bindRequest);

    assertTrue(bindRequest instanceof DIGESTMD5BindRequest);

    final DIGESTMD5BindRequest digestMD5Bind =
         (DIGESTMD5BindRequest) bindRequest;

    assertNotNull(digestMD5Bind.getAuthenticationID());
    assertEquals(digestMD5Bind.getAuthenticationID(), "u:test.user");

    assertNotNull(digestMD5Bind.getPasswordString());
    assertEquals(digestMD5Bind.getPasswordString(), "password");

    assertNotNull(digestMD5Bind.getAuthorizationID());
    assertEquals(digestMD5Bind.getAuthorizationID(), "u:another.user");

    assertNotNull(digestMD5Bind.getRealm());
    assertEquals(digestMD5Bind.getRealm(), "example.com");

    assertNotNull(digestMD5Bind.getAllowedQoP());
    assertEquals(digestMD5Bind.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH_CONF,
              SASLQualityOfProtection.AUTH_INT,
              SASLQualityOfProtection.AUTH));
  }



  /**
   * Tests the ability to create a DIGEST-MD5 bind request without a password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDIGESTMD5WithoutPassword()
         throws Exception
  {
    SASLUtils.createBindRequest(null, (String) null, null, "mech=DIGEST-MD5",
         "authID=u:test.user");
  }



  /**
   * Tests the ability to create a DIGEST-MD5 bind request without an authID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDIGESTMD5WithoutAuthID()
         throws Exception
  {
    SASLUtils.createBindRequest(null, "password", null, "mech=DIGEST-MD5");
  }



  /**
   * Tests the ability to create a DIGEST-MD5 bind request with an unsupported
   * option.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDIGESTMD5WithUnsupportedOption()
         throws Exception
  {
    SASLUtils.createBindRequest(null, "password", null, "mech=DIGEST-MD5",
         "authID=u:test.user", "unsupported=foo");
  }




  /**
   * Tests the ability to create a valid EXTERNAL bind request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidEXTERNALBind()
         throws Exception
  {
    final BindRequest bindRequest = SASLUtils.createBindRequest(null,
         (String) null, null, "mech=EXTERNAL");

    assertNotNull(bindRequest);

    assertTrue(bindRequest instanceof EXTERNALBindRequest);
  }



  /**
   * Tests the behavior when trying to create an EXTERNAL bind request with a
   * password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testEXTERNALBindWithPassword()
         throws Exception
  {
    SASLUtils.createBindRequest(null, "password", null, "mech=EXTERNAL");
  }



  /**
   * Tests the behavior when trying to create an EXTERNAL bind request with a
   * password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testEXTERNALBindWithUnsupportedOption()
         throws Exception
  {
    SASLUtils.createBindRequest(null, (String) null, null, "mech=EXTERNAL",
         "unsupported=foo");
  }



  /**
   * Tests the ability to create a valid GSSAPI bind request with the minimal
   * set of options.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidGSSAPIBindMinimal()
         throws Exception
  {
    final BindRequest bindRequest = SASLUtils.createBindRequest(null,
         "password", null, "mech=GSSAPI", "authID=test.user@EXAMPLE.COM");

    assertNotNull(bindRequest);

    assertTrue(bindRequest instanceof GSSAPIBindRequest);

    final GSSAPIBindRequest gssapiBind = (GSSAPIBindRequest) bindRequest;

    assertNotNull(gssapiBind.getAuthenticationID());
    assertEquals(gssapiBind.getAuthenticationID(), "test.user@EXAMPLE.COM");

    assertNull(gssapiBind.getAuthorizationID());

    assertFalse(gssapiBind.enableGSSAPIDebugging());

    assertNotNull(gssapiBind.getConfigFilePath());

    assertNull(gssapiBind.getKDCAddress());

    assertNull(gssapiBind.getRealm());

    assertNotNull(gssapiBind.getAllowedQoP());
    assertEquals(gssapiBind.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH));

    assertNotNull(gssapiBind.getServicePrincipalProtocol());
    assertEquals(gssapiBind.getServicePrincipalProtocol(), "ldap");

    assertTrue(gssapiBind.useTicketCache());

    assertFalse(gssapiBind.requireCachedCredentials());

    assertNull(gssapiBind.getTicketCachePath());

    assertFalse(gssapiBind.renewTGT());
  }



  /**
   * Tests the ability to create a valid GSSAPI bind request with a full set of
   * options.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidGSSAPIBindAllOptions()
         throws Exception
  {
    final BindRequest bindRequest = SASLUtils.createBindRequest(null,
         (String) null, null, "mech=GSSAPI", "authID=test.user@EXAMPLE.COM",
         "authzID=another.user@EXAMPLE.COM", "configFile=/tmp/jaas.conf",
         "debug=true", "kdcAddress=kdc.example.com", "protocol=foo",
         "realm=EXAMPLE.COM", "renewTGT=true", "useTicketCache=true",
         "ticketCache=/tmp/ticket.cache", "requireCache=true",
         "qop=auth-conf");

    assertNotNull(bindRequest);

    assertTrue(bindRequest instanceof GSSAPIBindRequest);

    final GSSAPIBindRequest gssapiBind = (GSSAPIBindRequest) bindRequest;

    assertNotNull(gssapiBind.getAuthenticationID());
    assertEquals(gssapiBind.getAuthenticationID(), "test.user@EXAMPLE.COM");

    assertNotNull(gssapiBind.getAuthorizationID());
    assertEquals(gssapiBind.getAuthorizationID(), "another.user@EXAMPLE.COM");

    assertTrue(gssapiBind.enableGSSAPIDebugging());

    assertNotNull(gssapiBind.getConfigFilePath());
    assertEquals(gssapiBind.getConfigFilePath(), "/tmp/jaas.conf");

    assertNotNull(gssapiBind.getKDCAddress());
    assertEquals(gssapiBind.getKDCAddress(), "kdc.example.com");

    assertNotNull(gssapiBind.getRealm());
    assertEquals(gssapiBind.getRealm(), "EXAMPLE.COM");

    assertNotNull(gssapiBind.getAllowedQoP());
    assertEquals(gssapiBind.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH_CONF));

    assertNotNull(gssapiBind.getServicePrincipalProtocol());
    assertEquals(gssapiBind.getServicePrincipalProtocol(), "foo");

    assertTrue(gssapiBind.useTicketCache());

    assertTrue(gssapiBind.requireCachedCredentials());

    assertNotNull(gssapiBind.getTicketCachePath());
    assertEquals(gssapiBind.getTicketCachePath(), "/tmp/ticket.cache");

    assertTrue(gssapiBind.renewTGT());
  }



  /**
   * Tests the ability to create a valid GSSAPI bind request with a missing
   * password when it should be required.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testValidGSSAPIBindMissingRequiredPassword()
         throws Exception
  {
    SASLUtils.createBindRequest(null, (String) null, null, "mech=GSSAPI",
         "authID=test.user@EXAMPLE.COM");
  }



  /**
   * Tests the ability to create a valid GSSAPI bind request with a missing
   * authID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testValidGSSAPIBindMissingAuthID()
         throws Exception
  {
    SASLUtils.createBindRequest(null, "password", null, "mech=GSSAPI");
  }



  /**
   * Tests the ability to create a valid GSSAPI bind request with an unsupported
   * option.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testValidGSSAPIBindUnsupportedOption()
         throws Exception
  {
    SASLUtils.createBindRequest(null, "password", null, "mech=GSSAPI",
         "authID=test.user@EXAMPLE.COM", "unsupported=foo");
  }



  /**
   * Tests the ability to create a valid OAUTHBEARER bind request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidOAUTHBEARERBind()
         throws Exception
  {
    final BindRequest bindRequest = SASLUtils.createBindRequest(null,
         (String) null, null, "mech=OAUTHBEARER", "accessToken=abcdefg");

    assertNotNull(bindRequest);

    assertTrue(bindRequest instanceof OAUTHBEARERBindRequest);

    final OAUTHBEARERBindRequest oAuthBearerBind =
         (OAUTHBEARERBindRequest) bindRequest;

    assertNotNull(oAuthBearerBind.getAccessToken());
    assertEquals(oAuthBearerBind.getAccessToken(), "abcdefg");
  }



  /**
   * Tests the behavior when trying to create an OAUTHBEARER bind request
   * without providing an access token.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testOAUTHBEARERBindWithoutAccessToken()
         throws Exception
  {
    SASLUtils.createBindRequest(null, (byte[]) null, false, null, null,
         Collections.singletonList("mech=OAUTHBEARER"));
  }



  /**
   * Tests the behavior when trying to create an OAUTHBEARER bind request
   * with an invalid option.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testOAUTHBEARERBindWithInvalidOption()
         throws Exception
  {
    SASLUtils.createBindRequest(null, (byte[]) null, false, null, null,
         Arrays.asList("mech=OAUTHBEARER", "accessToken=abcdefgh",
              "invalid=foo"));
  }



  /**
   * Tests the ability to create a valid PLAIN bind request without an alternate
   * authorization ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidPLAINBindWithoutAuthzID()
         throws Exception
  {
    final BindRequest bindRequest = SASLUtils.createBindRequest(null,
         "password", null, "mech=PLAIN", "authID=u:test.user");

    assertNotNull(bindRequest);

    assertTrue(bindRequest instanceof PLAINBindRequest);

    final PLAINBindRequest plainBind = (PLAINBindRequest) bindRequest;

    assertNotNull(plainBind.getAuthenticationID());
    assertEquals(plainBind.getAuthenticationID(), "u:test.user");

    assertNull(plainBind.getAuthorizationID());
  }



  /**
   * Tests the ability to create a valid PLAIN bind request with an alternate
   * authorization ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidPLAINBindWithAuthzID()
         throws Exception
  {
    final BindRequest bindRequest = SASLUtils.createBindRequest(null,
         "password", null, "mech=PLAIN", "authID=u:test.user",
         "authzID=u:another.user");

    assertNotNull(bindRequest);

    assertTrue(bindRequest instanceof PLAINBindRequest);

    final PLAINBindRequest plainBind = (PLAINBindRequest) bindRequest;

    assertNotNull(plainBind.getAuthenticationID());
    assertEquals(plainBind.getAuthenticationID(), "u:test.user");

    assertNotNull(plainBind.getAuthorizationID());
    assertEquals(plainBind.getAuthorizationID(), "u:another.user");
  }



  /**
   * Tests the behavior when using a PLAIN bind request with a missing password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testPLAINBindMissingPassword()
         throws Exception
  {
    SASLUtils.createBindRequest(null, (String) null, null, "mech=PLAIN",
         "authID=u:test.user");
  }



  /**
   * Tests the behavior when using a PLAIN bind request with a missing authID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testPLAINBindMissingAuthID()
         throws Exception
  {
    SASLUtils.createBindRequest(null, "password", null, "mech=PLAIN");
  }



  /**
   * Tests the behavior when using a PLAIN bind request with an unsupported
   * option.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testPLAINBindUnsupportedOption()
         throws Exception
  {
    SASLUtils.createBindRequest(null, "password", null, "mech=PLAIN",
         "authID=u:test.user", "unsupported=foo");
  }



  /**
   * Tests the ability to create a valid SCRAM-SHA-1 bind request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidSCRAMSHA1Bind()
         throws Exception
  {
    final BindRequest bindRequest = SASLUtils.createBindRequest(null,
         "password", null, "mech=SCRAM-SHA-1", "username=jdoe");

    assertNotNull(bindRequest);

    assertTrue(bindRequest instanceof SCRAMSHA1BindRequest);

    final SCRAMSHA1BindRequest scramBind =
         (SCRAMSHA1BindRequest) bindRequest;

    assertNotNull(scramBind.getUsername());
    assertEquals(scramBind.getUsername(), "jdoe");

    assertNotNull(scramBind.getPasswordString());
    assertEquals(scramBind.getPasswordString(), "password");
  }



  /**
   * Tests the behavior when trying to create a SCRAM-SHA-1 bind request
   * without a username.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testSCRAMSHA1BindWithoutUsername()
         throws Exception
  {
    SASLUtils.createBindRequest(null, StaticUtils.getBytes("password"),
         false, null, null, Collections.singletonList("mech=SCRAM-SHA-1"));
  }



  /**
   * Tests the behavior when trying to create a SCRAM-SHA-1 bind request
   * without a password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testSCRAMSHA1BindWithoutPassword()
         throws Exception
  {
    SASLUtils.createBindRequest(null, (byte[]) null, false, null, null,
         Arrays.asList("mech=SCRAM-SHA-1", "username=jdoe"));
  }



  /**
   * Tests the behavior when trying to create a SCRAM-SHA-1 bind request
   * with an invalid otpion.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testSCRAMSHA1BindWithInvalidOption()
         throws Exception
  {
    SASLUtils.createBindRequest(null, StaticUtils.getBytes("password"),
         false, null, null,
         Arrays.asList("mech=SCRAM-SHA-1", "username=jdoe", "invalid=foo"));
  }



  /**
   * Tests the ability to create a valid SCRAM-SHA-256 bind request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidSCRAMSHA256Bind()
         throws Exception
  {
    final BindRequest bindRequest = SASLUtils.createBindRequest(null,
         "password", null, "mech=SCRAM-SHA-256", "username=jdoe");

    assertNotNull(bindRequest);

    assertTrue(bindRequest instanceof SCRAMSHA256BindRequest);

    final SCRAMSHA256BindRequest scramBind =
         (SCRAMSHA256BindRequest) bindRequest;

    assertNotNull(scramBind.getUsername());
    assertEquals(scramBind.getUsername(), "jdoe");

    assertNotNull(scramBind.getPasswordString());
    assertEquals(scramBind.getPasswordString(), "password");
  }



  /**
   * Tests the behavior when trying to create a SCRAM-SHA-256 bind request
   * without a username.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testSCRAMSHA256BindWithoutUsername()
         throws Exception
  {
    SASLUtils.createBindRequest(null, StaticUtils.getBytes("password"),
         false, null, null, Collections.singletonList("mech=SCRAM-SHA-256"));
  }



  /**
   * Tests the behavior when trying to create a SCRAM-SHA-256 bind request
   * without a password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testSCRAMSHA256BindWithoutPassword()
         throws Exception
  {
    SASLUtils.createBindRequest(null, (byte[]) null, false, null, null,
         Arrays.asList("mech=SCRAM-SHA-256", "username=jdoe"));
  }



  /**
   * Tests the behavior when trying to create a SCRAM-SHA-256 bind request
   * with an invalid otpion.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testSCRAMSHA256BindWithInvalidOption()
         throws Exception
  {
    SASLUtils.createBindRequest(null, StaticUtils.getBytes("password"),
         false, null, null,
         Arrays.asList("mech=SCRAM-SHA-256", "username=jdoe", "invalid=foo"));
  }



  /**
   * Tests the ability to create a valid SCRAM-SHA-512 bind request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidSCRAMSHA512Bind()
         throws Exception
  {
    final BindRequest bindRequest = SASLUtils.createBindRequest(null,
         "password", null, "mech=SCRAM-SHA-512", "username=jdoe");

    assertNotNull(bindRequest);

    assertTrue(bindRequest instanceof SCRAMSHA512BindRequest);

    final SCRAMSHA512BindRequest scramBind =
         (SCRAMSHA512BindRequest) bindRequest;

    assertNotNull(scramBind.getUsername());
    assertEquals(scramBind.getUsername(), "jdoe");

    assertNotNull(scramBind.getPasswordString());
    assertEquals(scramBind.getPasswordString(), "password");
  }



  /**
   * Tests the behavior when trying to create a SCRAM-SHA-512 bind request
   * without a username.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testSCRAMSHA512BindWithoutUsername()
         throws Exception
  {
    SASLUtils.createBindRequest(null, StaticUtils.getBytes("password"),
         false, null, null, Collections.singletonList("mech=SCRAM-SHA-512"));
  }



  /**
   * Tests the behavior when trying to create a SCRAM-SHA-512 bind request
   * without a password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testSCRAMSHA512BindWithoutPassword()
         throws Exception
  {
    SASLUtils.createBindRequest(null, (byte[]) null, false, null, null,
         Arrays.asList("mech=SCRAM-SHA-512", "username=jdoe"));
  }



  /**
   * Tests the behavior when trying to create a SCRAM-SHA-512 bind request
   * with an invalid otpion.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testSCRAMSHA512BindWithInvalidOption()
         throws Exception
  {
    SASLUtils.createBindRequest(null, StaticUtils.getBytes("password"),
         false, null, null,
         Arrays.asList("mech=SCRAM-SHA-512", "username=jdoe", "invalid=foo"));
  }




  /**
   * Tests the ability to create a valid UNBOUNDID-CERTIFICATE-PLUS-PASSWORD
   * bind request when a password was provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidCertificatePlusPasswordBindPWProvided()
         throws Exception
  {
    final BindRequest bindRequest = SASLUtils.createBindRequest(null,
         "password", null, "mech=UNBOUNDID-CERTIFICATE-PLUS-PASSWORD");

    assertNotNull(bindRequest);

    assertTrue(bindRequest instanceof
         UnboundIDCertificatePlusPasswordBindRequest);

    final UnboundIDCertificatePlusPasswordBindRequest certPlusPWBind =
         (UnboundIDCertificatePlusPasswordBindRequest) bindRequest;

    assertNotNull(certPlusPWBind.getPassword());
    assertEquals(certPlusPWBind.getPassword().stringValue(), "password");
  }




  /**
   * Tests the ability to create a valid UNBOUNDID-CERTIFICATE-PLUS-PASSWORD
   * bind request when a password must be obtained via prompt.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidCertificatePlusPasswordBindPWPrompted()
         throws Exception
  {
    final LDAPSearch tool = new LDAPSearch(null, null);

    final BindRequest bindRequest;
    try
    {
      PasswordReader.setTestReader(new BufferedReader(new InputStreamReader(
           new ByteArrayInputStream("password\n".getBytes("UTF-8")))));
      bindRequest = SASLUtils.createBindRequest(null, (byte[]) null, false,
           tool, null,
           Arrays.asList("mech=UNBOUNDID-CERTIFICATE-PLUS-PASSWORD"));
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }

    assertNotNull(bindRequest);

    assertTrue(bindRequest instanceof
         UnboundIDCertificatePlusPasswordBindRequest);

    final UnboundIDCertificatePlusPasswordBindRequest certPlusPWBind =
         (UnboundIDCertificatePlusPasswordBindRequest) bindRequest;

    assertNotNull(certPlusPWBind.getPassword());
    assertEquals(certPlusPWBind.getPassword().stringValue(), "password");
  }



  /**
   * Tests the behavior when trying to create an EXTERNAL bind request with a
   * password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testCertificatePlusPasswordBindWithUnsupportedOption()
         throws Exception
  {
    final BindRequest bindRequest = SASLUtils.createBindRequest(null,
         "password", null, "mech=UNBOUNDID-CERTIFICATE-PLUS-PASSWORD",
         "unsupported=foo");
  }



  /**
   * Tests the ability to create a valid UNBOUNDID-DELIVERED-OTP bind request
   * without an alternate authorization ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidDeliveredOTPBindWithoutAuthzID()
         throws Exception
  {
    final BindRequest bindRequest = SASLUtils.createBindRequest(null,
         (String) null, null, "mech=UNBOUNDID-DELIVERED-OTP",
         "authID=u:test.user", "otp=123456");

    assertNotNull(bindRequest);

    assertTrue(bindRequest instanceof UnboundIDDeliveredOTPBindRequest);

    final UnboundIDDeliveredOTPBindRequest otpBind =
         (UnboundIDDeliveredOTPBindRequest) bindRequest;

    assertNotNull(otpBind.getAuthenticationID());
    assertEquals(otpBind.getAuthenticationID(), "u:test.user");

    assertNull(otpBind.getAuthorizationID());

    assertNotNull(otpBind.getOneTimePassword());
    assertEquals(otpBind.getOneTimePassword(), "123456");
  }



  /**
   * Tests the ability to create a valid UNBOUNDID-DELIVERED-OTP bind request
   * with an alternate authorization ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidDeliveredOTPBindWithAuthzID()
         throws Exception
  {
    final BindRequest bindRequest = SASLUtils.createBindRequest(null,
         (String) null, null, "mech=UNBOUNDID-DELIVERED-OTP",
         "authID=u:test.user", "authzID=u:other.user", "otp=654321");

    assertNotNull(bindRequest);

    assertTrue(bindRequest instanceof UnboundIDDeliveredOTPBindRequest);

    final UnboundIDDeliveredOTPBindRequest otpBind =
         (UnboundIDDeliveredOTPBindRequest) bindRequest;

    assertNotNull(otpBind.getAuthenticationID());
    assertEquals(otpBind.getAuthenticationID(), "u:test.user");

    assertNotNull(otpBind.getAuthorizationID());
    assertEquals(otpBind.getAuthorizationID(), "u:other.user");

    assertNotNull(otpBind.getOneTimePassword());
    assertEquals(otpBind.getOneTimePassword(), "654321");
  }



  /**
   * Tests the behavior when trying to create an UNBOUNDID-DELIVERED-OTP bind
   * request without an authentication ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testValidDeliveredOTPBindWithoutAuthID()
         throws Exception
  {
    SASLUtils.createBindRequest(null, (String) null, null,
         "mech=UNBOUNDID-DELIVERED-OTP", "otp=123456");
  }



  /**
   * Tests the behavior when trying to create an UNBOUNDID-DELIVERED-OTP bind
   * request without a one-time password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testValidDeliveredOTPBindWithoutOTP()
         throws Exception
  {
    SASLUtils.createBindRequest(null, (String) null, null,
         "mech=UNBOUNDID-DELIVERED-OTP", "authID=u:test.user");
  }



  /**
   * Tests the behavior when trying to create an UNBOUNDID-DELIVERED-OTP bind
   * request without a static password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testValidDeliveredOTPBindWithStaticPassword()
         throws Exception
  {
    SASLUtils.createBindRequest(null, "password", null,
         "mech=UNBOUNDID-DELIVERED-OTP", "authID=u:test.user", "otp=123456");
  }



  /**
   * Tests the ability to create a valid UNBOUNDID-TOTP bind request without an
   * alternate authorization ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidTOTPBindWithoutAuthzID()
         throws Exception
  {
    final BindRequest bindRequest = SASLUtils.createBindRequest(null,
         "password", null, "mech=UNBOUNDID-TOTP",
         "authID=u:test.user", "totpPassword=123456");

    assertNotNull(bindRequest);

    assertTrue(bindRequest instanceof SingleUseTOTPBindRequest);

    final SingleUseTOTPBindRequest totpBind =
         (SingleUseTOTPBindRequest) bindRequest;

    assertNotNull(totpBind.getAuthenticationID());
    assertEquals(totpBind.getAuthenticationID(), "u:test.user");

    assertNull(totpBind.getAuthorizationID());

    assertNotNull(totpBind.getStaticPassword());
    assertEquals(totpBind.getStaticPassword().stringValue(), "password");

    assertNotNull(totpBind.getTOTPPassword());
    assertEquals(totpBind.getTOTPPassword(), "123456");
  }



  /**
   * Tests the ability to create a valid UNBOUNDID-TOTP bind request with an
   * alternate authorization ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidTOTPBindWithAuthzID()
         throws Exception
  {
    final BindRequest bindRequest = SASLUtils.createBindRequest(null,
         "password", null, "mech=UNBOUNDID-TOTP",
         "authID=u:test.user", "authzID=u:another.user", "totpPassword=123456",
         "promptForStaticPassword=false");

    assertNotNull(bindRequest);

    assertTrue(bindRequest instanceof SingleUseTOTPBindRequest);

    final SingleUseTOTPBindRequest totpBind =
         (SingleUseTOTPBindRequest) bindRequest;

    assertNotNull(totpBind.getAuthenticationID());
    assertEquals(totpBind.getAuthenticationID(), "u:test.user");

    assertNotNull(totpBind.getAuthorizationID());
    assertEquals(totpBind.getAuthorizationID(), "u:another.user");

    assertNotNull(totpBind.getStaticPassword());
    assertEquals(totpBind.getStaticPassword().stringValue(), "password");

    assertNotNull(totpBind.getTOTPPassword());
    assertEquals(totpBind.getTOTPPassword(), "123456");
  }



  /**
   * Tests the ability to create a valid UNBOUNDID-TOTP bind request when
   * prompting for the static password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidTOTPBindWithStaticPasswordPrompt()
         throws Exception
  {
    final LDAPSearch tool = new LDAPSearch(null, null);

    final BindRequest bindRequest;
    try
    {
      PasswordReader.setTestReader(new BufferedReader(new InputStreamReader(
           new ByteArrayInputStream("password\n".getBytes("UTF-8")))));
      bindRequest = SASLUtils.createBindRequest(null, (byte[]) null, false,
           tool, null,
           Arrays.asList("mech=UNBOUNDID-TOTP", "authID=u:test.user",
                "totpPassword=123456", "promptForStaticPassword=true"));
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }

    assertNotNull(bindRequest);

    assertTrue(bindRequest instanceof SingleUseTOTPBindRequest);

    final SingleUseTOTPBindRequest totpBind =
         (SingleUseTOTPBindRequest) bindRequest;

    assertNotNull(totpBind.getAuthenticationID());
    assertEquals(totpBind.getAuthenticationID(), "u:test.user");

    assertNull(totpBind.getAuthorizationID());

    assertNotNull(totpBind.getStaticPassword());
    assertEquals(totpBind.getStaticPassword().stringValue(), "password");

    assertNotNull(totpBind.getTOTPPassword());
    assertEquals(totpBind.getTOTPPassword(), "123456");
  }



  /**
   * Tests the behavior when trying to create an UNBOUNDID-TOTP bind request
   * without an authentication ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testTOTPBindMissingAuthID()
         throws Exception
  {
    SASLUtils.createBindRequest(null, "password", null,
         "mech=UNBOUNDID-TOTP", "totpPassword=123456");
  }



  /**
   * Tests the behavior when trying to create an UNBOUNDID-TOTP bind request
   * when configured to prompt for a static password when a password was already
   * provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testTOTPBindPromptForStaticPasswordWithPasswordProvided()
         throws Exception
  {
    SASLUtils.createBindRequest(null, "password", null,
         "mech=UNBOUNDID-TOTP", "authID=u:test.user", "totpPassword=123456",
         "promptForStaticPassword=true");
  }



  /**
   * Tests the behavior when trying to create an UNBOUNDID-TOTP bind request
   * with an invalid value for the promptForStaticPassword property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testTOTPBindBadPromptForStaticPassword()
         throws Exception
  {
    SASLUtils.createBindRequest(null, (String) null, null,
         "mech=UNBOUNDID-TOTP", "authID=u:test.user", "totpPassword=123456",
         "promptForStaticPassword=invalid");
  }



  /**
   * Tests the behavior when trying to create an UNBOUNDID-TOTP bind request
   * without a TOTP password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testTOTPBindMissingTOTPPassword()
         throws Exception
  {
    SASLUtils.createBindRequest(null, "password", null,
         "mech=UNBOUNDID-TOTP", "authID=u:test.user");
  }



  /**
   * Tests the ability to create a valid UNBOUNDID-YUBIKEY-OTP bind request
   * without an alternate authorization ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidYubiKeyOTPBindWithoutAuthzID()
         throws Exception
  {
    final BindRequest bindRequest = SASLUtils.createBindRequest(null,
         "password", null, "mech=UNBOUNDID-YUBIKEY-OTP",
         "authID=u:test.user", "otp=YubiKeyOTP");

    assertNotNull(bindRequest);

    assertTrue(bindRequest instanceof UnboundIDYubiKeyOTPBindRequest);

    final UnboundIDYubiKeyOTPBindRequest yubiKeyBind =
         (UnboundIDYubiKeyOTPBindRequest) bindRequest;

    assertNotNull(yubiKeyBind.getAuthenticationID());
    assertEquals(yubiKeyBind.getAuthenticationID(), "u:test.user");

    assertNull(yubiKeyBind.getAuthorizationID());

    assertNotNull(yubiKeyBind.getStaticPasswordString());
    assertEquals(yubiKeyBind.getStaticPasswordString(), "password");

    assertNotNull(yubiKeyBind.getYubiKeyOTP());
    assertEquals(yubiKeyBind.getYubiKeyOTP(), "YubiKeyOTP");
  }



  /**
   * Tests the ability to create a valid UNBOUNDID-YUBIKEY-OTP bind request with
   * an alternate authorization ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidYubiKeyOTPBindWithAuthzID()
         throws Exception
  {
    final BindRequest bindRequest = SASLUtils.createBindRequest(null,
         "password", null, "mech=UNBOUNDID-YUBIKEY-OTP",
         "authID=u:test.user", "authzID=u:another.user", "otp=YubiKeyOTP");

    assertNotNull(bindRequest);

    assertTrue(bindRequest instanceof UnboundIDYubiKeyOTPBindRequest);

    final UnboundIDYubiKeyOTPBindRequest yubiKeyBind =
         (UnboundIDYubiKeyOTPBindRequest) bindRequest;

    assertNotNull(yubiKeyBind.getAuthenticationID());
    assertEquals(yubiKeyBind.getAuthenticationID(), "u:test.user");

    assertNotNull(yubiKeyBind.getAuthorizationID());
    assertEquals(yubiKeyBind.getAuthorizationID(), "u:another.user");

    assertNotNull(yubiKeyBind.getStaticPasswordString());
    assertEquals(yubiKeyBind.getStaticPasswordString(), "password");

    assertNotNull(yubiKeyBind.getYubiKeyOTP());
    assertEquals(yubiKeyBind.getYubiKeyOTP(), "YubiKeyOTP");
  }



  /**
   * Tests the ability to create a valid UNBOUNDID-YUBIKEY-OTP bind request
   * when prompting for a static password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidYubiKeyOTPBindPromptForStaticPassword()
         throws Exception
  {
    final LDAPSearch tool = new LDAPSearch(null, null);

    final BindRequest bindRequest;
    try
    {
      PasswordReader.setTestReader(new BufferedReader(new InputStreamReader(
           new ByteArrayInputStream("password\n".getBytes("UTF-8")))));
      bindRequest = SASLUtils.createBindRequest(null, (byte[]) null, false,
           tool, null,
           Arrays.asList("mech=UNBOUNDID-YUBIKEY-OTP", "authID=u:test.user",
                "otp=YubiKeyOTP", "promptForStaticPassword=true"));
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }

    assertNotNull(bindRequest);

    assertTrue(bindRequest instanceof UnboundIDYubiKeyOTPBindRequest);

    final UnboundIDYubiKeyOTPBindRequest yubiKeyBind =
         (UnboundIDYubiKeyOTPBindRequest) bindRequest;

    assertNotNull(yubiKeyBind.getAuthenticationID());
    assertEquals(yubiKeyBind.getAuthenticationID(), "u:test.user");

    assertNull(yubiKeyBind.getAuthorizationID());

    assertNotNull(yubiKeyBind.getStaticPasswordString());
    assertEquals(yubiKeyBind.getStaticPasswordString(), "password");

    assertNotNull(yubiKeyBind.getYubiKeyOTP());
    assertEquals(yubiKeyBind.getYubiKeyOTP(), "YubiKeyOTP");
  }



  /**
   * Tests the behavior when trying to create an UNBOUNDID-YUBIKEY-OTP bind
   * request without an authentication ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testYubiKeyOTPBindMissingAuthID()
         throws Exception
  {
    SASLUtils.createBindRequest(null, "password", null,
         "mech=UNBOUNDID-YUBIKEY-OTP", "otp=YubiKeyOTP");
  }



  /**
   * Tests the behavior when trying to create an UNBOUNDID-YUBIKEY-OTP bind
   * request without a one-time password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testYubiKeyOTPBindMissingOTP()
         throws Exception
  {
    SASLUtils.createBindRequest(null, "password", null,
         "mech=UNBOUNDID-YUBIKEY-OTP", "authID=u:test.user");
  }



  /**
   * Tests the behavior when trying to create an UNBOUNDID-YUBIKEY-OTP bind
   * when prompting for a static password when a static password was already
   * given.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testYubiKeyOTPBindPromptForStaticPasswordWithPasswordProvided()
         throws Exception
  {
    SASLUtils.createBindRequest(null, "password", null,
         "mech=UNBOUNDID-YUBIKEY-OTP", "authID=u:test.user", "otp=YubiKeyOTP",
         "promptForStaticPassword=true");
  }



  /**
   * Tests the behavior when trying to create an UNBOUNDID-TOTP bind request
   * without a TOTP password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testYubiKeyOTPBindBadPromptForStaticPassword()
         throws Exception
  {
    SASLUtils.createBindRequest(null, (String) null, null,
         "mech=UNBOUNDID-YUBIKEY-OTP", "authID=u:test.user", "otp=YubiKeyOTP",
         "promptForStaticPassword=invalid");
  }



  /**
   * Provides test coverage for the {@code testBooleanValue} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetBooleanValue()
         throws Exception
  {
    final HashMap<String,String> m = new HashMap<String,String>(13);

    m.put("true", "true");
    m.put("t", "t");
    m.put("yes", "yes");
    m.put("y", "y");
    m.put("on", "on");
    m.put("1", "1");

    m.put("false", "false");
    m.put("f", "f");
    m.put("no", "no");
    m.put("n", "n");
    m.put("off", "off");
    m.put("0", "0");

    m.put("invalid", "invalid");

    assertTrue(SASLUtils.getBooleanValue(m, "missing", true));
    assertFalse(SASLUtils.getBooleanValue(m, "missing", false));

    assertTrue(SASLUtils.getBooleanValue(m, "true", false));
    assertTrue(SASLUtils.getBooleanValue(m, "t", false));
    assertTrue(SASLUtils.getBooleanValue(m, "yes", false));
    assertTrue(SASLUtils.getBooleanValue(m, "y", false));
    assertTrue(SASLUtils.getBooleanValue(m, "on", false));
    assertTrue(SASLUtils.getBooleanValue(m, "1", false));

    assertFalse(SASLUtils.getBooleanValue(m, "false", true));
    assertFalse(SASLUtils.getBooleanValue(m, "f", true));
    assertFalse(SASLUtils.getBooleanValue(m, "no", true));
    assertFalse(SASLUtils.getBooleanValue(m, "n", true));
    assertFalse(SASLUtils.getBooleanValue(m, "off", true));
    assertFalse(SASLUtils.getBooleanValue(m, "0", true));

    try
    {
      SASLUtils.getBooleanValue(m, "invalid", false);
      fail("Expected an exception with a malformed boolean value");
    }
    catch (final LDAPException le)
    {
      assertResultCodeEquals(le, ResultCode.PARAM_ERROR);
    }
  }



  /**
   * Provides test coverage for the methods that can be used to obtain usage
   * information for SASL options.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUsage()
         throws Exception
  {
    assertNotNull(SASLUtils.getUsageString(0));
    assertFalse(SASLUtils.getUsageString(0).isEmpty());

    assertNotNull(SASLUtils.getUsageString(80));
    assertFalse(SASLUtils.getUsageString(80).isEmpty());

    assertNotNull(SASLUtils.getUsageString("GSSAPI", 0));
    assertFalse(SASLUtils.getUsageString("GSSAPI", 0).isEmpty());

    assertNotNull(SASLUtils.getUsageString("GSSAPI", 80));
    assertFalse(SASLUtils.getUsageString("GSSAPI", 80).isEmpty());

    assertNotNull(SASLUtils.getUsageString("UNKNOWN", 0));
    assertFalse(SASLUtils.getUsageString("UNKNOWN", 0).isEmpty());

    assertNotNull(SASLUtils.getUsageString("UNKNOWN", 80));
    assertFalse(SASLUtils.getUsageString("UNKNOWN", 80).isEmpty());

    assertNotNull(SASLUtils.getUsage(0));
    assertFalse(SASLUtils.getUsage(0).isEmpty());

    assertNotNull(SASLUtils.getUsage(80));
    assertFalse(SASLUtils.getUsage(80).isEmpty());

    assertNotNull(SASLUtils.getUsage("GSSAPI", 0));
    assertFalse(SASLUtils.getUsage("GSSAPI", 0).isEmpty());

    assertNotNull(SASLUtils.getUsage("GSSAPI", 80));
    assertFalse(SASLUtils.getUsage("GSSAPI", 80).isEmpty());

    assertNotNull(SASLUtils.getUsage("UNKNOWN", 0));
    assertFalse(SASLUtils.getUsage("UNKNOWN", 0).isEmpty());

    assertNotNull(SASLUtils.getUsage("UNKNOWN", 80));
    assertFalse(SASLUtils.getUsage("UNKNOWN", 80).isEmpty());
  }
}
