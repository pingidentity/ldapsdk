/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
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
 * Copyright (C) 2014-2021 Ping Identity Corporation
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



import java.util.Arrays;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test coverage for the
 * {@code DIGESTMD5BindRequestProperties} class.
 */
public final class DIGESTMD5BindRequestPropertiesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests with a minimal set of properties with a string password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalProperties()
         throws Exception
  {
    final DIGESTMD5BindRequestProperties properties =
         new DIGESTMD5BindRequestProperties("u:auth.user", "password");

    assertNotNull(properties.getAuthenticationID());
    assertEquals(properties.getAuthenticationID(), "u:auth.user");

    assertNull(properties.getAuthorizationID());

    assertNotNull(properties.getPassword());
    assertEquals(properties.getPassword().stringValue(), "password");

    assertNull(properties.getRealm());

    assertNotNull(properties.getAllowedQoP());
    assertEquals(properties.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH));

    assertNotNull(properties.toString());
  }



  /**
   * Tests with a complete set of properties with a byte array password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompleteProperties()
         throws Exception
  {
    final DIGESTMD5BindRequestProperties properties =
         new DIGESTMD5BindRequestProperties("u:auth.user",
              "password".getBytes("UTF-8"));
    properties.setAuthorizationID("u:authz.user");
    properties.setRealm("test-realm");
    properties.setAllowedQoP(SASLQualityOfProtection.AUTH_CONF,
         SASLQualityOfProtection.AUTH_INT, SASLQualityOfProtection.AUTH);

    assertNotNull(properties.getAuthenticationID());
    assertEquals(properties.getAuthenticationID(), "u:auth.user");

    assertNotNull(properties.getAuthorizationID());
    assertEquals(properties.getAuthorizationID(), "u:authz.user");

    assertNotNull(properties.getPassword());
    assertEquals(properties.getPassword().stringValue(), "password");

    assertNotNull(properties.getRealm());
    assertEquals(properties.getRealm(), "test-realm");

    assertNotNull(properties.getAllowedQoP());
    assertEquals(properties.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH_CONF,
              SASLQualityOfProtection.AUTH_INT, SASLQualityOfProtection.AUTH));

    assertNotNull(properties.toString());
  }



  /**
   * Tests with a set of properties for anonymous authentication.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAnonymousProperties()
         throws Exception
  {
    final DIGESTMD5BindRequestProperties properties =
         new DIGESTMD5BindRequestProperties("dn:", (ASN1OctetString) null);

    assertNotNull(properties.getAuthenticationID());
    assertEquals(properties.getAuthenticationID(), "dn:");

    assertNull(properties.getAuthorizationID());

    assertNotNull(properties.getPassword());
    assertEquals(properties.getPassword().stringValue(), "");

    assertNull(properties.getRealm());

    assertNotNull(properties.getAllowedQoP());
    assertEquals(properties.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH));

    assertNotNull(properties.toString());
  }



  /**
   * Tests properties related to the authentication ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthenticationID()
         throws Exception
  {
    final DIGESTMD5BindRequestProperties properties =
         new DIGESTMD5BindRequestProperties("u:auth.1", "password");

    assertNotNull(properties.getAuthenticationID());
    assertEquals(properties.getAuthenticationID(), "u:auth.1");

    properties.setAuthenticationID("u:auth.2");
    assertEquals(properties.getAuthenticationID(), "u:auth.2");

    try
    {
      properties.setAuthenticationID(null);
      fail("Expected an exception when trying to set a null authentication ID");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests properties related to the authorization ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthorizationID()
         throws Exception
  {
    final DIGESTMD5BindRequestProperties properties =
         new DIGESTMD5BindRequestProperties("u:auth.id", "password");

    assertNull(properties.getAuthorizationID());

    properties.setAuthorizationID("u:authz.1");
    assertNotNull(properties.getAuthorizationID());
    assertEquals(properties.getAuthorizationID(), "u:authz.1");

    properties.setAuthorizationID("u:authz.2");
    assertNotNull(properties.getAuthorizationID());
    assertEquals(properties.getAuthorizationID(), "u:authz.2");

    properties.setAuthorizationID(null);
    assertNull(properties.getAuthorizationID());
  }



  /**
   * Tests properties related to the password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPassword()
         throws Exception
  {
    final DIGESTMD5BindRequestProperties properties =
         new DIGESTMD5BindRequestProperties("u:auth.id", "password");

    assertNotNull(properties.getPassword());
    assertEquals(properties.getPassword().stringValue(), "password");

    properties.setPassword("stringPassword");
    assertNotNull(properties.getPassword());
    assertEquals(properties.getPassword().stringValue(), "stringPassword");

    properties.setPassword((String) null);
    assertNotNull(properties.getPassword());
    assertEquals(properties.getPassword().stringValue(), "");

    properties.setPassword("passwordBytes".getBytes("UTF-8"));
    assertNotNull(properties.getPassword());
    assertEquals(properties.getPassword().stringValue(), "passwordBytes");

    properties.setPassword((byte[]) null);
    assertNotNull(properties.getPassword());
    assertEquals(properties.getPassword().stringValue(), "");

    properties.setPassword(new ASN1OctetString("octetStringPassword"));
    assertNotNull(properties.getPassword());
    assertEquals(properties.getPassword().stringValue(), "octetStringPassword");

    properties.setPassword((ASN1OctetString) null);
    assertNotNull(properties.getPassword());
    assertEquals(properties.getPassword().stringValue(), "");
  }



  /**
   * Tests properties related to the realm.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRealm()
         throws Exception
  {
    final DIGESTMD5BindRequestProperties properties =
         new DIGESTMD5BindRequestProperties("u:auth.id", "password");

    assertNull(properties.getRealm());

    properties.setRealm("realm1");
    assertNotNull(properties.getRealm());
    assertEquals(properties.getRealm(), "realm1");

    properties.setRealm("realm2");
    assertNotNull(properties.getRealm());
    assertEquals(properties.getRealm(), "realm2");

    properties.setRealm(null);
    assertNull(properties.getRealm());
  }



  /**
   * Tests properties related to the allowed qualities of protection.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllowedQoP()
         throws Exception
  {
    final DIGESTMD5BindRequestProperties properties =
         new DIGESTMD5BindRequestProperties("u:auth.id", "password");

    assertNotNull(properties.getAllowedQoP());
    assertEquals(properties.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH));

    properties.setAllowedQoP(SASLQualityOfProtection.AUTH_CONF);
    assertNotNull(properties.getAllowedQoP());
    assertEquals(properties.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH_CONF));

    properties.setAllowedQoP();
    assertNotNull(properties.getAllowedQoP());
    assertEquals(properties.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH));

    properties.setAllowedQoP(SASLQualityOfProtection.AUTH_CONF,
         SASLQualityOfProtection.AUTH_INT, SASLQualityOfProtection.AUTH);
    assertNotNull(properties.getAllowedQoP());
    assertEquals(properties.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH_CONF,
              SASLQualityOfProtection.AUTH_INT, SASLQualityOfProtection.AUTH));

    properties.setAllowedQoP((List<SASLQualityOfProtection>) null);
    assertNotNull(properties.getAllowedQoP());
    assertEquals(properties.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH));

    properties.setAllowedQoP(SASLQualityOfProtection.AUTH,
         SASLQualityOfProtection.AUTH_INT, SASLQualityOfProtection.AUTH_CONF);
    assertNotNull(properties.getAllowedQoP());
    assertEquals(properties.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH,
              SASLQualityOfProtection.AUTH_INT,
              SASLQualityOfProtection.AUTH_CONF));
  }
}
