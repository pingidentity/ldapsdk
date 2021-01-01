/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
package com.unboundid.util.json;



import java.io.File;
import java.util.Arrays;
import java.util.Collections;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.CRAMMD5BindRequest;
import com.unboundid.ldap.sdk.DIGESTMD5BindRequest;
import com.unboundid.ldap.sdk.EXTERNALBindRequest;
import com.unboundid.ldap.sdk.GSSAPIBindRequest;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.PLAINBindRequest;
import com.unboundid.ldap.sdk.SASLQualityOfProtection;
import com.unboundid.ldap.sdk.SimpleBindRequest;



/**
 * This class provides a set of test cases for the authentication details class.
 */
public final class AuthenticationDetailsTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for the case in which the JSON object does not have the
   * authentication-details field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoDetails()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNull(spec.getBindRequest());
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that is an empty JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testEmptyDetails()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject()));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of none.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthTypeNone()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "none"))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNull(spec.getBindRequest());
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of simple
   * with empty DN and password values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthTypeSimpleAnonymous()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "simple"),
              new JSONField("dn", ""),
              new JSONField("password", ""))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNotNull(spec.getBindRequest());
    assertTrue(spec.getBindRequest() instanceof SimpleBindRequest);

    final SimpleBindRequest bindRequest =
         (SimpleBindRequest) spec.getBindRequest();
    assertDNsEqual(bindRequest.getBindDN(), "");
    assertEquals(bindRequest.getPassword().stringValue(), "");
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of simple
   * with a DN and a directly-provided password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthTypeSimpleDirectPassword()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "simple"),
              new JSONField("dn", "uid=john.doe,ou=People,dc=example,dc=com"),
              new JSONField("password", "ThePassword"))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNotNull(spec.getBindRequest());
    assertTrue(spec.getBindRequest() instanceof SimpleBindRequest);

    final SimpleBindRequest bindRequest =
         (SimpleBindRequest) spec.getBindRequest();
    assertDNsEqual(bindRequest.getBindDN(),
         "uid=john.doe,ou=People,dc=example,dc=com");
    assertEquals(bindRequest.getPassword().stringValue(), "ThePassword");
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of simple
   * with a DN and a password specified via a file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthTypeSimplePasswordFromFile()
         throws Exception
  {
    final File passwordFile = createTempFile("ReadFromFile");

    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "simple"),
              new JSONField("dn", "uid=john.doe,ou=People,dc=example,dc=com"),
              new JSONField("password-file", passwordFile.getAbsolutePath()))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNotNull(spec.getBindRequest());
    assertTrue(spec.getBindRequest() instanceof SimpleBindRequest);

    final SimpleBindRequest bindRequest =
         (SimpleBindRequest) spec.getBindRequest();
    assertDNsEqual(bindRequest.getBindDN(),
         "uid=john.doe,ou=People,dc=example,dc=com");
    assertEquals(bindRequest.getPassword().stringValue(), "ReadFromFile");
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of simple
   * but does not include a DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testAuthTypeSimpleWithoutDN()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "simple"),
              new JSONField("password", "ThePassword"))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of simple
   * but does not include a password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testAuthTypeSimpleWithoutPassword()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "simple"),
              new JSONField("dn",
                   "uid=john.doe,ou=People,dc=example,dc=com"))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of simple
   * with a password file that does not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testAuthTypeSimpleWithMissingPasswordFile()
         throws Exception
  {
    final File passwordFile = createTempFile("password");
    assertTrue(passwordFile.delete());

    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "simple"),
              new JSONField("dn", "uid=john.doe,ou=People,dc=example,dc=com"),
              new JSONField("password-file", passwordFile.getAbsolutePath()))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of simple
   * but has an invalid field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testAuthTypeSimpleWithInvalidField()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "simple"),
              new JSONField("dn", "uid=john.doe,ou=People,dc=example,dc=com"),
              new JSONField("password", "ThePassword"),
              new JSONField("authorization-id", "u:not.allowed"))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of CRAM-MD5
   * and is configured for anonymous authentication.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthTypeCRAMMD5Anonymous()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "CRAM-MD5"),
              new JSONField("authentication-id", "dn:"),
              new JSONField("password", ""))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNotNull(spec.getBindRequest());
    assertTrue(spec.getBindRequest() instanceof CRAMMD5BindRequest);

    final CRAMMD5BindRequest bindRequest =
         (CRAMMD5BindRequest) spec.getBindRequest();
    assertEquals(bindRequest.getAuthenticationID(), "dn:");
    assertEquals(bindRequest.getPasswordString(), "");
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of CRAM-MD5
   * and is configured for non-anonymous authentication.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthTypeCRAMMD5NonAnonymous()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "CRAM-MD5"),
              new JSONField("authentication-id", "u:john.doe"),
              new JSONField("password", "password"))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNotNull(spec.getBindRequest());
    assertTrue(spec.getBindRequest() instanceof CRAMMD5BindRequest);

    final CRAMMD5BindRequest bindRequest =
         (CRAMMD5BindRequest) spec.getBindRequest();
    assertEquals(bindRequest.getAuthenticationID(), "u:john.doe");
    assertEquals(bindRequest.getPasswordString(), "password");
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of CRAM-MD5
   * and is missing the authentication ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testAuthTypeCRAMMD5MissingAuthenticationID()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "CRAM-MD5"),
              new JSONField("password", "password"))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of CRAM-MD5
   * and is missing the password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testAuthTypeCRAMMD5MissingPassword()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "CRAM-MD5"),
              new JSONField("authentication-id", "u:john.doe"))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of DIGEST-MD5
   * and is configured for anonymous authentication.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthTypeDIGESTMD5Anonymous()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "DIGEST-MD5"),
              new JSONField("authentication-id", "dn:"),
              new JSONField("password", ""))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNotNull(spec.getBindRequest());
    assertTrue(spec.getBindRequest() instanceof DIGESTMD5BindRequest);

    final DIGESTMD5BindRequest bindRequest =
         (DIGESTMD5BindRequest) spec.getBindRequest();
    assertEquals(bindRequest.getAuthenticationID(), "dn:");
    assertNull(bindRequest.getAuthorizationID());
    assertEquals(bindRequest.getPasswordString(), "");
    assertNull(bindRequest.getRealm());
    assertNotNull(bindRequest.getAllowedQoP());
    assertEquals(bindRequest.getAllowedQoP(),
         Collections.singletonList(SASLQualityOfProtection.AUTH));
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of DIGEST-MD5
   * and is configured for non-anonymous authentication with a single allowed
   * quality of protection.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthTypeDIGESTMD5NonAnonymousSingleQoP()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "DIGEST-MD5"),
              new JSONField("authentication-id", "u:john.doe"),
              new JSONField("authorization-id", "u:someone.else"),
              new JSONField("password", "password"),
              new JSONField("realm", "dc=example,dc=com"),
              new JSONField("qop", "auth-conf"))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNotNull(spec.getBindRequest());
    assertTrue(spec.getBindRequest() instanceof DIGESTMD5BindRequest);

    final DIGESTMD5BindRequest bindRequest =
         (DIGESTMD5BindRequest) spec.getBindRequest();
    assertEquals(bindRequest.getAuthenticationID(), "u:john.doe");
    assertEquals(bindRequest.getAuthorizationID(), "u:someone.else");
    assertEquals(bindRequest.getPasswordString(), "password");
    assertEquals(bindRequest.getRealm(), "dc=example,dc=com");
    assertNotNull(bindRequest.getAllowedQoP());
    assertEquals(bindRequest.getAllowedQoP(),
         Collections.singletonList(SASLQualityOfProtection.AUTH_CONF));
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of DIGEST-MD5
   * and is configured for non-anonymous authentication with an array of
   * quality of protection values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthTypeDIGESTMD5NonAnonymousQoPArray()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "DIGEST-MD5"),
              new JSONField("authentication-id", "u:john.doe"),
              new JSONField("authorization-id", "u:someone.else"),
              new JSONField("password", "password"),
              new JSONField("realm", "dc=example,dc=com"),
              new JSONField("qop", new JSONArray(
                   new JSONString("auth-conf"),
                   new JSONString("auth-int"),
                   new JSONString("auth"))))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNotNull(spec.getBindRequest());
    assertTrue(spec.getBindRequest() instanceof DIGESTMD5BindRequest);

    final DIGESTMD5BindRequest bindRequest =
         (DIGESTMD5BindRequest) spec.getBindRequest();
    assertEquals(bindRequest.getAuthenticationID(), "u:john.doe");
    assertEquals(bindRequest.getAuthorizationID(), "u:someone.else");
    assertEquals(bindRequest.getPasswordString(), "password");
    assertEquals(bindRequest.getRealm(), "dc=example,dc=com");
    assertNotNull(bindRequest.getAllowedQoP());
    assertEquals(bindRequest.getAllowedQoP(),
         Arrays.asList(
              SASLQualityOfProtection.AUTH_CONF,
              SASLQualityOfProtection.AUTH_INT,
              SASLQualityOfProtection.AUTH));
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of DIGEST-MD5
   * and is configured for non-anonymous authentication with an invalid quality
   * of protection string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testAuthTypeDIGESTMD5NonInvalidQoPString()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "DIGEST-MD5"),
              new JSONField("authentication-id", "u:john.doe"),
              new JSONField("authorization-id", "u:someone.else"),
              new JSONField("password", "password"),
              new JSONField("realm", "dc=example,dc=com"),
              new JSONField("qop", "invalid"))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of DIGEST-MD5
   * and is configured for non-anonymous authentication with an invalid quality
   * of protection string value in the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testAuthTypeDIGESTMD5NonInvalidQoPStringArrayElement()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "DIGEST-MD5"),
              new JSONField("authentication-id", "u:john.doe"),
              new JSONField("authorization-id", "u:someone.else"),
              new JSONField("password", "password"),
              new JSONField("realm", "dc=example,dc=com"),
              new JSONField("qop", new JSONArray(
                   new JSONString("auth-conf"),
                   new JSONString("auth-int"),
                   new JSONString("invalid"))))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of DIGEST-MD5
   * and is configured for non-anonymous authentication with an invalid quality
   * of protection value type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testAuthTypeDIGESTMD5NonInvalidQoPValueType()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "DIGEST-MD5"),
              new JSONField("authentication-id", "u:john.doe"),
              new JSONField("authorization-id", "u:someone.else"),
              new JSONField("password", "password"),
              new JSONField("realm", "dc=example,dc=com"),
              new JSONField("qop", true))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of DIGEST-MD5
   * and is configured for non-anonymous authentication with an invalid quality
   * of protection string element type in an array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testAuthTypeDIGESTMD5NonInvalidQoPArrayElementType()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "DIGEST-MD5"),
              new JSONField("authentication-id", "u:john.doe"),
              new JSONField("authorization-id", "u:someone.else"),
              new JSONField("password", "password"),
              new JSONField("realm", "dc=example,dc=com"),
              new JSONField("qop", new JSONArray(
                   new JSONString("auth-conf"),
                   JSONBoolean.FALSE)))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of DIGEST-MD5
   * and is missing the authentication ID field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testAuthTypeDIGESTMD5MissingAuthenticationID()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "DIGEST-MD5"),
              new JSONField("password", "password"))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of DIGEST-MD5
   * and is missing the password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testAuthTypeDIGESTMD5MissingPassword()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "DIGEST-MD5"),
              new JSONField("authentication-id", "u:john.doe"))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of EXTERNAL
   * and does not have an authorization-id field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthTypeEXTERNALNoAuthorizationID()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "EXTERNAL"))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNotNull(spec.getBindRequest());
    assertTrue(spec.getBindRequest() instanceof EXTERNALBindRequest);

    final EXTERNALBindRequest bindRequest =
         (EXTERNALBindRequest) spec.getBindRequest();
    assertNull(bindRequest.getAuthorizationID());
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of EXTERNAL
   * and has an empty authorization-id field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthTypeEXTERNALEmptyAuthorizationID()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "EXTERNAL"),
              new JSONField("authorization-id", ""))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNotNull(spec.getBindRequest());
    assertTrue(spec.getBindRequest() instanceof EXTERNALBindRequest);

    final EXTERNALBindRequest bindRequest =
         (EXTERNALBindRequest) spec.getBindRequest();
    assertEquals(bindRequest.getAuthorizationID(), "");
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of EXTERNAL
   * and has a non-empty authorization-id field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthTypeEXTERNALNonEmptyAuthorizationID()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "EXTERNAL"),
              new JSONField("authorization-id", "u:authzid"))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNotNull(spec.getBindRequest());
    assertTrue(spec.getBindRequest() instanceof EXTERNALBindRequest);

    final EXTERNALBindRequest bindRequest =
         (EXTERNALBindRequest) spec.getBindRequest();
    assertEquals(bindRequest.getAuthorizationID(), "u:authzid");
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of GSSAPI and
   * a minimal set of properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthTypeGSSAPIMinimal()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "GSSAPI"),
              new JSONField("authentication-id", "john.doe@EXAMPLE.COM"),
              new JSONField("password", "password"))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNotNull(spec.getBindRequest());
    assertTrue(spec.getBindRequest() instanceof GSSAPIBindRequest);

    final GSSAPIBindRequest bindRequest =
         (GSSAPIBindRequest) spec.getBindRequest();
    assertEquals(bindRequest.getAuthenticationID(), "john.doe@EXAMPLE.COM");
    assertNull(bindRequest.getAuthorizationID());
    assertEquals(bindRequest.getPasswordString(), "password");
    assertNotNull(bindRequest.getConfigFilePath());
    assertNull(bindRequest.getKDCAddress());
    assertEquals(bindRequest.getAllowedQoP(),
         Collections.singletonList(SASLQualityOfProtection.AUTH));
    assertNull(bindRequest.getRealm());
    assertFalse(bindRequest.renewTGT());
    assertFalse(bindRequest.requireCachedCredentials());
    assertNull(bindRequest.getTicketCachePath());
    assertTrue(bindRequest.useSubjectCredentialsOnly());
    assertTrue(bindRequest.useTicketCache());
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of GSSAPI and
   * a complete set of properties set to non-default values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthTypeGSSAPIComplete()
         throws Exception
  {
    final File configFile = createTempFile();
    final File ticketCache = createTempFile();

    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "GSSAPI"),
              new JSONField("authentication-id", "john.doe@EXAMPLE.COM"),
              new JSONField("authorization-id", "another.user@EXAMPLE.COM"),
              new JSONField("config-file-path", configFile.getAbsolutePath()),
              new JSONField("kdc-address", "kdc.example.com"),
              new JSONField("qop", "auth-conf"),
              new JSONField("realm", "EXAMPLE.COM"),
              new JSONField("renew-tgt", true),
              new JSONField("require-cached-credentials", true),
              new JSONField("ticket-cache-path",
                   ticketCache.getAbsolutePath()),
              new JSONField("use-subject-credentials-only", false),
              new JSONField("use-ticket-cache", false))));


    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNotNull(spec.getBindRequest());
    assertTrue(spec.getBindRequest() instanceof GSSAPIBindRequest);

    final GSSAPIBindRequest bindRequest =
         (GSSAPIBindRequest) spec.getBindRequest();
    assertEquals(bindRequest.getAuthenticationID(), "john.doe@EXAMPLE.COM");
    assertEquals(bindRequest.getAuthorizationID(), "another.user@EXAMPLE.COM");
    assertNull(bindRequest.getPasswordString());
    assertEquals(bindRequest.getConfigFilePath(), configFile.getAbsolutePath());
    assertEquals(bindRequest.getKDCAddress(), "kdc.example.com");
    assertEquals(bindRequest.getAllowedQoP(),
         Collections.singletonList(SASLQualityOfProtection.AUTH_CONF));
    assertEquals(bindRequest.getRealm(), "EXAMPLE.COM");
    assertTrue(bindRequest.renewTGT());
    assertTrue(bindRequest.requireCachedCredentials());
    assertEquals(bindRequest.getTicketCachePath(),
         ticketCache.getAbsolutePath());
    assertFalse(bindRequest.useSubjectCredentialsOnly());
    assertFalse(bindRequest.useTicketCache());
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of GSSAPI and
   * is missing the authentication ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testAuthTypeGSSAPIMissingAuthenticationID()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "GSSAPI"),
              new JSONField("password", "password"))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of GSSAPI and
   * is missing the password when cached credentials are not required.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testAuthTypeGSSAPIMissingPasswordWithoutRequireCachedCredentials()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "GSSAPI"),
              new JSONField("authentication-id", "john.doe@EXAMPLE.COM"))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of PLAIN and
   * is configured for anonymous authentication.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthTypePLAINAnonymous()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "PLAIN"),
              new JSONField("authentication-id", "dn:"),
              new JSONField("password", ""))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNotNull(spec.getBindRequest());
    assertTrue(spec.getBindRequest() instanceof PLAINBindRequest);

    final PLAINBindRequest bindRequest =
         (PLAINBindRequest) spec.getBindRequest();
    assertEquals(bindRequest.getAuthenticationID(), "dn:");
    assertNull(bindRequest.getAuthorizationID());
    assertEquals(bindRequest.getPasswordString(), "");
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of PLAIN and
   * is configured for non-anonymous authentication.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthTypePLAINNonAnonymous()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "PLAIN"),
              new JSONField("authentication-id", "u:john.doe"),
              new JSONField("authorization-id", "u:another.user"),
              new JSONField("password", "password"))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNotNull(spec.getBindRequest());
    assertTrue(spec.getBindRequest() instanceof PLAINBindRequest);

    final PLAINBindRequest bindRequest =
         (PLAINBindRequest) spec.getBindRequest();
    assertEquals(bindRequest.getAuthenticationID(), "u:john.doe");
    assertEquals(bindRequest.getAuthorizationID(), "u:another.user");
    assertEquals(bindRequest.getPasswordString(), "password");
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of PLAIN and
   * is missing the authentication ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testAuthTypePLAINMissingAuthenticationID()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "PLAIN"),
              new JSONField("password", "password"))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an authentication type of PLAIN and
   * is missing the password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testAuthTypePLAINMissingPassword()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "PLAIN"),
              new JSONField("authentication-id", "u:john.doe"))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the JSON object has an
   * authentication-details field that has an invalid authentication type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testInvalidAuthType()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "invalid"))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }
}
