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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.io.ByteArrayOutputStream;
import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.
           AdministrativeSessionInMemoryExtendedOperationHandler;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.extensions.NoticeOfDisconnectionExtendedResult;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedRequest;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedRequest;
import com.unboundid.util.Base64;
import com.unboundid.util.PasswordReader;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the {@code ldappasswordmodify}
 * command-line tool.
 */
public final class LDAPPasswordModifyTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the tool methods that can be invoked without
   * running the tool.
   */
  @Test()
  public void testToolMethods()
  {
    final LDAPPasswordModify tool = new LDAPPasswordModify(null, null);

    assertNotNull(tool.getToolName());
    assertEquals(tool.getToolName(), "ldappasswordmodify");

    assertNotNull(tool.getToolDescription());
    assertFalse(tool.getToolDescription().isEmpty());

    assertNotNull(tool.getAdditionalDescriptionParagraphs());
    assertFalse(tool.getAdditionalDescriptionParagraphs().isEmpty());

    assertNotNull(tool.getToolVersion());
    assertFalse(tool.getToolVersion().isEmpty());

    assertTrue(tool.supportsInteractiveMode());
    assertTrue(tool.defaultsToInteractiveMode());

    assertTrue(tool.supportsPropertiesFile());

    assertTrue(tool.supportsOutputFile());

    assertTrue(tool.supportsAuthentication());

    assertTrue(tool.defaultToPromptForBindPassword());

    assertTrue(tool.supportsSASLHelp());

    assertTrue(tool.includeAlternateLongIdentifiers());

    assertTrue(tool.supportsMultipleServers());

    assertTrue(tool.supportsSSLDebugging());

    assertTrue(tool.logToolInvocationByDefault());

    assertNull(tool.getToolCompletionMessage());

    assertNotNull(tool.getSuppressedShortIdentifiers());
    assertFalse(tool.getSuppressedShortIdentifiers().isEmpty());

    assertNotNull(tool.getExampleUsages());
    assertFalse(tool.getExampleUsages().isEmpty());
  }



  /**
   * Tests the behavior when trying to obtain usage information from the tool.
   */
  @Test()
  public void testGetUsage()
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ResultCode resultCode = LDAPPasswordModify.main(out, out, "--help");
    assertEquals(resultCode, ResultCode.SUCCESS);
    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior when attempting to change a user's password when the
   * tool determines that the password modify extended operation is the best
   * method to use.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordChangeViaInferredPasswordModifyExtOp()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    try (LDAPConnection conn = ds.getConnection())
    {
      assertNotNull(conn.getRootDSE());
      assertTrue(conn.getRootDSE().supportsExtendedOperation(
           PasswordModifyExtendedRequest.PASSWORD_MODIFY_REQUEST_OID));

      ldapPasswordModify(ResultCode.SUCCESS,
           "--hostname", "localhost",
           "--port", String.valueOf(ds.getListenPort()),
           "--userIdentity", "uid=test.user,ou=People,dc=example,dc=com",
           "--currentPassword", "password",
           "--newPassword", "newPassword",
           "--verbose");
    }
  }



  /**
   * Tests the behavior when attempting to change a user's password when the
   * the tool is explicitly told to use the password modify extended operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordChangeViaExplicitPasswordModifyExtOp()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.SUCCESS,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--userIdentity", "uid=test.user,ou=People,dc=example,dc=com",
         "--currentPassword", "password",
         "--newPassword", "newPassword",
         "--passwordChangeMethod", "password-modify-extended-operation",
         "--verbose");
  }



  /**
   * Tests the behavior when attempting to change a user's password when the
   * tool determines that a regular LDAP modify operation is the best method
   * to use.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordChangeViaInferredRegularLDAPModify()
         throws Exception
  {
    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.getExtendedOperationHandlers().clear();

    try (InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg))
    {
      ds.startListening();
      try (LDAPConnection conn = ds.getConnection())
      {
        conn.add(
             "dn: dc=example,dc=com",
             "objectClass: top",
             "objectClass: domain",
             "dc: example");
        conn.add(
             "dn: ou=People,dc=example,dc=com",
             "objectClass: top",
             "objectClass: organizationalUnit",
             "ou: People");
        conn.add(
             "dn: uid=test.user,ou=People,dc=example,dc=com",
             "objectClass: top",
             "objectClass: person",
             "objectClass: organizationalPerson",
             "objectClass: inetOrgPerson",
             "uid: test.user",
             "givenName: Test",
             "sn: User",
             "cn: Test User",
             "userPassword: password");

        assertNotNull(conn.getRootDSE());
        assertFalse(conn.getRootDSE().supportsExtendedOperation(
             PasswordModifyExtendedRequest.PASSWORD_MODIFY_REQUEST_OID));

        ldapPasswordModify(ResultCode.SUCCESS,
             "--hostname", "localhost",
             "--port", String.valueOf(ds.getListenPort()),
             "--userIdentity", "uid=test.user,ou=People,dc=example,dc=com",
             "--currentPassword", "password",
             "--newPassword", "newPassword",
             "--verbose");
      }
    }
  }



  /**
   * Tests the behavior when attempting to change a user's password when the
   * the tool is explicitly told to use a regular LDAP modify operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordChangeViaExplicitRegularLDAPModify()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.SUCCESS,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--userIdentity", "uid=test.user,ou=People,dc=example,dc=com",
         "--currentPassword", "password",
         "--newPassword", "newPassword",
         "--passwordChangeMethod", "ldap-modify",
         "--verbose");
  }



  /**
   * Tests the behavior when attempting to change a user's password when the
   * tool determines that an Active Directory-specific LDAP modify operation is
   * the best method to use.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordChangeViaInferredActiveDirectoryLDAPModify()
         throws Exception
  {
    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.getExtendedOperationHandlers().clear();

    // Create a supportedControl attribute that advertises at least 20 controls
    // below the Microsoft base OID of 1.2.840.113556.
    final List<String> supportedControlValues = new ArrayList<>(20);
    for (int i=1; i <= 20; i++)
    {
      supportedControlValues.add("1.2.840.113556." + i);
    }

    dsCfg.setCustomRootDSEAttributes(Collections.singletonList(
         new Attribute("supportedControl", supportedControlValues)));
    dsCfg.setSchema(null);

    try (InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg))
    {
      ds.startListening();
      try (LDAPConnection conn = ds.getConnection())
      {
        conn.add(
             "dn: dc=example,dc=com",
             "objectClass: top",
             "objectClass: domain",
             "dc: example");
        conn.add(
             "dn: ou=People,dc=example,dc=com",
             "objectClass: top",
             "objectClass: organizationalUnit",
             "ou: People");

        final String encodedOldPasswordBase64 =
             Base64.encode(LDAPPasswordModify.encodePasswordForActiveDirectory(
                  StaticUtils.getBytes("password")));
        conn.add(
             "dn: uid=test.user,ou=People,dc=example,dc=com",
             "objectClass: top",
             "objectClass: person",
             "objectClass: organizationalPerson",
             "objectClass: inetOrgPerson",
             "uid: test.user",
             "givenName: Test",
             "sn: User",
             "cn: Test User",
             "unicodePwd:: " + encodedOldPasswordBase64);

        ldapPasswordModify(ResultCode.SUCCESS,
             "--hostname", "localhost",
             "--port", String.valueOf(ds.getListenPort()),
             "--userIdentity", "uid=test.user,ou=People,dc=example,dc=com",
             "--currentPassword", "password",
             "--newPassword", "newPassword",
             "--verbose");
      }
    }
  }



  /**
   * Tests the behavior when attempting to change a user's password when the
   * the tool is explicitly told to use an Active Directory-specific LDAP modify
   * operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordChangeViaExplicitActiveDirectoryLDAPModify()
         throws Exception
  {
    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.getExtendedOperationHandlers().clear();
    dsCfg.setSchema(null);

    try (InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg))
    {
      ds.startListening();
      try (LDAPConnection conn = ds.getConnection())
      {
        conn.add(
             "dn: dc=example,dc=com",
             "objectClass: top",
             "objectClass: domain",
             "dc: example");
        conn.add(
             "dn: ou=People,dc=example,dc=com",
             "objectClass: top",
             "objectClass: organizationalUnit",
             "ou: People");

        final String encodedOldPasswordBase64 =
             Base64.encode(LDAPPasswordModify.encodePasswordForActiveDirectory(
                  StaticUtils.getBytes("password")));
        conn.add(
             "dn: uid=test.user,ou=People,dc=example,dc=com",
             "objectClass: top",
             "objectClass: person",
             "objectClass: organizationalPerson",
             "objectClass: inetOrgPerson",
             "uid: test.user",
             "givenName: Test",
             "sn: User",
             "cn: Test User",
             "unicodePwd:: " + encodedOldPasswordBase64);

        ldapPasswordModify(ResultCode.SUCCESS,
             "--hostname", "localhost",
             "--port", String.valueOf(ds.getListenPort()),
             "--userIdentity", "uid=test.user,ou=People,dc=example,dc=com",
             "--currentPassword", "password",
             "--newPassword", "newPassword",
             "--passwordChangeMethod", "active-directory",
             "--verbose");
      }
    }
  }



  /**
   * Tests the behavior when using a password modify extended operation with no
   * explicitly specified user identity.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordModifyExtOpNoProvidedUserIdentity()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.SUCCESS,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "uid=test.user,ou=People,dc=example,dc=com",
         "--bindPassword", "password",
         "--newPassword", "newPassword",
         "--passwordChangeMethod", "password-modify-extended-operation",
         "--verbose");
  }



  /**
   * Tests the behavior when using a password modify extended operation with the
   * bind DN provided as the user identity.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordModifyExtOpBindDNProvidedAsUserIdentity()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.SUCCESS,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "uid=test.user,ou=People,dc=example,dc=com",
         "--bindPassword", "password",
         "--provideBindDNAsUserIdentity",
         "--newPassword", "newPassword",
         "--passwordChangeMethod", "password-modify-extended-operation",
         "--verbose");
  }



  /**
   * Tests the behavior when using an LDAP modify operation with a user identity
   * specified as a DN, but prefixed with "dn:".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPModifyDNUserIdentityWithPrefix()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.SUCCESS,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--userIdentity", "dn:uid=test.user,ou=People,dc=example,dc=com",
         "--newPassword", "newPassword",
         "--passwordChangeMethod", "ldap-modify",
         "--verbose");
  }



  /**
   * Tests the behavior when using an LDAP modify operation with a user identity
   * specified as a username when using the default username attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPModifyUserNameUserIdentityDefaultAttribute()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.SUCCESS,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--userIdentity", "u:test.user",
         "--newPassword", "newPassword",
         "--passwordChangeMethod", "ldap-modify",
         "--verbose");
  }



  /**
   * Tests the behavior when using an LDAP modify operation with a user identity
   * specified as a username when using a non-default username attribute, and
   * also multiple username attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPModifyUserNameUserIdentityMultipleAttributes()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.SUCCESS,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--userIdentity", "u:Test User",
         "--usernameAttribute", "uid",
         "--usernameAttribute", "mail",
         "--usernameAttribute", "cn",
         "--newPassword", "newPassword",
         "--passwordChangeMethod", "ldap-modify",
         "--verbose");
  }



  /**
   * Tests the behavior when using an LDAP modify operation when not specifying
   * a user identity, and when the connection is authenticated using a simple
   * bind.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPModifyInferredUserIdentityWithSimpleAuthentication()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.SUCCESS,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "uid=test.user,ou=People,dc=example,dc=com",
         "--bindPassword", "password",
         "--newPassword", "newPassword",
         "--passwordChangeMethod", "ldap-modify",
         "--verbose");
  }



  /**
   * Tests the behavior when using an LDAP modify operation when not specifying
   * a user identity, and when the connection is authenticated via SASL PLAIN,
   * so that it's necessary to use the "Who Am I?" operation to determine the
   * authentication identity.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPModifyInferredUserIdentityWithSASLAuthentication()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.SUCCESS,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--saslOption", "mech=PLAIN",
         "--saslOption", "authID=u:test.user",
         "--bindPassword", "password",
         "--newPassword", "newPassword",
         "--passwordChangeMethod", "ldap-modify",
         "--verbose");
  }



  /**
   * Tests the behavior when using an LDAP modify operation when not specifying
   * a user identity, and when the connection is authenticated via SASL PLAIN,
   * and when the server does not support the "Who Am I?" extended operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPModifyInferredUserIdentityWithSASLAuthenticationNoWhoAmI()
         throws Exception
  {
    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.getExtendedOperationHandlers().clear();

    try (InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg))
    {
      ds.startListening();
      try (LDAPConnection conn = ds.getConnection())
      {
        conn.add(
             "dn: dc=example,dc=com",
             "objectClass: top",
             "objectClass: domain",
             "dc: example");
        conn.add(
             "dn: ou=People,dc=example,dc=com",
             "objectClass: top",
             "objectClass: organizationalUnit",
             "ou: People");
        conn.add(
             "dn: uid=test.user,ou=People,dc=example,dc=com",
             "objectClass: top",
             "objectClass: person",
             "objectClass: organizationalPerson",
             "objectClass: inetOrgPerson",
             "uid: test.user",
             "givenName: Test",
             "sn: User",
             "cn: Test User",
             "userPassword: password");

        assertNotNull(conn.getRootDSE());
        assertFalse(conn.getRootDSE().supportsExtendedOperation(
             WhoAmIExtendedRequest.WHO_AM_I_REQUEST_OID));

        ldapPasswordModify(ResultCode.PARAM_ERROR,
             "--hostname", "localhost",
             "--port", String.valueOf(ds.getListenPort()),
             "--saslOption", "mech=PLAIN",
             "--saslOption", "authID=u:test.user",
             "--bindPassword", "password",
             "--newPassword", "newPassword",
             "--passwordChangeMethod", "ldap-modify",
             "--verbose");
      }
    }
  }



  /**
   * Tests the behavior when using an LDAP modify operation when not specifying
   * a user identity, and when no authentication arguments are provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPModifyNoUserIdentityWithoutAuthentication()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.PARAM_ERROR,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--newPassword", "newPassword",
         "--passwordChangeMethod", "ldap-modify",
         "--verbose");
  }



  /**
   * Tests the behavior when using an LDAP modify operation when not specifying
   * a user identity, and when binding anonymously.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPModifyNoUserIdentityWithAnonymousAuthentication()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.PARAM_ERROR,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "",
         "--bindPassword", "",
         "--newPassword", "newPassword",
         "--passwordChangeMethod", "ldap-modify",
         "--verbose");
  }



  /**
   * Tests the behavior when using an LDAP modify operation when the user
   * identity is specified as a malformed DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPModifyUserIdentityMalformedDN()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.PARAM_ERROR,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--userIdentity", "dn:malformed",
         "--newPassword", "newPassword",
         "--passwordChangeMethod", "ldap-modify",
         "--verbose");
  }



  /**
   * Tests the behavior when using an LDAP modify operation when the user
   * identity is specified as the null DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPModifyUserIdentityNullDN()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.PARAM_ERROR,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--userIdentity", "dn:",
         "--newPassword", "newPassword",
         "--passwordChangeMethod", "ldap-modify",
         "--verbose");
  }



  /**
   * Tests the behavior when using an LDAP modify operation when the user
   * identity is specified as an empty username.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPModifyUserIdentityEmptyUsername()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.PARAM_ERROR,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--userIdentity", "u:",
         "--newPassword", "newPassword",
         "--passwordChangeMethod", "ldap-modify",
         "--verbose");
  }



  /**
   * Tests the behavior when attempting to change a user's password searching
   * for the target user in an Active Directory instance.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordChangeActiveDirectoryUsername()
         throws Exception
  {
    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.getExtendedOperationHandlers().clear();
    dsCfg.setSchema(null);

    try (InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg))
    {
      ds.startListening();
      try (LDAPConnection conn = ds.getConnection())
      {
        conn.add(
             "dn: dc=example,dc=com",
             "objectClass: top",
             "objectClass: domain",
             "dc: example");
        conn.add(
             "dn: ou=People,dc=example,dc=com",
             "objectClass: top",
             "objectClass: organizationalUnit",
             "ou: People");

        final String encodedOldPasswordBase64 =
             Base64.encode(LDAPPasswordModify.encodePasswordForActiveDirectory(
                  StaticUtils.getBytes("password")));
        conn.add(
             "dn: cn=Test User,ou=People,dc=example,dc=com",
             "objectClass: top",
             "objectClass: person",
             "objectClass: organizationalPerson",
             "objectClass: inetOrgPerson",
             "samAccountName: test.user",
             "cn: Test User",
             "unicodePwd:: " + encodedOldPasswordBase64);

        ldapPasswordModify(ResultCode.SUCCESS,
             "--hostname", "localhost",
             "--port", String.valueOf(ds.getListenPort()),
             "--userIdentity", "u:test.user",
             "--currentPassword", "password",
             "--newPassword", "newPassword",
             "--passwordChangeMethod", "active-directory",
             "--verbose");
      }
    }
  }



  /**
   * Tests the behavior when using an LDAP modify operation when searching for
   * a user that does not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPModifyUserIdentityUsernameDoesNotExist()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.NO_RESULTS_RETURNED,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--userIdentity", "u:nonexistent",
         "--newPassword", "newPassword",
         "--passwordChangeMethod", "ldap-modify",
         "--verbose");
  }



  /**
   * Tests the behavior when using an LDAP modify operation when searching for
   * a user that does not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPModifyUserIdentityUsernameMatchesMultipleEntries()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    try (LDAPConnection conn = ds.getConnection())
    {
      conn.add(
           "dn: cn=Another Test User,ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: test.user",
           "givenName: Another",
           "sn: User",
           "cn: Another Test User",
           "userPassword: password");

      ldapPasswordModify(ResultCode.SIZE_LIMIT_EXCEEDED,
           "--hostname", "localhost",
           "--port", String.valueOf(ds.getListenPort()),
           "--userIdentity", "u:test.user",
           "--newPassword", "newPassword",
           "--passwordChangeMethod", "ldap-modify",
           "--verbose");
    }
  }



  /**
   * Tests the behavior when using an LDAP modify operation when searching for
   * a user below a nonexistent base DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPModifyUserIdentityNonexistentBaseDN()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.NO_SUCH_OBJECT,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--userIdentity", "u:test.user",
         "--searchBaseDN", "ou=nonexistent,dc=example,dc=com",
         "--newPassword", "newPassword",
         "--passwordChangeMethod", "ldap-modify",
         "--verbose");
  }



  /**
   * Tests the behavior when obtaining the new password from a file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNewPasswordFromFile()
         throws Exception
  {
    final File newPasswordFile = createTempFile("this-is-the-new-password");

    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.SUCCESS,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "uid=test.user,ou=People,dc=example,dc=com",
         "--bindPassword", "password",
         "--newPasswordFile", newPasswordFile.getAbsolutePath(),
         "--passwordChangeMethod", "password-modify-extended-operation",
         "--verbose");
  }



  /**
   * Tests the behavior when obtaining the new password from an empty file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNewPasswordFromEmptyFile()
         throws Exception
  {
    final File newPasswordFile = createTempFile();

    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.PARAM_ERROR,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "uid=test.user,ou=People,dc=example,dc=com",
         "--bindPassword", "password",
         "--newPasswordFile", newPasswordFile.getAbsolutePath(),
         "--passwordChangeMethod", "password-modify-extended-operation",
         "--verbose");
  }



  /**
   * Tests the behavior when obtaining the new password from "interactive"
   * prompting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPromptForNewPassword()
         throws Exception
  {
    PasswordReader.setTestReaderLines(
         "", // Empty first attempt.
         "this-is-the-new-password",
         "this-is-not-the-same-new-password",
         "this-is-the-new-password",
         "this-is-the-new-password");

    try
    {
      final InMemoryDirectoryServer ds = getTestDS(true, true);
      ldapPasswordModify(ResultCode.SUCCESS,
           "--hostname", "localhost",
           "--port", String.valueOf(ds.getListenPort()),
           "--bindDN", "uid=test.user,ou=People,dc=example,dc=com",
           "--bindPassword", "password",
           "--promptForNewPassword",
           "--passwordChangeMethod", "password-modify-extended-operation",
           "--verbose");
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }
  }



  /**
   * Tests the behavior when obtaining the current password from a file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCurrentPasswordFromFile()
         throws Exception
  {
    final File currentPasswordFile =
         createTempFile("password");

    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.SUCCESS,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "uid=test.user,ou=People,dc=example,dc=com",
         "--bindPassword", "password",
         "--currentPasswordFile", currentPasswordFile.getAbsolutePath(),
         "--newPassword", "newPassword",
         "--passwordChangeMethod", "password-modify-extended-operation",
         "--verbose");
  }



  /**
   * Tests the behavior when obtaining the current password from an empty file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCurrentPasswordFromEmptyFile()
         throws Exception
  {
    final File currentPasswordFile = createTempFile();

    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.PARAM_ERROR,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "uid=test.user,ou=People,dc=example,dc=com",
         "--bindPassword", "password",
         "--currentPasswordFile", currentPasswordFile.getAbsolutePath(),
         "--newPassword", "newPassword",
         "--passwordChangeMethod", "password-modify-extended-operation",
         "--verbose");
  }



  /**
   * Tests the behavior when obtaining the current password from "interactive"
   * prompting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPromptForCurrentPassword()
         throws Exception
  {
    PasswordReader.setTestReaderLines(
         "", // Empty first attempt.
         "password");

    try
    {
      final InMemoryDirectoryServer ds = getTestDS(true, true);
      ldapPasswordModify(ResultCode.SUCCESS,
           "--hostname", "localhost",
           "--port", String.valueOf(ds.getListenPort()),
           "--bindDN", "uid=test.user,ou=People,dc=example,dc=com",
           "--bindPassword", "password",
           "--promptForCurrentPassword",
           "--newPassword", "newPassword",
           "--passwordChangeMethod", "password-modify-extended-operation",
           "--verbose");
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }
  }



  /**
   * Tests the behavior when the new password will be generated by the client.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNewPasswordGeneratedByClient()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.SUCCESS,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "uid=test.user,ou=People,dc=example,dc=com",
         "--bindPassword", "password",
         "--generateClientSideNewPassword",
         "--passwordChangeMethod", "password-modify-extended-operation",
         "--verbose");
  }



  /**
   * Tests the behavior when the new password will be generated by the client,
   * but when using custom character sets when one of them is empty.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNewPasswordGeneratedWithEmptyCharacterSet()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.PARAM_ERROR,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "uid=test.user,ou=People,dc=example,dc=com",
         "--bindPassword", "password",
         "--generateClientSideNewPassword",
         "--generatedPasswordLength", "8",
         "--generatedPasswordCharacterSet", "abcdefghijklmnopqrstuvwxyz",
         "--generatedPasswordCharacterSet", "",
         "--passwordChangeMethod", "password-modify-extended-operation",
         "--verbose");
  }



  /**
   * Tests the behavior when no new password is specified when using the
   * password modify extended operation, which will generate the new password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoNewPasswordExtOp()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.SUCCESS,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "uid=test.user,ou=People,dc=example,dc=com",
         "--bindPassword", "password",
         "--passwordChangeMethod", "password-modify-extended-operation",
         "--verbose");
  }



  /**
   * Tests the behavior when no new password is specified when using a regular
   * LDAP modify operation, which will fail.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoNewPasswordLDAPModify()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.PARAM_ERROR,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "uid=test.user,ou=People,dc=example,dc=com",
         "--bindPassword", "password",
         "--passwordChangeMethod", "ldap-modify",
         "--verbose");
  }



  /**
   * Tests the behavior when changing the password using a password modify
   * extended operation when it does not complete successfully.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoSuchUserExtendedOperation()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.UNWILLING_TO_PERFORM,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--userIdentity", "uid=nonexistent,ou=People,dc=example,dc=com",
         "--newPassword", "newPassword",
         "--passwordChangeMethod", "password-modify-extended-operation",
         "--verbose");
  }



  /**
   * Tests the behavior when changing the password using an LDAP modify
   * operation when it does not complete successfully.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoSuchUserLDAPModify()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.NO_SUCH_OBJECT,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--userIdentity", "uid=nonexistent,ou=People,dc=example,dc=com",
         "--newPassword", "newPassword",
         "--passwordChangeMethod", "ldap-modify",
         "--verbose");
  }



  /**
   * Tests the behavior when changing the password using a password modify
   * extended operation when the no operation request control was provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoOperationControlExtendedOperation()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.SUCCESS,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--userIdentity", "uid=test.user,ou=People,dc=example,dc=com",
         "--currentPassword", "password",
         "--passwordChangeMethod", "password-modify-extended-operation",
         "--noOperation",
         "--verbose");
  }



  /**
   * Tests the behavior when changing the password using an LDAP modify
   * operation when it does not complete successfully.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoOperationControlLDAPModify()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.SUCCESS,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--userIdentity", "uid=test.user,ou=People,dc=example,dc=com",
         "--currentPassword", "password",
         "--newPassword", "newPassword",
         "--passwordChangeMethod", "ldap-modify",
         "--noOperation",
         "--verbose");
  }



  /**
   * Tests the behavior when changing the password using a password modify
   * extended operation when a referral will be generated and they should not be
   * automatically followed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedOperationReferralNotFollowed()
         throws Exception
  {
    final InMemoryDirectoryServer ds1 = getTestDS(true, true);


    final InMemoryDirectoryServerConfig ds2Cfg =
         new InMemoryDirectoryServerConfig(ds1.getConfig());
    ds2Cfg.addInMemoryOperationInterceptor(
         new TestLDAPPasswordModifyReferralInMemoryOperationInterceptor(
              "ldap://localhost:" + ds1.getListenPort() +
                   "/uid=test.user,ou=People,dc=example,dc=com"));

    try (InMemoryDirectoryServer ds2 = new InMemoryDirectoryServer(ds2Cfg))
    {
      ds2.startListening();

      ldapPasswordModify(ResultCode.REFERRAL,
           "--hostname", "localhost",
           "--port", String.valueOf(ds2.getListenPort()),
           "--userIdentity", "uid=test.user,ou=Users,dc=example,dc=com",
           "--currentPassword", "password",
           "--newPassword", "newPassword",
           "--passwordChangeMethod", "password-modify-extended-operation",
           "--verbose");
    }
  }



  /**
   * Tests the behavior when changing the password using a password modify
   * extended operation when a referral will be generated and they should be
   * automatically followed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedOperationReferralFollowed()
         throws Exception
  {
    final InMemoryDirectoryServer ds1 = getTestDS(true, true);


    final InMemoryDirectoryServerConfig ds2Cfg =
         new InMemoryDirectoryServerConfig(ds1.getConfig());
    ds2Cfg.addInMemoryOperationInterceptor(
         new TestLDAPPasswordModifyReferralInMemoryOperationInterceptor(
              "malformed-url",
              "ldap://localhost:" + ds1.getListenPort() +
                   "/uid=test.user,ou=People,dc=example,dc=com"));

    try (InMemoryDirectoryServer ds2 = new InMemoryDirectoryServer(ds2Cfg))
    {
      ds2.startListening();

      ldapPasswordModify(ResultCode.SUCCESS,
           "--hostname", "localhost",
           "--port", String.valueOf(ds2.getListenPort()),
           "--userIdentity", "uid=test.user,ou=Users,dc=example,dc=com",
           "--currentPassword", "password",
           "--passwordChangeMethod", "password-modify-extended-operation",
           "--followReferrals",
           "--verbose");
    }
  }



  /**
   * Tests the behavior when changing the password using a password modify
   * extended operation when a referral will be generated and they should be
   * automatically followed, and also when the referred operation fails.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedOperationReferralFollowedFailrue()
         throws Exception
  {
    final InMemoryDirectoryServer ds1 = getTestDS(true, true);


    final InMemoryDirectoryServerConfig ds2Cfg =
         new InMemoryDirectoryServerConfig(ds1.getConfig());
    ds2Cfg.addInMemoryOperationInterceptor(
         new TestLDAPPasswordModifyReferralInMemoryOperationInterceptor(
              "ldap://localhost:" + ds1.getListenPort() +
                   "/uid=nonexistent,ou=People,dc=example,dc=com"));

    try (InMemoryDirectoryServer ds2 = new InMemoryDirectoryServer(ds2Cfg))
    {
      ds2.startListening();

      ldapPasswordModify(ResultCode.UNWILLING_TO_PERFORM,
           "--hostname", "localhost",
           "--port", String.valueOf(ds2.getListenPort()),
           "--userIdentity", "uid=test.user,ou=Users,dc=example,dc=com",
           "--currentPassword", "password",
           "--newPassword", "newPassword",
           "--passwordChangeMethod", "password-modify-extended-operation",
           "--noOperation",
           "--followReferrals",
           "--verbose");
    }
  }



  /**
   * Tests the behavior when changing the password using a password modify
   * extended operation when a referral will be generated and they should be
   * automatically followed, and also when the no-operation control is to be
   * used.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedOperationReferralFollowedNoOperation()
         throws Exception
  {
    final InMemoryDirectoryServer ds1 = getTestDS(true, true);


    final InMemoryDirectoryServerConfig ds2Cfg =
         new InMemoryDirectoryServerConfig(ds1.getConfig());
    ds2Cfg.addInMemoryOperationInterceptor(
         new TestLDAPPasswordModifyReferralInMemoryOperationInterceptor(
              "ldap://localhost:" + ds1.getListenPort() +
                   "/uid=test.user,ou=People,dc=example,dc=com"));

    try (InMemoryDirectoryServer ds2 = new InMemoryDirectoryServer(ds2Cfg))
    {
      ds2.startListening();

      ldapPasswordModify(ResultCode.SUCCESS,
           "--hostname", "localhost",
           "--port", String.valueOf(ds2.getListenPort()),
           "--userIdentity", "uid=test.user,ou=Users,dc=example,dc=com",
           "--currentPassword", "password",
           "--passwordChangeMethod", "password-modify-extended-operation",
           "--noOperation",
           "--followReferrals",
           "--verbose");
    }
  }



  /**
   * Tests the behavior when changing the password using a password modify
   * extended operation when a referral will be generated and they should be
   * automatically followed, but when the hop limit is exceeded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedOperationReferralFollowedHopLimitExceeded()
         throws Exception
  {
    final InMemoryDirectoryServer ds1 = getTestDS(true, true);

    final TestLDAPPasswordModifyReferralInMemoryOperationInterceptor i =
         new TestLDAPPasswordModifyReferralInMemoryOperationInterceptor(
              "ldap://localhost:" + ds1.getListenPort() +
                   "/uid=test.user,ou=People,dc=example,dc=com");

    final InMemoryDirectoryServerConfig ds2Cfg =
         new InMemoryDirectoryServerConfig(ds1.getConfig());
    ds2Cfg.addInMemoryOperationInterceptor(i);

    try (InMemoryDirectoryServer ds2 = new InMemoryDirectoryServer(ds2Cfg))
    {
      ds2.startListening();

      // Update the interceptor so it refers to itself.
      i.setReferralURLs("ldap://localhost:" + ds2.getListenPort() +
           "/uid=test.user,ou=People,dc=example,dc=com");

      ldapPasswordModify(ResultCode.REFERRAL_LIMIT_EXCEEDED,
           "--hostname", "localhost",
           "--port", String.valueOf(ds2.getListenPort()),
           "--userIdentity", "uid=test.user,ou=Users,dc=example,dc=com",
           "--currentPassword", "password",
           "--newPassword", "newPassword",
           "--passwordChangeMethod", "password-modify-extended-operation",
           "--followReferrals",
           "--verbose");
    }
  }



  /**
   * Tests the behavior when changing the password using a regular LDAP modify
   * operation when a referral will be generated and they should not be
   * automatically followed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPModifyReferralNotFollowed()
         throws Exception
  {
    final InMemoryDirectoryServer ds1 = getTestDS(true, true);


    final InMemoryDirectoryServerConfig ds2Cfg =
         new InMemoryDirectoryServerConfig(ds1.getConfig());
    ds2Cfg.addInMemoryOperationInterceptor(
         new TestLDAPPasswordModifyReferralInMemoryOperationInterceptor(
              "ldap://localhost:" + ds1.getListenPort() +
                   "/uid=test.user,ou=People,dc=example,dc=com"));

    try (InMemoryDirectoryServer ds2 = new InMemoryDirectoryServer(ds2Cfg))
    {
      ds2.startListening();

      ldapPasswordModify(ResultCode.REFERRAL,
           "--hostname", "localhost",
           "--port", String.valueOf(ds2.getListenPort()),
           "--userIdentity", "uid=test.user,ou=Users,dc=example,dc=com",
           "--currentPassword", "password",
           "--newPassword", "newPassword",
           "--passwordChangeMethod", "ldap-modify",
           "--verbose");
    }
  }



  /**
   * Tests the behavior when changing the password using a regular LDAP modify
   * operation when a referral will be generated and they should be
   * automatically followed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPModifyReferralFollowed()
         throws Exception
  {
    final InMemoryDirectoryServer ds1 = getTestDS(true, true);


    final InMemoryDirectoryServerConfig ds2Cfg =
         new InMemoryDirectoryServerConfig(ds1.getConfig());
    ds2Cfg.addInMemoryOperationInterceptor(
         new TestLDAPPasswordModifyReferralInMemoryOperationInterceptor(
              "malformed-url",
              "ldap://localhost:" + ds1.getListenPort() +
                   "/uid=test.user,ou=People,dc=example,dc=com"));

    try (InMemoryDirectoryServer ds2 = new InMemoryDirectoryServer(ds2Cfg))
    {
      ds2.startListening();

      ldapPasswordModify(ResultCode.SUCCESS,
           "--hostname", "localhost",
           "--port", String.valueOf(ds2.getListenPort()),
           "--userIdentity", "uid=test.user,ou=Users,dc=example,dc=com",
           "--currentPassword", "password",
           "--newPassword", "newPassword",
           "--passwordChangeMethod", "ldap-modify",
           "--followReferrals",
           "--verbose");
    }
  }



  /**
   * Tests the behavior when the attempt to connect to the server fails.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConnectFailure()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final int port = ds.getListenPort();

    try
    {
      ds.shutDown(true);
      ldapPasswordModify(ResultCode.CONNECT_ERROR,
           "--hostname", "localhost",
           "--port", String.valueOf(port),
           "--userIdentity", "uid=test.user,ou=People,dc=example,dc=com",
           "--currentPassword", "password",
           "--newPassword", "newPassword",
           "--verbose");
    }
    finally
    {
      ds.startListening();
    }
  }



  /**
   * Tests the behavior when the attempt to bind to the server fails.  Also,
   * use all of the arguments to generate bind controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindFailure()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ldapPasswordModify(ResultCode.INVALID_CREDENTIALS,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "uid=test.user,ou=People,dc=example,dc=com",
         "--bindPassword", "wrongPassword",
         "--userIdentity", "uid=test.user,ou=People,dc=example,dc=com",
         "--currentPassword", "password",
         "--newPassword", "newPassword",
         "--bindControl", "1.2.3.4",
         "--useAuthorizationIdentityControl",
         "--usePasswordPolicyControlOnBind",
         "--getAuthorizationEntryAttribute", "*",
         "--getAuthorizationEntryAttribute", "+",
         "--getUserResourceLimits",
         "--verbose");
  }



  /**
   * Tests the behavior when trying to use an administrative session.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAdministrativeSession()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final InMemoryDirectoryServerConfig ds2Cfg =
         new InMemoryDirectoryServerConfig(ds.getConfig());
    ds2Cfg.addExtendedOperationHandler(
         new AdministrativeSessionInMemoryExtendedOperationHandler());

    try (InMemoryDirectoryServer ds2 =  new InMemoryDirectoryServer(ds2Cfg))
    {
      ds2.startListening();
      try (LDAPConnection conn = ds2.getConnection())
      {
        conn.add(
             "dn: dc=example,dc=com",
             "objectClass: top",
             "objectClass: domain",
             "dc: example");
        conn.add(
             "dn: ou=People,dc=example,dc=com",
             "objectClass: top",
             "objectClass: organizationalUnit",
             "ou: People");
        conn.add(
             "dn: uid=test.user,ou=People,dc=example,dc=com",
             "objectClass: top",
             "objectClass: person",
             "objectClass: organizationalPerson",
             "objectClass: inetOrgPerson",
             "uid: test.user",
             "givenName: Test",
             "sn: User",
             "cn: Test User",
             "userPassword: password");

        ldapPasswordModify(ResultCode.SUCCESS,
             "--hostname", "localhost",
             "--port", String.valueOf(ds2.getListenPort()),
             "--userIdentity", "uid=test.user,ou=People,dc=example,dc=com",
             "--currentPassword", "password",
             "--newPassword", "newPassword",
             "--useAdministrativeSession",
             "--verbose");
      }
    }
  }



  /**
   * Tests the behavior for a request including all of the supported update
   * controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUpdateControls()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ldapPasswordModify(ResultCode.UNAVAILABLE_CRITICAL_EXTENSION,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--userIdentity", "uid=nonexistent,ou=People,dc=example,dc=com",
         "--newPassword", "newPassword",
         "--passwordChangeMethod", "password-modify-extended-operation",
         "--updateControl", "1.2.3.4:true",
         "--usePasswordPolicyControlOnUpdate",
         "--getPasswordValidationDetails",
         "--retireCurrentPassword",
         "--passwordUpdateBehavior", "is-self-change=true",
         "--passwordUpdateBehavior", "allow-pre-encoded-password=true",
         "--passwordUpdateBehavior", "skip-password-validation=true",
         "--passwordUpdateBehavior", "ignore-password-history=true",
         "--passwordUpdateBehavior", "ignore-minimum-password-age=true",
         "--passwordUpdateBehavior", "password-storage-scheme=SSHA",
         "--passwordUpdateBehavior", "must-change-password=true",
         "--useAssuredReplication",
         "--assuredReplicationLocalLevel", "none",
         "--assuredReplicationRemoteLevel", "none",
         "--assuredReplicationTimeout", "1s",
         "--operationPurpose", "testUpdateControls",
         "--verbose");

    ldapPasswordModify(ResultCode.UNAVAILABLE_CRITICAL_EXTENSION,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--userIdentity", "uid=nonexistent,ou=People,dc=example,dc=com",
         "--newPassword", "newPassword",
         "--passwordChangeMethod", "password-modify-extended-operation",
         "--updateControl", "1.2.3.4:true",
         "--purgeCurrentPassword",
         "--useAssuredReplication",
         "--assuredReplicationLocalLevel", "received-any-server",
         "--assuredReplicationRemoteLevel", "received-any-remote-location",
         "--verbose");

    ldapPasswordModify(ResultCode.UNAVAILABLE_CRITICAL_EXTENSION,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--userIdentity", "uid=nonexistent,ou=People,dc=example,dc=com",
         "--newPassword", "newPassword",
         "--passwordChangeMethod", "password-modify-extended-operation",
         "--updateControl", "1.2.3.4:true",
         "--useAssuredReplication",
         "--assuredReplicationLocalLevel", "processed-all-servers",
         "--assuredReplicationRemoteLevel", "received-all-remote-locations",
         "--verbose");

    ldapPasswordModify(ResultCode.UNAVAILABLE_CRITICAL_EXTENSION,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--userIdentity", "uid=nonexistent,ou=People,dc=example,dc=com",
         "--newPassword", "newPassword",
         "--passwordChangeMethod", "password-modify-extended-operation",
         "--updateControl", "1.2.3.4:true",
         "--useAssuredReplication",
         "--assuredReplicationLocalLevel", "processed-all-servers",
         "--assuredReplicationRemoteLevel", "processed-all-remote-servers",
         "--verbose");
  }



  /**
   * Tests the behavior of the {@code encodePasswordForActiveDirectory} method
   * when the provided password is {@code null}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEncodePasswordForActiveDirectoryNull()
         throws Exception
  {
    assertNull(LDAPPasswordModify.encodePasswordForActiveDirectory(null));
  }



  /**
   * Tests the behavior of the {@code handleUnsolicitedNotification} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHandleUnsolicitedNotification()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final LDAPPasswordModify tool = new LDAPPasswordModify(out, out);

    final InMemoryDirectoryServer ds = getTestDS(true, true);
    try (LDAPConnection conn = ds.getConnection())
    {
      tool.handleUnsolicitedNotification(conn,
           new NoticeOfDisconnectionExtendedResult(ResultCode.OTHER,
                "Disconnected"));
    }

    assertTrue(out.toByteArray().length > 0);
  }



  /**
   * Ensure that running the tool with the provided arguments yields the
   * expected result code.
   *
   * @param  expectedResultCode  The result code that is expected when running
   *                             the tool.
   * @param  args                The command-line arguments to provide when
   *                             running the tool.
   */
  private static void ldapPasswordModify(final ResultCode expectedResultCode,
                                         final String... args)
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode actualResultCode = LDAPPasswordModify.main(out, out, args);
    if (actualResultCode != expectedResultCode)
    {
      fail(StaticUtils.EOL +
           "Command-line arguments:  " + Arrays.toString(args) +
           StaticUtils.EOL +
           "Expected result code:  " +expectedResultCode +
           StaticUtils.EOL +
           "Actual result code:  " + actualResultCode +
           StaticUtils.EOL +
           "Output:" +
           StaticUtils.EOL +
           StaticUtils.toUTF8String(out.toByteArray()) +
           StaticUtils.EOL);
    }
  }
}
