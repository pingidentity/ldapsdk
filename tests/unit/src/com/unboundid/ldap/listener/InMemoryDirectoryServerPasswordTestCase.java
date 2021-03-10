/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
package com.unboundid.ldap.listener;



import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.util.Base64;
import com.unboundid.util.CryptoHelper;



/**
 * This class provides a set of test cases for the
 * {@code InMemoryDirectoryServerPassword} class.
 */
public final class InMemoryDirectoryServerPasswordTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with an unencoded password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnencodedPasswordWithoutEncoders()
         throws Exception
  {
    final ReadOnlyEntry userEntry = new ReadOnlyEntry(
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

    final InMemoryDirectoryServerPassword password =
         new InMemoryDirectoryServerPassword(new ASN1OctetString("password"),
              userEntry, "userPassword",
              Collections.<InMemoryPasswordEncoder>emptyList());

    assertNotNull(password.getStoredPassword());
    assertTrue(password.getStoredPassword().equalsIgnoreType(
         new ASN1OctetString("password")));

    assertNotNull(password.getAttributeName());
    assertEquals(password.getAttributeName(), "userPassword");

    assertFalse(password.isEncoded());

    assertNull(password.getPasswordEncoder());

    assertNotNull(password.getClearPassword());
    assertTrue(password.getClearPassword().equalsIgnoreType(
         new ASN1OctetString("password")));

    assertTrue(password.matchesClearPassword(new ASN1OctetString("password")));
    assertFalse(password.matchesClearPassword(new ASN1OctetString("wrong")));
  }



  /**
   * Tests the behavior with an unencoded password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnencodedPasswordWithEncoders()
         throws Exception
  {
    final ReadOnlyEntry userEntry = new ReadOnlyEntry(
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

    final MessageDigest sha1Digest = CryptoHelper.getMessageDigest("SHA-1");
    final List<InMemoryPasswordEncoder> passwordEncoders = Arrays.asList(
         new ClearInMemoryPasswordEncoder("{CLEAR}", null),
         new ClearInMemoryPasswordEncoder("{HEX}",
              HexPasswordEncoderOutputFormatter.getLowercaseInstance()),
         new ClearInMemoryPasswordEncoder("{BASE64}",
              Base64PasswordEncoderOutputFormatter.getInstance()),
         new UnsaltedMessageDigestInMemoryPasswordEncoder("{SHA}",
              Base64PasswordEncoderOutputFormatter.getInstance(), sha1Digest));

    final InMemoryDirectoryServerPassword password =
         new InMemoryDirectoryServerPassword(new ASN1OctetString("password"),
              userEntry, "userPassword", passwordEncoders);

    assertNotNull(password.getStoredPassword());
    assertTrue(password.getStoredPassword().equalsIgnoreType(
         new ASN1OctetString("password")));

    assertNotNull(password.getAttributeName());
    assertEquals(password.getAttributeName(), "userPassword");

    assertFalse(password.isEncoded());

    assertNull(password.getPasswordEncoder());

    assertNotNull(password.getClearPassword());
    assertTrue(password.getClearPassword().equalsIgnoreType(
         new ASN1OctetString("password")));

    assertTrue(password.matchesClearPassword(new ASN1OctetString("password")));
    assertFalse(password.matchesClearPassword(new ASN1OctetString("wrong")));
  }



  /**
   * Tests the behavior with a reversibly encoded password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReversiblyEncodedPassword()
         throws Exception
  {
    final ReadOnlyEntry userEntry = new ReadOnlyEntry(
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

    final MessageDigest sha1Digest = CryptoHelper.getMessageDigest("SHA-1");
    final List<InMemoryPasswordEncoder> passwordEncoders = Arrays.asList(
         new ClearInMemoryPasswordEncoder("{CLEAR}", null),
         new ClearInMemoryPasswordEncoder("{HEX}",
              HexPasswordEncoderOutputFormatter.getLowercaseInstance()),
         new ClearInMemoryPasswordEncoder("{BASE64}",
              Base64PasswordEncoderOutputFormatter.getInstance()),
         new UnsaltedMessageDigestInMemoryPasswordEncoder("{SHA}",
              Base64PasswordEncoderOutputFormatter.getInstance(), sha1Digest));

    final InMemoryDirectoryServerPassword password =
         new InMemoryDirectoryServerPassword(
              new ASN1OctetString("{CLEAR}password"), userEntry, "userPassword",
              passwordEncoders);

    assertNotNull(password.getStoredPassword());
    assertTrue(password.getStoredPassword().equalsIgnoreType(
         new ASN1OctetString("{CLEAR}password")));

    assertNotNull(password.getAttributeName());
    assertEquals(password.getAttributeName(), "userPassword");

    assertTrue(password.isEncoded());

    assertNotNull(password.getPasswordEncoder());
    assertEquals(password.getPasswordEncoder().getPrefix(), "{CLEAR}");

    assertNotNull(password.getClearPassword());
    assertTrue(password.getClearPassword().equalsIgnoreType(
         new ASN1OctetString("password")));

    assertTrue(password.matchesClearPassword(new ASN1OctetString("password")));
    assertFalse(password.matchesClearPassword(new ASN1OctetString("wrong")));
  }



  /**
   * Tests the behavior with a non-reversibly encoded password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonReversiblyEncodedPassword()
         throws Exception
  {
    final ReadOnlyEntry userEntry = new ReadOnlyEntry(
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

    final MessageDigest sha1Digest = CryptoHelper.getMessageDigest("SHA-1");
    final List<InMemoryPasswordEncoder> passwordEncoders = Arrays.asList(
         new ClearInMemoryPasswordEncoder("{CLEAR}", null),
         new ClearInMemoryPasswordEncoder("{HEX}",
              HexPasswordEncoderOutputFormatter.getLowercaseInstance()),
         new ClearInMemoryPasswordEncoder("{BASE64}",
              Base64PasswordEncoderOutputFormatter.getInstance()),
         new UnsaltedMessageDigestInMemoryPasswordEncoder("{SHA}",
              Base64PasswordEncoderOutputFormatter.getInstance(), sha1Digest));

    final String shaPassword = "{SHA}" +
         Base64.encode(sha1Digest.digest("password".getBytes("UTF-8")));

    final InMemoryDirectoryServerPassword password =
         new InMemoryDirectoryServerPassword(new ASN1OctetString(shaPassword),
              userEntry, "userPassword", passwordEncoders);

    assertNotNull(password.getStoredPassword());
    assertTrue(password.getStoredPassword().equalsIgnoreType(
         new ASN1OctetString(shaPassword)));

    assertNotNull(password.getAttributeName());
    assertEquals(password.getAttributeName(), "userPassword");

    assertTrue(password.isEncoded());

    assertNotNull(password.getPasswordEncoder());
    assertEquals(password.getPasswordEncoder().getPrefix(), "{SHA}");

    try
    {
      password.getClearPassword();
      fail("Expected an exception when trying to get the clear-text " +
           "representation of a non-reversible password");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    assertTrue(password.matchesClearPassword(new ASN1OctetString("password")));
    assertFalse(password.matchesClearPassword(new ASN1OctetString("wrong")));
  }
}
