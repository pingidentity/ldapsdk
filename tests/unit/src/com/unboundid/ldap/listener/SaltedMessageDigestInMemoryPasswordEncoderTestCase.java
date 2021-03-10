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



import java.util.Collections;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.LDAPSDKRuntimeException;



/**
 * This class provides a set of test cases for the in-memory password encoder
 * that uses a salted message digest to encode passwords.
 */
public final class SaltedMessageDigestInMemoryPasswordEncoderTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with a SHA-1 digest using base64 formatting.  The
   * salt will be appended to both the clear-text password and to the digest.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSHA1WithBase64()
         throws Exception
  {
    final SaltedMessageDigestInMemoryPasswordEncoder encoder =
         new SaltedMessageDigestInMemoryPasswordEncoder("{SSHA}",
              Base64PasswordEncoderOutputFormatter.getInstance(),
              CryptoHelper.getMessageDigest("SHA-1"), 8, true, true);

    assertNotNull(encoder.getPrefix());
    assertEquals(encoder.getPrefix(), "{SSHA}");

    assertNotNull(encoder.getOutputFormatter());

    assertNotNull(encoder.getDigestAlgorithm());
    assertEquals(encoder.getDigestAlgorithm(), "SHA-1");

    assertEquals(encoder.getDigestLengthBytes(), 20);

    assertEquals(encoder.getNumSaltBytes(), 8);

    assertTrue(encoder.isSaltAfterClearPassword());

    assertTrue(encoder.isSaltAfterMessageDigest());

    final ASN1OctetString clearPassword = new ASN1OctetString("password");

    final ReadOnlyEntry userEntry =  new ReadOnlyEntry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "Cn: Test User",
         "userPassword: password");

    final List<Modification> mods = Collections.emptyList();

    final ASN1OctetString encodedPassword = encoder.encodePassword(
         clearPassword, userEntry, mods);
    assertNotNull(encodedPassword);
    assertTrue(encodedPassword.stringValue().startsWith("{SSHA}"));

    encoder.ensurePreEncodedPasswordAppearsValid(encodedPassword, userEntry,
         mods);

    assertTrue(encoder.clearPasswordMatchesEncodedPassword(clearPassword,
         encodedPassword, userEntry));
    assertFalse(encoder.clearPasswordMatchesEncodedPassword(
         new ASN1OctetString("wrong"), encodedPassword, userEntry));
    assertFalse(encoder.clearPasswordMatchesEncodedPassword(
         new ASN1OctetString("Password"), encodedPassword, userEntry));

    assertNotNull(encoder.toString());
  }



  /**
   * Tests the behavior with a 256-bit SHA-2 digest using hex formatting.
   * The salt will be prepended to both the clear-text password and to the
   * digest.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSHA256WithHex()
         throws Exception
  {
    final SaltedMessageDigestInMemoryPasswordEncoder encoder =
         new SaltedMessageDigestInMemoryPasswordEncoder("{SSHA256}",
              HexPasswordEncoderOutputFormatter.getLowercaseInstance(),
              CryptoHelper.getMessageDigest("SHA-256"), 16, false, false);

    assertNotNull(encoder.getPrefix());
    assertEquals(encoder.getPrefix(), "{SSHA256}");

    assertNotNull(encoder.getOutputFormatter());

    assertNotNull(encoder.getDigestAlgorithm());
    assertEquals(encoder.getDigestAlgorithm(), "SHA-256");

    assertEquals(encoder.getDigestLengthBytes(), 32);

    assertEquals(encoder.getNumSaltBytes(), 16);

    assertFalse(encoder.isSaltAfterClearPassword());

    assertFalse(encoder.isSaltAfterMessageDigest());

    final ASN1OctetString clearPassword = new ASN1OctetString("password");

    final ReadOnlyEntry userEntry =  new ReadOnlyEntry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "Cn: Test User",
         "userPassword: password");

    final List<Modification> mods = Collections.emptyList();

    final ASN1OctetString encodedPassword = encoder.encodePassword(
         clearPassword, userEntry, mods);
    assertNotNull(encodedPassword);
    assertTrue(encodedPassword.stringValue().startsWith("{SSHA256}"));

    encoder.ensurePreEncodedPasswordAppearsValid(encodedPassword, userEntry,
         mods);

    assertTrue(encoder.clearPasswordMatchesEncodedPassword(clearPassword,
         encodedPassword, userEntry));
    assertFalse(encoder.clearPasswordMatchesEncodedPassword(
         new ASN1OctetString("wrong"), encodedPassword, userEntry));
    assertFalse(encoder.clearPasswordMatchesEncodedPassword(
         new ASN1OctetString("Password"), encodedPassword, userEntry));

    assertNotNull(encoder.toString());
  }



  /**
   * Tests the behavior with a 512-bit SHA-2 digest using no output formatting.
   * The salt will be appended to the clear-text password but prepended to the
   * message digest.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSHA512WithNoFormatting()
         throws Exception
  {
    final SaltedMessageDigestInMemoryPasswordEncoder encoder =
         new SaltedMessageDigestInMemoryPasswordEncoder("{SSHA512}", null,
              CryptoHelper.getMessageDigest("SHA-512"), 32, true, false);

    assertNotNull(encoder.getPrefix());
    assertEquals(encoder.getPrefix(), "{SSHA512}");

    assertNull(encoder.getOutputFormatter());

    assertNotNull(encoder.getDigestAlgorithm());
    assertEquals(encoder.getDigestAlgorithm(), "SHA-512");

    assertEquals(encoder.getDigestLengthBytes(), 64);

    assertEquals(encoder.getNumSaltBytes(), 32);

    assertTrue(encoder.isSaltAfterClearPassword());

    assertFalse(encoder.isSaltAfterMessageDigest());

    final ASN1OctetString clearPassword = new ASN1OctetString("password");

    final ReadOnlyEntry userEntry =  new ReadOnlyEntry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "Cn: Test User",
         "userPassword: password");

    final List<Modification> mods = Collections.emptyList();

    final ASN1OctetString encodedPassword = encoder.encodePassword(
         clearPassword, userEntry, mods);
    assertNotNull(encodedPassword);
    assertTrue(
         encoder.passwordStartsWithPrefix(new ASN1OctetString("{SSHA512}")));

    encoder.ensurePreEncodedPasswordAppearsValid(encodedPassword, userEntry,
         mods);

    assertTrue(encoder.clearPasswordMatchesEncodedPassword(clearPassword,
         encodedPassword, userEntry));
    assertFalse(encoder.clearPasswordMatchesEncodedPassword(
         new ASN1OctetString("wrong"), encodedPassword, userEntry));
    assertFalse(encoder.clearPasswordMatchesEncodedPassword(
         new ASN1OctetString("Password"), encodedPassword, userEntry));

    assertNotNull(encoder.toString());
  }



  /**
   * Tests the behavior with a variable-length message digest.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKRuntimeException.class })
  public void testVariableLengthDigest()
         throws Exception
  {
    new SaltedMessageDigestInMemoryPasswordEncoder("{TEST}", null,
         new TestPassThroughMessageDigest(), 8, true, true);
  }



  /**
   * Tests the behavior when trying to use zero salt bytes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKRuntimeException.class })
  public void testZeroSaltBytes()
         throws Exception
  {
    new SaltedMessageDigestInMemoryPasswordEncoder("{SSHA}",
         Base64PasswordEncoderOutputFormatter.getInstance(),
         CryptoHelper.getMessageDigest("SHA-1"), 0, true, true);
  }



  /**
   * Tests the behavior when trying to validate an encoded password whose length
   * does not match the digest length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testValidatePreEncodedPasswordWithInvalidLength()
         throws Exception
  {
    final SaltedMessageDigestInMemoryPasswordEncoder encoder =
         new SaltedMessageDigestInMemoryPasswordEncoder("{SSHA256}",
              HexPasswordEncoderOutputFormatter.getLowercaseInstance(),
              CryptoHelper.getMessageDigest("SHA-256"), 16, true, true);

    final ReadOnlyEntry userEntry =  new ReadOnlyEntry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "Cn: Test User",
         "userPassword: password");

    final List<Modification> mods = Collections.emptyList();

    encoder.ensurePreEncodedPasswordAppearsValid(
         new ASN1OctetString("{SSHA256}abcdef"), userEntry, mods);
  }



  /**
   * Tests the behavior when trying to determine whether a clear-text password
   * matches an encoded password that is too short.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordMatchesTooShort()
         throws Exception
  {
    final SaltedMessageDigestInMemoryPasswordEncoder encoder =
         new SaltedMessageDigestInMemoryPasswordEncoder("{SSHA256}",
              HexPasswordEncoderOutputFormatter.getLowercaseInstance(),
              CryptoHelper.getMessageDigest("SHA-256"), 16, false, true);

    final ReadOnlyEntry userEntry =  new ReadOnlyEntry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "Cn: Test User",
         "userPassword: password");

    assertFalse(encoder.clearPasswordMatchesEncodedPassword(
         new ASN1OctetString("password"),
         new ASN1OctetString("{SSHA256}abcdef"), userEntry));
  }



  /**
   * Tests the behavior when trying to extract a clear-text password from an
   * encoded password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testExtractClearPassword()
         throws Exception
  {
    final SaltedMessageDigestInMemoryPasswordEncoder encoder =
         new SaltedMessageDigestInMemoryPasswordEncoder("{SSHA256}",
              HexPasswordEncoderOutputFormatter.getLowercaseInstance(),
              CryptoHelper.getMessageDigest("SHA-256"), 16, false, true);

    final ReadOnlyEntry userEntry =  new ReadOnlyEntry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "Cn: Test User",
         "userPassword: password");

    final List<Modification> mods = Collections.emptyList();

    final ASN1OctetString encodedPassword = encoder.encodePassword(
         new ASN1OctetString("password"), userEntry, mods);

    encoder.extractClearPasswordFromEncodedPassword(encodedPassword, userEntry);
  }
}
