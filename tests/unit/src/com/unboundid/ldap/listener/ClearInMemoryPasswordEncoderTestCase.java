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
import com.unboundid.util.LDAPSDKRuntimeException;



/**
 * This class provides a set of test cases for the in-memory password encoder
 * that "encodes" passwords using their clear-text representations.
 */
public final class ClearInMemoryPasswordEncoderTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the password encoder's behavior without any output formatting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutEncoder()
         throws Exception
  {
    final ClearInMemoryPasswordEncoder encoder =
         new ClearInMemoryPasswordEncoder("{CLEAR}", null);

    assertNotNull(encoder.getPrefix());
    assertEquals(encoder.getPrefix(), "{CLEAR}");

    assertNull(encoder.getOutputFormatter());

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
    assertEquals(encodedPassword.stringValue(), "{CLEAR}password");

    encoder.ensurePreEncodedPasswordAppearsValid(encodedPassword, userEntry,
         mods);

    assertTrue(encoder.clearPasswordMatchesEncodedPassword(clearPassword,
         encodedPassword, userEntry));
    assertFalse(encoder.clearPasswordMatchesEncodedPassword(
         new ASN1OctetString("wrong"), encodedPassword, userEntry));
    assertFalse(encoder.clearPasswordMatchesEncodedPassword(
         new ASN1OctetString("Password"), encodedPassword, userEntry));

    final ASN1OctetString extractedPassword =
         encoder.extractClearPasswordFromEncodedPassword(encodedPassword,
              userEntry);
    assertNotNull(extractedPassword);
    assertEquals(extractedPassword, clearPassword);

    assertNotNull(encoder.toString());
  }



  /**
   * Tests the password encoder's behavior with a hex output formatter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutHexOutputFormatter()
         throws Exception
  {
    final ClearInMemoryPasswordEncoder encoder =
         new ClearInMemoryPasswordEncoder("{HEX}",
              HexPasswordEncoderOutputFormatter.getLowercaseInstance());

    assertNotNull(encoder.getPrefix());
    assertEquals(encoder.getPrefix(), "{HEX}");

    assertNotNull(encoder.getOutputFormatter());
    assertTrue(encoder.getOutputFormatter() instanceof
         HexPasswordEncoderOutputFormatter);

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
    assertEquals(encodedPassword.stringValue(), "{HEX}70617373776f7264");

    encoder.ensurePreEncodedPasswordAppearsValid(encodedPassword, userEntry,
         mods);

    assertTrue(encoder.clearPasswordMatchesEncodedPassword(clearPassword,
         encodedPassword, userEntry));
    assertFalse(encoder.clearPasswordMatchesEncodedPassword(
         new ASN1OctetString("wrong"), encodedPassword, userEntry));
    assertFalse(encoder.clearPasswordMatchesEncodedPassword(
         new ASN1OctetString("Password"), encodedPassword, userEntry));

    final ASN1OctetString extractedPassword =
         encoder.extractClearPasswordFromEncodedPassword(encodedPassword,
              userEntry);
    assertNotNull(extractedPassword);
    assertEquals(extractedPassword, clearPassword);

    assertNotNull(encoder.toString());
  }



  /**
   * Tests the behavior when trying to create a password encoder with a
   * {@code null} prefix.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKRuntimeException.class })
  public void testCreateEncoderWithNullPrefix()
         throws Exception
  {
    new ClearInMemoryPasswordEncoder(null, null);
  }



  /**
   * Tests the behavior when trying to create a password encoder with an empty
   * prefix.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKRuntimeException.class })
  public void testCreateEncoderWithEmptyPrefix()
         throws Exception
  {
    new ClearInMemoryPasswordEncoder("", null);
  }



  /**
   * Tests the behavior when trying to encode an empty password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testEncodeEmptyPassword()
         throws Exception
  {
    final ClearInMemoryPasswordEncoder encoder =
         new ClearInMemoryPasswordEncoder("{CLEAR}", null);

    final ASN1OctetString clearPassword = new ASN1OctetString("");

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

    encoder.encodePassword(clearPassword, userEntry, mods);
  }



  /**
   * Tests the behavior when trying to validate a pre-encoded password that
   * does not start with the right prefix.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testValidatePreEncodedPasswordWrongPrefix()
         throws Exception
  {
    final ClearInMemoryPasswordEncoder encoder =
         new ClearInMemoryPasswordEncoder("{CLEAR}", null);

    final ASN1OctetString clearPassword =
         new ASN1OctetString("{WRONG}password");

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

    encoder.ensurePreEncodedPasswordAppearsValid(clearPassword, userEntry,
         mods);
  }



  /**
   * Tests the behavior when trying to validate a pre-encoded password in which
   * the entire encoded password is shorter than the expected prefix.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testValidatePreEncodedPasswordShorterThanPrefix()
         throws Exception
  {
    final ClearInMemoryPasswordEncoder encoder =
         new ClearInMemoryPasswordEncoder("{CLEAR}", null);

    final ASN1OctetString clearPassword = new ASN1OctetString("{X}x");

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

    encoder.ensurePreEncodedPasswordAppearsValid(clearPassword, userEntry,
         mods);
  }



  /**
   * Tests the behavior when trying to validate a pre-encoded password in in
   * which a formatter is configured but the pre-encoded value isn't valid
   * according to that format.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testValidatePreEncodedPasswordImproperlyFormatted()
         throws Exception
  {
    final ClearInMemoryPasswordEncoder encoder =
         new ClearInMemoryPasswordEncoder("{HEX}",
              HexPasswordEncoderOutputFormatter.getLowercaseInstance());

    final ASN1OctetString clearPassword = new ASN1OctetString("{HEX}password");

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

    encoder.ensurePreEncodedPasswordAppearsValid(clearPassword, userEntry,
         mods);
  }



  /**
   * Tests the behavior when trying to determine whether an empty clear-text
   * password matches an encoded password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyClearPasswordMatches()
         throws Exception
  {
    final ClearInMemoryPasswordEncoder encoder =
         new ClearInMemoryPasswordEncoder("{CLEAR}", null);

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
         new ASN1OctetString(""), new ASN1OctetString("{CLEAR}"), userEntry));
  }



  /**
   * Tests the behavior when trying to determine whether a clear-text password
   * matches an encoded password that doesn't start with the right prefix.
   * password matches an encoded password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testClearPasswordMatchesEncodedPasswordWithWrongPrefix()
         throws Exception
  {
    final ClearInMemoryPasswordEncoder encoder =
         new ClearInMemoryPasswordEncoder("{CLEAR}", null);

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
         new ASN1OctetString("{WRONG}password"), userEntry));
  }



  /**
   * Tests the behavior when trying to determine whether a clear-text password
   * matches an encoded password that doesn't use the right output formatting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testClearPasswordMatchesEncodedPasswordWithWrongFormatting()
         throws Exception
  {
    final ClearInMemoryPasswordEncoder encoder =
         new ClearInMemoryPasswordEncoder("{HEX}",
              HexPasswordEncoderOutputFormatter.getLowercaseInstance());

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

    encoder.clearPasswordMatchesEncodedPassword(new ASN1OctetString("password"),
         new ASN1OctetString("{HEX}password"), userEntry);
  }



  /**
   * Tests the behavior when trying to determine whether a clear-text password
   * matches an encoded password that consists only of the prefix.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testClearPasswordMatchesEmptyEncodedPassword()
         throws Exception
  {
    final ClearInMemoryPasswordEncoder encoder =
         new ClearInMemoryPasswordEncoder("{CLEAR}", null);

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
         new ASN1OctetString("password"), new ASN1OctetString("{CLEAR}"),
         userEntry));
  }



  /**
   * Tests the behavior when trying to extract the clear-text password from an
   * encoded password that doesn't start with the right prefix.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testExtractClearPasswordFromEncodedPasswordWithWrongPrefix()
         throws Exception
  {
    final ClearInMemoryPasswordEncoder encoder =
         new ClearInMemoryPasswordEncoder("{CLEAR}", null);

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

    encoder.extractClearPasswordFromEncodedPassword(
         new ASN1OctetString("{WRONG}password"), userEntry);
  }



  /**
   * Tests the behavior when trying to extract the clear-text password from an
   * encoded password that doesn't use the right output formatting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testExtractClearPasswordFromEncodedPasswordWithWrongFormatting()
         throws Exception
  {
    final ClearInMemoryPasswordEncoder encoder =
         new ClearInMemoryPasswordEncoder("{HEX}",
              HexPasswordEncoderOutputFormatter.getLowercaseInstance());

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

    encoder.extractClearPasswordFromEncodedPassword(
         new ASN1OctetString("{HEX}aPassword"), userEntry);
  }
}
