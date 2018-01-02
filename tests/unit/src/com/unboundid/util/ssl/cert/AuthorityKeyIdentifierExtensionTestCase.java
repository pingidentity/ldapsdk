/*
 * Copyright 2017-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2017-2018 Ping Identity Corporation
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
package com.unboundid.util.ssl.cert;



import java.math.BigInteger;
import java.util.Collections;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.OID;



/**
 * This class provides test coverage for the AuthorityKeyIdentifierExtension
 * class.
 */
public class AuthorityKeyIdentifierExtensionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with a valid extension that doesn't have any components.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidExtensionNoComponents()
         throws Exception
  {
    AuthorityKeyIdentifierExtension e = new AuthorityKeyIdentifierExtension(
         true, null, null, null);

    e = new AuthorityKeyIdentifierExtension(e);

    assertNotNull(e.getOID());
    assertEquals(e.getOID().toString(), "2.5.29.35");

    assertTrue(e.isCritical());

    assertNotNull(e.getValue());

    assertNull(e.getKeyIdentifier());

    assertNull(e.getAuthorityCertIssuer());

    assertNull(e.getAuthorityCertSerialNumber());

    assertNotNull(e.getExtensionName());
    assertFalse(e.getExtensionName().equals("2.5.29.35"));

    assertNotNull(e.toString());
  }



  /**
   * Tests the behavior with a valid extension that has all components.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidExtensionAllComponents()
         throws Exception
  {
    AuthorityKeyIdentifierExtension e = new AuthorityKeyIdentifierExtension(
         false, new ASN1OctetString("keyIdentifier"),
         new GeneralNamesBuilder().addDNSName("ldap.example.com").build(),
         BigInteger.valueOf(12345L));

    e = new AuthorityKeyIdentifierExtension(e);

    assertNotNull(e.getOID());
    assertEquals(e.getOID().toString(), "2.5.29.35");

    assertFalse(e.isCritical());

    assertNotNull(e.getValue());

    assertNotNull(e.getKeyIdentifier());
    assertEquals(e.getKeyIdentifier().stringValue(), "keyIdentifier");

    assertNotNull(e.getAuthorityCertIssuer());
    assertEquals(e.getAuthorityCertIssuer().getDNSNames(),
         Collections.singletonList("ldap.example.com"));

    assertNotNull(e.getAuthorityCertSerialNumber());
    assertEquals(e.getAuthorityCertSerialNumber().longValue(), 12345L);

    assertNotNull(e.getExtensionName());
    assertFalse(e.getExtensionName().equals("2.5.29.35"));

    assertNotNull(e.toString());
  }



  /**
   * Tests the behavior when trying to create a value that has an illegal value
   * in an issuer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testCreateWithMalformedIssuer()
         throws Exception
  {
    final GeneralNames malformedAuthorityCertIssuer = new GeneralNamesBuilder().
         addRegisteredID(new OID("1234.5678")).build();
    new AuthorityKeyIdentifierExtension(true, null,
         malformedAuthorityCertIssuer, null);
  }



  /**
   * Tests the behavior when trying to decode an extension that can't be
   * decoded as a valid authority key identifier extension.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeMalformedExtension()
         throws Exception
  {
    new AuthorityKeyIdentifierExtension(new X509CertificateExtension(
         new OID("2.5.29.35"), true, "not a valid sequence".getBytes("UTF-8")));
  }
}
