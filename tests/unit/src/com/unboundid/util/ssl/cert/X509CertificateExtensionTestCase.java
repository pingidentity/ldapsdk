/*
 * Copyright 2017-2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2017-2020 Ping Identity Corporation
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



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.OID;



/**
 * This class provides a set of test cases for the X509CertificateExtension
 * class.
 */
public final class X509CertificateExtensionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with a critical extension and a printable value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCriticalWithPrintableValue()
         throws Exception
  {
    X509CertificateExtension extension = new X509CertificateExtension(
         new OID("1.2.3.4"), true, "foo".getBytes("UTF-8"));

    extension = new X509CertificateExtension(extension);

    assertNotNull(extension.getOID());
    assertEquals(extension.getOID().toString(), "1.2.3.4");

    assertTrue(extension.isCritical());

    assertNotNull(extension.getValue());
    assertEquals(extension.getValue(), "foo".getBytes("UTF-8"));

    assertNotNull(extension.encode());

    assertNotNull(extension.getExtensionName());
    assertEquals(extension.getExtensionName(), "1.2.3.4");

    assertNotNull(extension.toString());
  }



  /**
   * Tests the behavior with a non-critical extension and a non-printable value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonCriticalWithNonPrintableValue()
         throws Exception
  {
    X509CertificateExtension extension = new X509CertificateExtension(
         new OID("1.2.3.5"), false, new byte[100]);

    extension = new X509CertificateExtension(extension);

    assertNotNull(extension.getOID());
    assertEquals(extension.getOID().toString(), "1.2.3.5");

    assertFalse(extension.isCritical());

    assertNotNull(extension.getValue());
    assertEquals(extension.getValue(), new byte[100]);

    assertNotNull(extension.encode());

    assertNotNull(extension.getExtensionName());
    assertEquals(extension.getExtensionName(), "1.2.3.5");

    assertNotNull(extension.toString());
  }



  /**
   * Tests the behavior when trying to encode an extension with a malformed OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testEncodeWithMalformedOID()
         throws Exception
  {
    final X509CertificateExtension extension = new X509CertificateExtension(
         new OID("1234.56789"), false, new byte[100]);
    extension.encode();
  }



  /**
   * Tests the behavior of the {@code decode} method when provided with an
   * element that is not a valid ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeElementNotSequence()
         throws Exception
  {
    X509CertificateExtension.decode(
         new ASN1OctetString("not a valid sequence"));
  }
}
