/*
 * Copyright 2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021 Ping Identity Corporation
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
 * Copyright (C) 2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.io.File;
import java.io.FileOutputStream;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the
 * {@code KeyStoreDataReplaceCertificateKeyStoreContent} class.
 */
public final class KeyStoreDataReplaceCertificateKeyStoreContentTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a key store content object with only the required
   * fields set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalFieldsSet()
         throws Exception
  {
    final byte[] testKeyStoreData = StaticUtils.getBytes("test-key-store-data");
    KeyStoreDataReplaceCertificateKeyStoreContent c =
         new KeyStoreDataReplaceCertificateKeyStoreContent(testKeyStoreData,
              "test-key-store-pin", null, null, null);

    c = KeyStoreDataReplaceCertificateKeyStoreContent.decodeInternal(
         c.encode());
    assertNotNull(c);

    assertNotNull(c.getKeyStoreData());
    assertEquals(c.getKeyStoreData(), testKeyStoreData);

    assertNotNull(c.getKeyStorePIN());
    assertEquals(c.getKeyStorePIN(), "test-key-store-pin");

    assertNull(c.getPrivateKeyPIN());

    assertNull(c.getKeyStoreType());

    assertNull(c.getSourceCertificateAlias());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior for a key store content object with values set for all
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllFieldsSet()
         throws Exception
  {
    final byte[] testKeyStoreData = StaticUtils.getBytes("test-key-store-data");

    final File testKeyStoreDataFile = createTempFile();
    assertTrue(testKeyStoreDataFile.delete());
    try (FileOutputStream outputStream =
              new FileOutputStream(testKeyStoreDataFile))
    {
      outputStream.write(testKeyStoreData);
    }

    KeyStoreDataReplaceCertificateKeyStoreContent c =
         new KeyStoreDataReplaceCertificateKeyStoreContent(testKeyStoreDataFile,
              "test-key-store-pin", "test-private-key-pin",
              "test-key-store-type", "test-source-cert-alias");

    c = KeyStoreDataReplaceCertificateKeyStoreContent.decodeInternal(
         c.encode());
    assertNotNull(c);

    assertNotNull(c.getKeyStoreData());
    assertEquals(c.getKeyStoreData(), testKeyStoreData);

    assertNotNull(c.getKeyStorePIN());
    assertEquals(c.getKeyStorePIN(), "test-key-store-pin");

    assertNotNull(c.getPrivateKeyPIN());
    assertEquals(c.getPrivateKeyPIN(), "test-private-key-pin");

    assertNotNull(c.getKeyStoreType());
    assertEquals(c.getKeyStoreType(), "test-key-store-type");

    assertNotNull(c.getSourceCertificateAlias());
    assertEquals(c.getSourceCertificateAlias(), "test-source-cert-alias");

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when attempting to decode an ASN.1 element that is not a
   * valid sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeElementNotSequence()
         throws Exception
  {
    try
    {
      KeyStoreDataReplaceCertificateKeyStoreContent.decodeInternal(
           new ASN1OctetString(
                KeyStoreDataReplaceCertificateKeyStoreContent.
                     TYPE_KEY_STORE_CONTENT,
                "not-a-valid-asn1-sequence"));
      fail("Expected an exception when trying to decode an encoded element " +
           "whose value is not a valid sequence.");
    }
    catch (final LDAPException e)
    {
      // This was expected.
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }
  }
}
