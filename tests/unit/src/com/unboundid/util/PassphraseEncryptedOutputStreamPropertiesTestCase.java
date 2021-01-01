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
package com.unboundid.util;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the passphrase-encrypted output
 * stream properties class.
 */
public final class PassphraseEncryptedOutputStreamPropertiesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when using the default values for all properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultProperties()
         throws Exception
  {
    final PassphraseEncryptedOutputStreamProperties properties =
         new PassphraseEncryptedOutputStreamProperties(
              PassphraseEncryptionCipherType.AES_128);

    assertNotNull(properties.getCipherType());
    assertEquals(properties.getCipherType(),
         PassphraseEncryptionCipherType.AES_128);

    assertTrue(properties.writeHeaderToStream());

    assertEquals(properties.getKeyFactoryIterationCount(),
         PassphraseEncryptionCipherType.AES_128.getKeyFactoryIterationCount());

    assertNull(properties.getKeyIdentifier());

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior when using non-default values for all properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonDefaultProperties()
         throws Exception
  {
    final PassphraseEncryptedOutputStreamProperties properties =
         new PassphraseEncryptedOutputStreamProperties(
              PassphraseEncryptionCipherType.AES_256);
    properties.setWriteHeaderToStream(false);
    properties.setKeyFactoryIterationCount(12345);
    properties.setKeyIdentifier("the-key-identifier");

    assertNotNull(properties.getCipherType());
    assertEquals(properties.getCipherType(),
         PassphraseEncryptionCipherType.AES_256);

    assertFalse(properties.writeHeaderToStream());

    assertEquals(properties.getKeyFactoryIterationCount(), 12345);

    assertNotNull(properties.getKeyIdentifier());
    assertEquals(properties.getKeyIdentifier(), "the-key-identifier");

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the properties related to writing the header.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWriteHeaderToStream()
         throws Exception
  {
    final PassphraseEncryptedOutputStreamProperties properties =
         new PassphraseEncryptedOutputStreamProperties(
              PassphraseEncryptionCipherType.AES_128);

    assertNotNull(properties.getCipherType());
    assertEquals(properties.getCipherType(),
         PassphraseEncryptionCipherType.AES_128);

    assertTrue(properties.writeHeaderToStream());

    assertEquals(properties.getKeyFactoryIterationCount(),
         PassphraseEncryptionCipherType.AES_128.getKeyFactoryIterationCount());

    assertNull(properties.getKeyIdentifier());

    assertNotNull(properties.toString());


    properties.setWriteHeaderToStream(false);

    assertNotNull(properties.getCipherType());
    assertEquals(properties.getCipherType(),
         PassphraseEncryptionCipherType.AES_128);

    assertFalse(properties.writeHeaderToStream());

    assertEquals(properties.getKeyFactoryIterationCount(),
         PassphraseEncryptionCipherType.AES_128.getKeyFactoryIterationCount());

    assertNull(properties.getKeyIdentifier());

    assertNotNull(properties.toString());


    properties.setWriteHeaderToStream(true);

    assertNotNull(properties.getCipherType());
    assertEquals(properties.getCipherType(),
         PassphraseEncryptionCipherType.AES_128);

    assertTrue(properties.writeHeaderToStream());

    assertEquals(properties.getKeyFactoryIterationCount(),
         PassphraseEncryptionCipherType.AES_128.getKeyFactoryIterationCount());

    assertNull(properties.getKeyIdentifier());

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the properties related to the key factory iteration
   * count.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testKeyFactoryIterationCount()
         throws Exception
  {
    final PassphraseEncryptedOutputStreamProperties properties =
         new PassphraseEncryptedOutputStreamProperties(
              PassphraseEncryptionCipherType.AES_256);

    assertNotNull(properties.getCipherType());
    assertEquals(properties.getCipherType(),
         PassphraseEncryptionCipherType.AES_256);

    assertTrue(properties.writeHeaderToStream());

    assertEquals(properties.getKeyFactoryIterationCount(),
         PassphraseEncryptionCipherType.AES_256.getKeyFactoryIterationCount());

    assertNull(properties.getKeyIdentifier());

    assertNotNull(properties.toString());


    properties.setKeyFactoryIterationCount(5678);

    assertNotNull(properties.getCipherType());
    assertEquals(properties.getCipherType(),
         PassphraseEncryptionCipherType.AES_256);

    assertTrue(properties.writeHeaderToStream());

    assertEquals(properties.getKeyFactoryIterationCount(), 5678);

    assertNull(properties.getKeyIdentifier());

    assertNotNull(properties.toString());


    properties.setKeyFactoryIterationCount(null);

    assertNotNull(properties.getCipherType());
    assertEquals(properties.getCipherType(),
         PassphraseEncryptionCipherType.AES_256);

    assertTrue(properties.writeHeaderToStream());

    assertEquals(properties.getKeyFactoryIterationCount(),
         PassphraseEncryptionCipherType.AES_256.getKeyFactoryIterationCount());

    assertNull(properties.getKeyIdentifier());

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the properties related to the key identifier.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testKeyIdentifier()
         throws Exception
  {
    final PassphraseEncryptedOutputStreamProperties properties =
         new PassphraseEncryptedOutputStreamProperties(
              PassphraseEncryptionCipherType.AES_256);

    assertNotNull(properties.getCipherType());
    assertEquals(properties.getCipherType(),
         PassphraseEncryptionCipherType.AES_256);

    assertTrue(properties.writeHeaderToStream());

    assertEquals(properties.getKeyFactoryIterationCount(),
         PassphraseEncryptionCipherType.AES_256.getKeyFactoryIterationCount());

    assertNull(properties.getKeyIdentifier());

    assertNotNull(properties.toString());


    properties.setKeyIdentifier("foo");

    assertNotNull(properties.getCipherType());
    assertEquals(properties.getCipherType(),
         PassphraseEncryptionCipherType.AES_256);

    assertTrue(properties.writeHeaderToStream());

    assertEquals(properties.getKeyFactoryIterationCount(),
         PassphraseEncryptionCipherType.AES_256.getKeyFactoryIterationCount());

    assertNotNull(properties.getKeyIdentifier());
    assertEquals(properties.getKeyIdentifier(), "foo");

    assertNotNull(properties.toString());


    properties.setKeyIdentifier(null);

    assertNotNull(properties.getCipherType());
    assertEquals(properties.getCipherType(),
         PassphraseEncryptionCipherType.AES_256);

    assertTrue(properties.writeHeaderToStream());

    assertEquals(properties.getKeyFactoryIterationCount(),
         PassphraseEncryptionCipherType.AES_256.getKeyFactoryIterationCount());

    assertNull(properties.getKeyIdentifier());

    assertNotNull(properties.toString());
  }
}
