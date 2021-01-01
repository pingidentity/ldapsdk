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
 * This class provides a set of test cases for the passphrase encryption cipher
 * type enum.
 */
public final class PassphraseEncryptionCipherTypeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the cipher type values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCipherType()
         throws Exception
  {
    for (final PassphraseEncryptionCipherType cipherType :
         PassphraseEncryptionCipherType.values())
    {
      assertNotNull(cipherType.getCipherTransformation());
      assertFalse(cipherType.getCipherTransformation().isEmpty());

      assertTrue(cipherType.getKeyLengthBits() > 0);

      assertNotNull(cipherType.getKeyFactoryAlgorithm());
      assertFalse(cipherType.getKeyFactoryAlgorithm().isEmpty());

      assertTrue(cipherType.getKeyFactoryIterationCount() > 0);

      assertTrue(cipherType.getKeyFactorySaltLengthBytes() > 0);

      assertTrue(cipherType.getInitializationVectorLengthBytes() > 0);

      assertNotNull(cipherType.getMacAlgorithm());
      assertFalse(cipherType.getMacAlgorithm().isEmpty());

      assertNotNull(cipherType.toString());

      assertEquals(PassphraseEncryptionCipherType.forName(cipherType.name()),
           cipherType);
      assertEquals(
           PassphraseEncryptionCipherType.forName(
                cipherType.name().toLowerCase()),
           cipherType);
      assertEquals(
           PassphraseEncryptionCipherType.forName(
                cipherType.name().replace('_', '-')),
           cipherType);
      assertEquals(
           PassphraseEncryptionCipherType.forName(
                cipherType.name().toLowerCase().replace('_', '-')),
           cipherType);

      assertEquals(PassphraseEncryptionCipherType.valueOf(cipherType.name()),
           cipherType);
    }

    assertNull(PassphraseEncryptionCipherType.forName("undefined"));

    assertNotNull(
         PassphraseEncryptionCipherType.getStrongestAvailableCipherType());
  }
}
