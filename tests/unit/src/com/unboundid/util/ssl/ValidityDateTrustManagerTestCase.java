/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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
package com.unboundid.util.ssl;



import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.testng.annotations.Test;



/**
 * This class provides test coverage for the ValidityDateTrustManager class.
 */
public class ValidityDateTrustManagerTestCase
       extends SSLTestCase
{
  /**
   * Tests with a certificate with a time between the validity dates.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValid()
         throws Exception
  {
    final ValidityDateTrustManager m = new ValidityDateTrustManager();

    assertNotNull(m);

    final KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    final X509Certificate[] chain =
         ksManager.getCertificateChain(getJKSKeyStoreAlias());
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkClientTrusted(chain, "RSA");

    m.checkServerTrusted(chain, "RSA");

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests with a certificate using a date that is before the certificate
   * becomes valid.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testNotYetValid()
         throws Exception
  {
    final ValidityDateTrustManager m = new ValidityDateTrustManager();

    assertNotNull(m);

    final KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    final X509Certificate[] chain =
         ksManager.getCertificateChain("notyetvalid");
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkServerTrusted(chain, "RSA");
  }



  /**
   * Tests with a certificate using a date that is after the certificate
   * expires.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testExpired()
         throws Exception
  {
    final ValidityDateTrustManager m = new ValidityDateTrustManager();

    assertNotNull(m);

    final KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    final X509Certificate[] chain = ksManager.getCertificateChain("expired");
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkServerTrusted(chain, "RSA");
  }
}
