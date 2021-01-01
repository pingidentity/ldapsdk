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
package com.unboundid.util.ssl;



import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.testng.annotations.Test;



/**
 * This class provides test coverage for the NullTrustManager class.
 */
public class NullTrustManagerTestCase
       extends SSLTestCase
{
  /**
   * Tests the behavior of the trust manager.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTrustManager()
  {
    final NullTrustManager trustManager = NullTrustManager.getInstance();

    final X509Certificate[] certificates = trustManager.getAcceptedIssuers();
    assertNotNull(certificates);
    assertEquals(certificates.length, 0);

    try
    {
      trustManager.checkClientTrusted(certificates, "RSA");
      fail("Expected an exception from checkClientTrusted");
    }
    catch (final CertificateException e)
    {
      // This was expected.
    }

    try
    {
      trustManager.checkServerTrusted(certificates, "RSA");
      fail("Expected an exception from checkServerTrusted");
    }
    catch (final CertificateException e)
    {
      // This was expected.
    }
  }
}
