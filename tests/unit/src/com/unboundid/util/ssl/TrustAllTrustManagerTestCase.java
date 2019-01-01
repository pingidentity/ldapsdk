/*
 * Copyright 2008-2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2019 Ping Identity Corporation
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



import java.security.cert.X509Certificate;

import org.testng.annotations.Test;



/**
 * This class provides test coverage for the TrustAllTrustManager class.
 */
public class TrustAllTrustManagerTestCase
       extends SSLTestCase
{
  /**
   * Tests the first constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    TrustAllTrustManager m = new TrustAllTrustManager();

    assertNotNull(m);

    assertFalse(m.examineValidityDates());

    KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    X509Certificate[] chain =
         ksManager.getCertificateChain(getJKSKeyStoreAlias());
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkClientTrusted(chain, "RSA");

    m.checkServerTrusted(chain, "RSA");

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests the second constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    TrustAllTrustManager m = new TrustAllTrustManager(true);

    assertNotNull(m);

    assertTrue(m.examineValidityDates());

    KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    X509Certificate[] chain =
         ksManager.getCertificateChain(getJKSKeyStoreAlias());
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkClientTrusted(chain, "RSA");

    m.checkServerTrusted(chain, "RSA");

    assertNotNull(m.getAcceptedIssuers());
  }
}
