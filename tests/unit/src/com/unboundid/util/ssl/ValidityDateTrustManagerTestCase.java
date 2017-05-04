/*
 * Copyright 2012-2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2012-2017 Ping Identity Corporation
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
