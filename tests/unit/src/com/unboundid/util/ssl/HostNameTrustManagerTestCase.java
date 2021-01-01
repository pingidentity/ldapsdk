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
 * This class provides test coverage for the HostNameTrustManager class.
 */
public class HostNameTrustManagerTestCase
       extends SSLTestCase
{
  /**
   * Tests with a certificate that contains a non-wildcard hostname in the CN
   * subject attribute and that hostname matches one of the expected values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchCNNonWildcard()
         throws Exception
  {
    final HostNameTrustManager m = new HostNameTrustManager(false,
         "directory.example.com", "ds.example.com", "ldap.example.com");

    assertNotNull(m);

    assertFalse(m.allowWildcards());

    assertNotNull(m.getAcceptableHostNames());
    assertEquals(m.getAcceptableHostNames().size(), 3);
    assertTrue(m.getAcceptableHostNames().contains("directory.example.com"));
    assertTrue(m.getAcceptableHostNames().contains("ds.example.com"));
    assertTrue(m.getAcceptableHostNames().contains("ldap.example.com"));
    assertFalse(m.getAcceptableHostNames().contains("ldap.example.org"));

    final KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    final X509Certificate[] chain = ksManager.getCertificateChain("hnincn");
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkClientTrusted(chain, "RSA");

    m.checkServerTrusted(chain, "RSA");

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests with a certificate that contains a non-wildcard hostname in the CN
   * subject attribute and that hostname does not match any of the expected
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testNonMatchCNNonWildcard()
         throws Exception
  {
    final HostNameTrustManager m = new HostNameTrustManager(false,
         "directory.example.com", "ds.example.com");

    assertNotNull(m);

    final KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    final X509Certificate[] chain = ksManager.getCertificateChain("hnincn");
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkServerTrusted(chain, "RSA");
  }



  /**
   * Tests with a certificate that contains a wildcard hostname in the CN
   * subject attribute and that hostname matches one of the expected values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchCNWildcardAllowed()
         throws Exception
  {
    final HostNameTrustManager m = new HostNameTrustManager(true,
         "directory.example.com", "ds.example.com", "ldap.example.com");

    assertNotNull(m);

    final KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    final X509Certificate[] chain = ksManager.getCertificateChain("wcincn");
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkClientTrusted(chain, "RSA");

    m.checkServerTrusted(chain, "RSA");

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests with a certificate that contains a wildcard hostname in the CN
   * subject attribute and that hostname matches one of the expected values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testMatchCNWildcardForbidden()
         throws Exception
  {
    final HostNameTrustManager m = new HostNameTrustManager(false,
         "directory.example.com", "ds.example.com", "ldap.example.com");

    assertNotNull(m);

    final KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    final X509Certificate[] chain = ksManager.getCertificateChain("wcincn");
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkServerTrusted(chain, "RSA");
  }



  /**
   * Tests with a certificate that contains a non-wildcard hostname in the CN
   * subject attribute and that hostname does not match any of the expected
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testNonMatchCNWildcard()
         throws Exception
  {
    final HostNameTrustManager m = new HostNameTrustManager(true,
         "directory.example.org", "ds.example.org", "ldap.example.org");

    assertNotNull(m);

    final KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    final X509Certificate[] chain = ksManager.getCertificateChain("wcincn");
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkServerTrusted(chain, "RSA");
  }



  /**
   * Tests with a certificate that contains a non-wildcard hostname in a dNSName
   * subjectAltName extension and that hostname matches one of the expected
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchDNSSubjectAltNameNonWildcard()
         throws Exception
  {
    final HostNameTrustManager m = new HostNameTrustManager(false,
         "directory.example.com", "ds.example.com", "ldap.example.com");

    assertNotNull(m);

    final KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    final X509Certificate[] chain = ksManager.getCertificateChain("dnsaltname");
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkClientTrusted(chain, "RSA");

    m.checkServerTrusted(chain, "RSA");

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests with a certificate that contains a non-wildcard hostname in a dNSName
   * subjectAltName extension and that hostname does not match any of the
   * expected values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testNonMatchDNSSubjectAltNameNonWildcard()
         throws Exception
  {
    final HostNameTrustManager m = new HostNameTrustManager(false,
         "directory.example.com", "ds.example.com");

    assertNotNull(m);

    final KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    final X509Certificate[] chain = ksManager.getCertificateChain("dnsaltname");
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkServerTrusted(chain, "RSA");
  }



  /**
   * Tests with a certificate that contains a wildcard hostname in a dNSName
   * subjectAltName extension and that hostname matches one of the expected
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchDNSSubjectAltNameWildcardAllowed()
         throws Exception
  {
    final HostNameTrustManager m = new HostNameTrustManager(true,
         "directory.example.com", "ds.example.com", "ldap.example.com");

    assertNotNull(m);

    final KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    final X509Certificate[] chain =
         ksManager.getCertificateChain("dnsaltnamewc");
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkClientTrusted(chain, "RSA");

    m.checkServerTrusted(chain, "RSA");

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests with a certificate that contains a wildcard hostname in a dNSName
   * subjectAltName extension and that hostname matches one of the expected
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testMatchDNSSubjectAltNameWildcardForbidden()
         throws Exception
  {
    final HostNameTrustManager m = new HostNameTrustManager(false,
         "directory.example.com", "ds.example.com", "ldap.example.com");

    assertNotNull(m);

    final KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    final X509Certificate[] chain =
         ksManager.getCertificateChain("dnsaltnamewc");
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkServerTrusted(chain, "RSA");
  }



  /**
   * Tests with a certificate that contains a non-wildcard hostname in a dNSName
   * subjectAltName extension and that hostname does not match any of the
   * expected values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testNonMatchDNSSubjectAltNameWildcard()
         throws Exception
  {
    final HostNameTrustManager m = new HostNameTrustManager(true,
         "directory.example.org", "ds.example.org", "ldap.example.org");

    assertNotNull(m);

    final KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    final X509Certificate[] chain = ksManager.getCertificateChain("dnsaltname");
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkServerTrusted(chain, "RSA");
  }
}
