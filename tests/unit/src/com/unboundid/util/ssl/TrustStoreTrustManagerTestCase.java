/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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



import java.io.File;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.testng.annotations.Test;

import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides test coverage for the TrustStoreTrustManager class.
 */
public class TrustStoreTrustManagerTestCase
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
    TrustStoreTrustManager m = new TrustStoreTrustManager(getJKSKeyStorePath());

    assertNotNull(m);

    assertNotNull(m.getTrustStoreFile());

    assertNotNull(m.getTrustStoreFormat());

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



  /**
   * Tests the first constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1File()
         throws Exception
  {
    TrustStoreTrustManager m =
         new TrustStoreTrustManager(new File(getJKSKeyStorePath()));

    assertNotNull(m);

    assertNotNull(m.getTrustStoreFile());

    assertNotNull(m.getTrustStoreFormat());

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



  /**
   * Tests the second constructor with the JKS format.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2JKS()
         throws Exception
  {
    TrustStoreTrustManager m =
         new TrustStoreTrustManager(getJKSKeyStorePath(), getJKSKeyStorePIN(),
                                    "JKS", false);

    assertNotNull(m);

    assertNotNull(m.getTrustStoreFile());

    assertNotNull(m.getTrustStoreFormat());

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
   * Tests the second constructor with the JKS format.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2JKSFile()
         throws Exception
  {
    TrustStoreTrustManager m = new TrustStoreTrustManager(
         new File(getJKSKeyStorePath()), getJKSKeyStorePIN(), "JKS", false);

    assertNotNull(m);

    assertNotNull(m.getTrustStoreFile());

    assertNotNull(m.getTrustStoreFormat());

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
   * Tests the second constructor with the PKCS12 format.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2PKCS12()
         throws Exception
  {
    TrustStoreTrustManager m =
         new TrustStoreTrustManager(getPKCS12KeyStorePath(),
                                    getPKCS12KeyStorePIN(), "PKCS12", false);

    assertNotNull(m);

    assertNotNull(m.getTrustStoreFile());

    assertNotNull(m.getTrustStoreFormat());

    assertFalse(m.examineValidityDates());

    KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    X509Certificate[] chain =
         ksManager.getCertificateChain(getPKCS12KeyStoreAlias());
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkClientTrusted(chain, "RSA");

    m.checkServerTrusted(chain, "RSA");

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests the trust file trust manager with a {@code null} file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNullFile()
         throws Exception
  {
    new TrustStoreTrustManager((String) null);
  }



  /**
   * Tests the trust file trust manager with a nonexistent file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testNonexistentFile()
         throws Exception
  {
    File f = createTempFile();
    f.delete();

    TrustStoreTrustManager m = new TrustStoreTrustManager(f.getAbsolutePath());

    assertNotNull(m);

    assertNotNull(m.getTrustStoreFile());

    assertNotNull(m.getTrustStoreFormat());

    assertTrue(m.examineValidityDates());

    KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    X509Certificate[] chain =
         ksManager.getCertificateChain(getJKSKeyStoreAlias());
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkClientTrusted(chain, "RSA");
  }



  /**
   * Tests the trust file trust manager with an invalid file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testInvalidFile()
         throws Exception
  {
    File f = createTempFile("not a valid trust store");

    TrustStoreTrustManager m = new TrustStoreTrustManager(f.getAbsolutePath());

    assertNotNull(m);

    assertNotNull(m.getTrustStoreFile());

    assertNotNull(m.getTrustStoreFormat());

    assertTrue(m.examineValidityDates());

    KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    X509Certificate[] chain =
         ksManager.getCertificateChain(getJKSKeyStoreAlias());
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkServerTrusted(chain, "RSA");
  }



  /**
   * Tests the trust file trust manager with an invalid trust store format.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testInvalidTrustStoreFormat()
         throws Exception
  {
    TrustStoreTrustManager m =
         new TrustStoreTrustManager(getJKSKeyStorePath(), getJKSKeyStorePIN(),
                                    "invalid", true);

    assertNotNull(m);

    assertNotNull(m.getTrustStoreFile());

    assertNotNull(m.getTrustStoreFormat());

    assertTrue(m.examineValidityDates());

    KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    X509Certificate[] chain =
         ksManager.getCertificateChain(getJKSKeyStoreAlias());
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkServerTrusted(chain, "RSA");
  }
}
