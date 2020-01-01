/*
 * Copyright 2012-2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2012-2020 Ping Identity Corporation
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
 * This class provides test coverage for the AggregateTrustManager class.
 */
public class AggregateTrustManagerTestCase
       extends SSLTestCase
{
  /**
   * Tests with a certificate that satisfies the criteria for all of the
   * associated trust managers when all of them must be satisfied.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testANDMatchesAll()
         throws Exception
  {
    final AggregateTrustManager m = new AggregateTrustManager(true,
         new ValidityDateTrustManager(),
         new HostNameTrustManager(false, "ldap.example.com"));

    assertNotNull(m);

    assertTrue(m.requireAllAccepted());

    assertNotNull(m.getAssociatedTrustManagers());
    assertEquals(m.getAssociatedTrustManagers().size(), 2);

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
   * Tests with a certificate that satisfies the criteria for one of the
   * associated trust managers when all of them must be satisfied.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testANDMatchesOneClient()
         throws Exception
  {
    final AggregateTrustManager m = new AggregateTrustManager(true,
         new ValidityDateTrustManager(),
         new HostNameTrustManager(false, "ds.example.com"));

    assertNotNull(m);

    assertTrue(m.requireAllAccepted());

    assertNotNull(m.getAssociatedTrustManagers());
    assertEquals(m.getAssociatedTrustManagers().size(), 2);

    final KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    final X509Certificate[] chain = ksManager.getCertificateChain("hnincn");
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkClientTrusted(chain, "RSA");
  }



  /**
   * Tests with a certificate that satisfies the criteria for one of the
   * associated trust managers when all of them must be satisfied.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testANDMatchesOneServer()
         throws Exception
  {
    final AggregateTrustManager m = new AggregateTrustManager(true,
         new ValidityDateTrustManager(),
         new HostNameTrustManager(false, "ds.example.com"));

    assertNotNull(m);

    assertTrue(m.requireAllAccepted());

    assertNotNull(m.getAssociatedTrustManagers());
    assertEquals(m.getAssociatedTrustManagers().size(), 2);

    final KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    final X509Certificate[] chain = ksManager.getCertificateChain("hnincn");
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkServerTrusted(chain, "RSA");
  }



  /**
   * Tests with a certificate that satisfies the criteria for one of the
   * associated trust managers when all of them must be satisfied.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testANDMatchesNoneClient()
         throws Exception
  {
    final AggregateTrustManager m = new AggregateTrustManager(true,
         new ValidityDateTrustManager(),
         new HostNameTrustManager(false, "ds.example.com"));

    assertNotNull(m);

    assertTrue(m.requireAllAccepted());

    assertNotNull(m.getAssociatedTrustManagers());
    assertEquals(m.getAssociatedTrustManagers().size(), 2);

    final KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    final X509Certificate[] chain = ksManager.getCertificateChain("expired");
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkClientTrusted(chain, "RSA");
  }



  /**
   * Tests with a certificate that satisfies the criteria for one of the
   * associated trust managers when all of them must be satisfied.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testANDMatchesNoneServer()
         throws Exception
  {
    final AggregateTrustManager m = new AggregateTrustManager(true,
         new ValidityDateTrustManager(),
         new HostNameTrustManager(false, "ds.example.com"));

    assertNotNull(m);

    assertTrue(m.requireAllAccepted());

    assertNotNull(m.getAssociatedTrustManagers());
    assertEquals(m.getAssociatedTrustManagers().size(), 2);

    final KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    final X509Certificate[] chain = ksManager.getCertificateChain("expired");
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkServerTrusted(chain, "RSA");
  }



  /**
   * Tests with a certificate that satisfies the criteria for all of the
   * associated trust managers when at least one of them must be satisfied.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testORMatchesAll()
         throws Exception
  {
    final AggregateTrustManager m = new AggregateTrustManager(false,
         new ValidityDateTrustManager(),
         new HostNameTrustManager(false, "ldap.example.com"));

    assertNotNull(m);

    assertFalse(m.requireAllAccepted());

    assertNotNull(m.getAssociatedTrustManagers());
    assertEquals(m.getAssociatedTrustManagers().size(), 2);

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
   * Tests with a certificate that satisfies the criteria for one of the
   * associated trust managers when at least one of them must be satisfied.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testORMatchesOne()
         throws Exception
  {
    final AggregateTrustManager m = new AggregateTrustManager(false,
         new ValidityDateTrustManager(),
         new HostNameTrustManager(false, "ds.example.com"));

    assertNotNull(m);

    assertFalse(m.requireAllAccepted());

    assertNotNull(m.getAssociatedTrustManagers());
    assertEquals(m.getAssociatedTrustManagers().size(), 2);

    final KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    final X509Certificate[] chain = ksManager.getCertificateChain("hnincn");
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkClientTrusted(chain, "RSA");

    m.checkServerTrusted(chain, "RSA");

    assertNotNull(m.getAcceptedIssuers());

    m.checkServerTrusted(chain, "RSA");
  }



  /**
   * Tests with a certificate that satisfies the criteria for one of the
   * associated trust managers when none of them are satisfied and there are
   * multiple trust managers.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testORMatchesNoneClient()
         throws Exception
  {
    final AggregateTrustManager m = new AggregateTrustManager(false,
         new ValidityDateTrustManager(),
         new HostNameTrustManager(false, "ds.example.com"));

    assertNotNull(m);

    assertFalse(m.requireAllAccepted());

    assertNotNull(m.getAssociatedTrustManagers());
    assertEquals(m.getAssociatedTrustManagers().size(), 2);

    final KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    final X509Certificate[] chain = ksManager.getCertificateChain("expired");
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkClientTrusted(chain, "RSA");
  }



  /**
   * Tests with a certificate that satisfies the criteria for one of the
   * associated trust managers when none of them are satisfied and there are
   * multiple trust managers.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testORMatchesNoneServer()
         throws Exception
  {
    final AggregateTrustManager m = new AggregateTrustManager(false,
         new ValidityDateTrustManager(),
         new HostNameTrustManager(false, "ds.example.com"));

    assertNotNull(m);

    assertFalse(m.requireAllAccepted());

    assertNotNull(m.getAssociatedTrustManagers());
    assertEquals(m.getAssociatedTrustManagers().size(), 2);

    final KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    final X509Certificate[] chain = ksManager.getCertificateChain("expired");
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkServerTrusted(chain, "RSA");
  }



  /**
   * Tests with a certificate that satisfies the criteria for one of the
   * associated trust managers when none of them are satisfied and there is only
   * one trust manager.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testORDoesNotMatchOnlyClient()
         throws Exception
  {
    final AggregateTrustManager m = new AggregateTrustManager(false,
         new ValidityDateTrustManager());

    assertNotNull(m);

    assertFalse(m.requireAllAccepted());

    assertNotNull(m.getAssociatedTrustManagers());
    assertEquals(m.getAssociatedTrustManagers().size(), 1);

    final KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    final X509Certificate[] chain = ksManager.getCertificateChain("expired");
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkClientTrusted(chain, "RSA");
  }



  /**
   * Tests with a certificate that satisfies the criteria for one of the
   * associated trust managers when none of them are satisfied and there is only
   * one trust manager.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testORDoesNotMatchOnlyServer()
         throws Exception
  {
    final AggregateTrustManager m = new AggregateTrustManager(false,
         new ValidityDateTrustManager());

    assertNotNull(m);

    assertFalse(m.requireAllAccepted());

    assertNotNull(m.getAssociatedTrustManagers());
    assertEquals(m.getAssociatedTrustManagers().size(), 1);

    final KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    final X509Certificate[] chain = ksManager.getCertificateChain("expired");
    assertNotNull(chain);
    assertFalse(chain.length == 0);

    m.checkServerTrusted(chain, "RSA");
  }
}
