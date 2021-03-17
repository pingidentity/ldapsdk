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
package com.unboundid.util;



import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.cert.CertificateException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.ssl.SSLUtil;



/**
 * This class provides a set of test cases for the crypto helper class.  Note
 * that the LDAP SDK unit tests are not intended to be used when the LDAP SDK
 * is operating in FIPS mode, and these tests are written with that assumption.
 */
public final class CryptoHelperTestCase
       extends LDAPSDKTestCase
{
  /**
   * A null provider.
   */
  private static final Provider NULL_PROVIDER = null;



  /**
   * A null string.
   */
  private static final String NULL_STRING = null;



  /**
   * Provides test coverage for the {@code usingFIPSMode} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUsingFIPSMode()
         throws Exception
  {
    assertFalse(CryptoHelper.usingFIPSMode());

    try
    {
      CryptoHelper.setUseFIPSMode(true);
      fail("Expected an exception when trying to enable FIPS mode");
    }
    catch (final NoSuchProviderException e)
    {
      // This was expected.
    }

    assertFalse(CryptoHelper.usingFIPSMode());

    CryptoHelper.setUseFIPSMode(false);

    assertFalse(CryptoHelper.usingFIPSMode());
  }



  /**
   * Provides test coverage for the {@code getCertificateFactory} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetCertificateFactory()
         throws Exception
  {
    assertNotNull(CryptoHelper.getCertificateFactory("X.509"));
    final Provider defaultProvider =
         CryptoHelper.getCertificateFactory("X.509").getProvider();
    assertNotNull(defaultProvider);

    try
    {
      CryptoHelper.getCertificateFactory("UnknownType");
      fail("Expected a getCertificateFactory exception with unknown type");
    }
    catch (final CertificateException e)
    {
      // This was expected.
    }

    assertNotNull(CryptoHelper.getCertificateFactory("X.509", NULL_STRING));
    assertEquals(
         CryptoHelper.getCertificateFactory("X.509",
              NULL_STRING).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(CryptoHelper.getCertificateFactory("X.509",
         defaultProvider.getName()));
    assertEquals(
         CryptoHelper.getCertificateFactory("X.509",
              defaultProvider.getName()).getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getCertificateFactory("UnknownType", NULL_STRING);
      fail("Expected a getCertificateFactory exception with unknown type");
    }
    catch (final CertificateException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getCertificateFactory("UnknownType",
           defaultProvider.getName());
      fail("Expected a getCertificateFactory exception with unknown type");
    }
    catch (final CertificateException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getCertificateFactory("X.509", "UnknownProvider");
      fail("Expected a getCertificateFactory exception with unknown provider");
    }
    catch (final NoSuchProviderException e)
    {
      // This was expected.
    }

    assertNotNull(CryptoHelper.getCertificateFactory("X.509", NULL_PROVIDER));
    assertEquals(
         CryptoHelper.getCertificateFactory("X.509",
              NULL_PROVIDER).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(CryptoHelper.getCertificateFactory("X.509", defaultProvider));
    assertEquals(
         CryptoHelper.getCertificateFactory("X.509",
              defaultProvider).getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getCertificateFactory("UnknownType", NULL_PROVIDER);
      fail("Expected a getCertificateFactory exception with unknown type");
    }
    catch (final CertificateException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getCertificateFactory("UnknownType",
           defaultProvider);
      fail("Expected a getCertificateFactory exception with unknown type");
    }
    catch (final CertificateException e)
    {
      // This was expected.
    }
  }



  /**
   * Provides test coverage for the {@code getCipher} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetCipher()
         throws Exception
  {
    assertNotNull(CryptoHelper.getCipher("AES"));
    final Provider defaultProvider =
         CryptoHelper.getCipher("AES").getProvider();

    assertNotNull(CryptoHelper.getCipher("AES/CBC/PKCS5Padding"));
    assertEquals(
         CryptoHelper.getCipher("AES/CBC/PKCS5Padding").getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getCipher("UnknownAlgorithm");
      fail("Expected a getCipher exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getCipher("UnknownAlgorithm/CBC/PKCS5Padding");
      fail("Expected a getCipher exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getCipher("AES/UnknownMode/PKCS5Padding");
      fail("Expected a getCipher exception with unknown mode");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getCipher("AES/CBC/UnknownPadding");
      fail("Expected a getCipher exception with unknown padding");
    }
    catch (final Exception e)
    {
      assertTrue((e instanceof NoSuchAlgorithmException) ||
                (e instanceof NoSuchPaddingException));
    }

    assertNotNull(CryptoHelper.getCipher("AES", NULL_STRING));
    assertEquals(
         CryptoHelper.getCipher("AES", NULL_STRING).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(CryptoHelper.getCipher("AES/CBC/PKCS5Padding", NULL_STRING));
    assertEquals(
         CryptoHelper.getCipher("AES/CBC/PKCS5Padding",
              NULL_STRING).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(CryptoHelper.getCipher("AES", defaultProvider.getName()));
    assertEquals(
         CryptoHelper.getCipher("AES",
              defaultProvider.getName()).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(
         CryptoHelper.getCipher("AES/CBC/PKCS5Padding",
              defaultProvider.getName()));
    assertEquals(
         CryptoHelper.getCipher("AES/CBC/PKCS5Padding",
              defaultProvider.getName()).getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getCipher("UnknownAlgorithm", NULL_STRING);
      fail("Expected a getCipher exception with an unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected
    }

    try
    {
      CryptoHelper.getCipher("UnknownAlgorithm", defaultProvider.getName());
      fail("Expected a getCipher exception with an unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected
    }

    try
    {
      CryptoHelper.getCipher("AES", "UnknownProvider");
      fail("Expected a getCipher exception with an unknown provider");
    }
    catch (final NoSuchProviderException e)
    {
      // This was expected
    }

    assertNotNull(CryptoHelper.getCipher("AES", NULL_PROVIDER));
    assertEquals(
         CryptoHelper.getCipher("AES", NULL_PROVIDER).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(
         CryptoHelper.getCipher("AES/CBC/PKCS5Padding", NULL_PROVIDER));
    assertEquals(
         CryptoHelper.getCipher("AES/CBC/PKCS5Padding",
              NULL_PROVIDER).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(CryptoHelper.getCipher("AES", defaultProvider));
    assertEquals(
         CryptoHelper.getCipher("AES", defaultProvider).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(
         CryptoHelper.getCipher("AES/CBC/PKCS5Padding", defaultProvider));
    assertEquals(
         CryptoHelper.getCipher("AES/CBC/PKCS5Padding",
              defaultProvider).getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getCipher("UnknownAlgorithm", NULL_PROVIDER);
      fail("Expected a getCipher exception with an unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected
    }

    try
    {
      CryptoHelper.getCipher("UnknownAlgorithm", defaultProvider);
      fail("Expected a getCipher exception with an unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected
    }
  }



  /**
   * Provides test coverage for the {@code getKeyFactory} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetKeyFactory()
         throws Exception
  {
    assertNotNull(CryptoHelper.getKeyFactory("RSA"));
    final Provider defaultProvider =
         CryptoHelper.getKeyFactory("RSA").getProvider();

    try
    {
      CryptoHelper.getKeyFactory("UnknownAlgorithm");
      fail("Expected a getKeyFactory exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    assertNotNull(CryptoHelper.getKeyFactory("RSA", NULL_STRING));
    assertEquals(
         CryptoHelper.getKeyFactory("RSA", NULL_STRING).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(CryptoHelper.getKeyFactory("RSA", defaultProvider.getName()));
    assertEquals(
         CryptoHelper.getKeyFactory("RSA",
              defaultProvider.getName()).getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getKeyFactory("UnknownAlgorithm", NULL_STRING);
      fail("Expected a getKeyFactory exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getKeyFactory("UnknownAlgorithm", defaultProvider.getName());
      fail("Expected a getKeyFactory exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getKeyFactory("RSA", "UnknownProvider");
      fail("Expected a getKeyFactory exception with unknown provider");
    }
    catch (final NoSuchProviderException e)
    {
      // This was expected.
    }

    assertNotNull(CryptoHelper.getKeyFactory("RSA", NULL_PROVIDER));
    assertEquals(
         CryptoHelper.getKeyFactory("RSA",
              NULL_PROVIDER).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(CryptoHelper.getKeyFactory("RSA", defaultProvider));
    assertEquals(
         CryptoHelper.getKeyFactory("RSA",
              defaultProvider).getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getKeyFactory("UnknownAlgorithm", NULL_PROVIDER);
      fail("Expected a getKeyFactory exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getKeyFactory("UnknownAlgorithm", defaultProvider);
      fail("Expected a getKeyFactory exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }
  }



  /**
   * Provides test coverage for the {@code getKeyManagerFactory} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetKeyManagerFactory()
         throws Exception
  {
    final String defaultAlgorithm = KeyManagerFactory.getDefaultAlgorithm();

    assertNotNull(CryptoHelper.getKeyManagerFactory(defaultAlgorithm));
    final Provider defaultProvider =
         CryptoHelper.getKeyManagerFactory(defaultAlgorithm).getProvider();

    try
    {
      CryptoHelper.getKeyManagerFactory("UnknownAlgorithm");
      fail("Expected a getKeyManagerFactory exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    assertNotNull(
         CryptoHelper.getKeyManagerFactory(defaultAlgorithm, NULL_STRING));
    assertEquals(
         CryptoHelper.getKeyManagerFactory(defaultAlgorithm,
              NULL_STRING).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(
         CryptoHelper.getKeyManagerFactory(defaultAlgorithm,
              defaultProvider.getName()));
    assertEquals(
         CryptoHelper.getKeyManagerFactory(defaultAlgorithm,
              defaultProvider.getName()).getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getKeyManagerFactory("UnknownAlgorithm", NULL_STRING);
      fail("Expected a getKeyManagerFactory exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected
    }

    try
    {
      CryptoHelper.getKeyManagerFactory("UnknownAlgorithm",
           defaultProvider.getName());
      fail("Expected a getKeyManagerFactory exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected
    }

    try
    {
      CryptoHelper.getKeyManagerFactory(defaultAlgorithm, "UnknownProvider");
      fail("Expected a getKeyManagerFactory exception with unknown provider");
    }
    catch (final NoSuchProviderException e)
    {
      // This was expected
    }

    assertNotNull(
         CryptoHelper.getKeyManagerFactory(defaultAlgorithm, NULL_PROVIDER));
    assertEquals(
         CryptoHelper.getKeyManagerFactory(defaultAlgorithm,
              NULL_PROVIDER).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(
         CryptoHelper.getKeyManagerFactory(defaultAlgorithm, defaultProvider));
    assertEquals(
         CryptoHelper.getKeyManagerFactory(defaultAlgorithm,
              defaultProvider).getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getKeyManagerFactory("UnknownAlgorithm", NULL_PROVIDER);
      fail("Expected a getKeyManagerFactory exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected
    }

    try
    {
      CryptoHelper.getKeyManagerFactory("UnknownAlgorithm", defaultProvider);
      fail("Expected a getKeyManagerFactory exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected
    }
  }



  /**
   * Provides test coverage for the {@code getKeyPairGenerator} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetKeyPairGenerator()
         throws Exception
  {
    assertNotNull(CryptoHelper.getKeyPairGenerator("RSA"));
    final Provider defaultProvider =
         CryptoHelper.getKeyPairGenerator("RSA").getProvider();

    try
    {
      CryptoHelper.getKeyPairGenerator("UnknownAlgorithm");
      fail("Expected a getKeyPairGenerator exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    assertNotNull(CryptoHelper.getKeyPairGenerator("RSA", NULL_STRING));
    assertEquals(
         CryptoHelper.getKeyPairGenerator("RSA",
              NULL_STRING).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(CryptoHelper.getKeyPairGenerator("RSA",
         defaultProvider.getName()));
    assertEquals(
         CryptoHelper.getKeyPairGenerator("RSA",
              defaultProvider.getName()).getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getKeyPairGenerator("UnknownAlgorithm", NULL_STRING);
      fail("Expected a getKeyPairGenerator exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getKeyPairGenerator("UnknownAlgorithm",
           defaultProvider.getName());
      fail("Expected a getKeyPairGenerator exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getKeyPairGenerator("RSA", "UnknownProvider");
      fail("Expected a getKeyPairGenerator exception with unknown provider");
    }
    catch (final NoSuchProviderException e)
    {
      // This was expected.
    }

    assertNotNull(CryptoHelper.getKeyPairGenerator("RSA", NULL_PROVIDER));
    assertEquals(
         CryptoHelper.getKeyPairGenerator("RSA",
              NULL_PROVIDER).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(CryptoHelper.getKeyPairGenerator("RSA", defaultProvider));
    assertEquals(
         CryptoHelper.getKeyPairGenerator("RSA",
              defaultProvider).getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getKeyPairGenerator("UnknownAlgorithm", NULL_PROVIDER);
      fail("Expected a getKeyPairGenerator exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getKeyPairGenerator("UnknownAlgorithm", defaultProvider);
      fail("Expected a getKeyPairGenerator exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }
  }



  /**
   * Provides test coverage for the {@code getDefaultKeyStoreType} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetDefaultKeyStoreType()
         throws Exception
  {
    final String initialDefaultType = CryptoHelper.getDefaultKeyStoreType();
    assertNotNull(initialDefaultType);
    assertEquals(initialDefaultType, KeyStore.getDefaultType());

    CryptoHelper.setDefaultKeyStoreType("PKCS12");
    assertNotNull(CryptoHelper.getDefaultKeyStoreType());
    assertEquals(CryptoHelper.getDefaultKeyStoreType(), "PKCS12");

    CryptoHelper.setDefaultKeyStoreType("JKS");
    assertNotNull(CryptoHelper.getDefaultKeyStoreType());
    assertEquals(CryptoHelper.getDefaultKeyStoreType(), "JKS");

    CryptoHelper.setDefaultKeyStoreType(initialDefaultType);
    assertNotNull(CryptoHelper.getDefaultKeyStoreType());
    assertEquals(CryptoHelper.getDefaultKeyStoreType(), initialDefaultType);
  }



  /**
   * Provides test coverage for the {@code getKeyStore} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetKeyStore()
         throws Exception
  {
    assertNotNull(CryptoHelper.getKeyStore("JKS"));
    final Provider defaultProvider =
         CryptoHelper.getKeyStore("JKS").getProvider();

    try
    {
      CryptoHelper.getKeyStore("UnknownType");
      fail("Expected a getKeyStore exception with unknown type");
    }
    catch (final KeyStoreException e)
    {
      // This was expected.
    }

    assertNotNull(CryptoHelper.getKeyStore("JKS", NULL_STRING));
    assertEquals(
         CryptoHelper.getKeyStore("JKS", NULL_STRING).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(CryptoHelper.getKeyStore("JKS", defaultProvider.getName()));
    assertEquals(
         CryptoHelper.getKeyStore("JKS",
              defaultProvider.getName()).getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getKeyStore("UnknownType", NULL_STRING);
      fail("Expected a getKeyStore exception with unknown type");
    }
    catch (final KeyStoreException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getKeyStore("UnknownType", defaultProvider.getName());
      fail("Expected a getKeyStore exception with unknown type");
    }
    catch (final KeyStoreException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getKeyStore("JKS", "UknownProvider");
      fail("Expected a getKeyStore exception with unknown provider");
    }
    catch (final NoSuchProviderException e)
    {
      // This was expected.
    }

    assertNotNull(CryptoHelper.getKeyStore("JKS", NULL_PROVIDER));
    assertEquals(
         CryptoHelper.getKeyStore("JKS", NULL_PROVIDER).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(CryptoHelper.getKeyStore("JKS", defaultProvider));
    assertEquals(
         CryptoHelper.getKeyStore("JKS",
              defaultProvider).getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getKeyStore("UnknownType", NULL_PROVIDER);
      fail("Expected a getKeyStore exception with unknown type");
    }
    catch (final KeyStoreException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getKeyStore("UnknownType", defaultProvider);
      fail("Expected a getKeyStore exception with unknown type");
    }
    catch (final KeyStoreException e)
    {
      // This was expected.
    }
  }



  /**
   * Provides test coverage for the {@code getMAC} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetMAC()
         throws Exception
  {
    assertNotNull(CryptoHelper.getMAC("HmacSHA256"));
    final Provider defaultProvider =
         CryptoHelper.getMAC("HmacSHA256").getProvider();

    try
    {
      CryptoHelper.getMAC("UnknownAlgorithm");
      fail("Expected a getMAC exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    assertNotNull(CryptoHelper.getMAC("HmacSHA256", NULL_STRING));
    assertEquals(
         CryptoHelper.getMAC("HmacSHA256", NULL_STRING).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(CryptoHelper.getMAC("HmacSHA256", defaultProvider.getName()));
    assertEquals(
         CryptoHelper.getMAC("HmacSHA256",
              defaultProvider.getName()).getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getMAC("UnknownAlgorithm", NULL_STRING);
      fail("Expected a getMAC exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getMAC("UnknownAlgorithm", defaultProvider.getName());
      fail("Expected a getMAC exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getMAC("HmacSHA256", "UnknownProvider");
      fail("Expected a getMAC exception with unknown provider");
    }
    catch (final NoSuchProviderException e)
    {
      // This was expected.
    }

    assertNotNull(CryptoHelper.getMAC("HmacSHA256", NULL_PROVIDER));
    assertEquals(
         CryptoHelper.getMAC("HmacSHA256",
              NULL_PROVIDER).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(CryptoHelper.getMAC("HmacSHA256", defaultProvider));
    assertEquals(
         CryptoHelper.getMAC("HmacSHA256",
              defaultProvider).getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getMAC("UnknownAlgorithm", NULL_PROVIDER);
      fail("Expected a getMAC exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getMAC("UnknownAlgorithm", defaultProvider);
      fail("Expected a getMAC exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }
  }



  /**
   * Provides test coverage for the {@code getMessageDigest} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetMessageDigest()
         throws Exception
  {
    assertNotNull(CryptoHelper.getMessageDigest("SHA-256"));
    final Provider defaultProvider =
         CryptoHelper.getMessageDigest("SHA-256").getProvider();

    try
    {
      CryptoHelper.getMessageDigest("UnknownAlgorithm");
      fail("Expected a getMessageDigest exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    assertNotNull(CryptoHelper.getMessageDigest("SHA-256", NULL_STRING));
    assertEquals(
         CryptoHelper.getMessageDigest("SHA-256",
              NULL_STRING).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(
         CryptoHelper.getMessageDigest("SHA-256", defaultProvider.getName()));
    assertEquals(
         CryptoHelper.getMessageDigest("SHA-256",
              defaultProvider.getName()).getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getMessageDigest("UnknownAlgorithm", NULL_STRING);
      fail("Expected a getMessageDigest exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getMessageDigest("UnknownAlgorithm",
           defaultProvider.getName());
      fail("Expected a getMessageDigest exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getMessageDigest("SHA-256", "UnknownProvider");
      fail("Expected a getMessageDigest exception with unknown provider");
    }
    catch (final NoSuchProviderException e)
    {
      // This was expected.
    }

    assertNotNull(CryptoHelper.getMessageDigest("SHA-256", NULL_PROVIDER));
    assertEquals(
         CryptoHelper.getMessageDigest("SHA-256",
              NULL_PROVIDER).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(
         CryptoHelper.getMessageDigest("SHA-256", defaultProvider));
    assertEquals(
         CryptoHelper.getMessageDigest("SHA-256",
              defaultProvider).getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getMessageDigest("UnknownAlgorithm", NULL_PROVIDER);
      fail("Expected a getMessageDigest exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getMessageDigest("UnknownAlgorithm", defaultProvider);
      fail("Expected a getMessageDigest exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }
  }



  /**
   * Provides test coverage for the {@code getSecretKeyFactory} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSecretKeyFactory()
         throws Exception
  {
    assertNotNull(CryptoHelper.getSecretKeyFactory("PBKDF2WithHmacSHA256"));
    final Provider defaultProvider = CryptoHelper.getSecretKeyFactory(
         "PBKDF2WithHmacSHA256").getProvider();

    try
    {
      CryptoHelper.getSecretKeyFactory("UnknownAlgorithm");
      fail("Expected a getSecretKeyFactory exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    assertNotNull(
         CryptoHelper.getSecretKeyFactory("PBKDF2WithHmacSHA256", NULL_STRING));
    assertEquals(
         CryptoHelper.getSecretKeyFactory("PBKDF2WithHmacSHA256",
              NULL_STRING).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(
         CryptoHelper.getSecretKeyFactory("PBKDF2WithHmacSHA256",
              defaultProvider.getName()));
    assertEquals(
         CryptoHelper.getSecretKeyFactory("PBKDF2WithHmacSHA256",
              defaultProvider.getName()).getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getSecretKeyFactory("UnknownAlgorithm", NULL_STRING);
      fail("Expected a getSecretKeyFactory exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getSecretKeyFactory("UnknownAlgorithm",
           defaultProvider.getName());
      fail("Expected a getSecretKeyFactory exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getSecretKeyFactory("PBKDF2WithHmacSHA256",
           "UnknownProvider");
      fail("Expected a getSecretKeyFactory exception with unknown provider");
    }
    catch (final NoSuchProviderException e)
    {
      // This was expected.
    }

    assertNotNull(
         CryptoHelper.getSecretKeyFactory("PBKDF2WithHmacSHA256",
              NULL_PROVIDER));
    assertEquals(
         CryptoHelper.getSecretKeyFactory("PBKDF2WithHmacSHA256",
              NULL_PROVIDER).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(
         CryptoHelper.getSecretKeyFactory("PBKDF2WithHmacSHA256",
              defaultProvider));
    assertEquals(
         CryptoHelper.getSecretKeyFactory("PBKDF2WithHmacSHA256",
              defaultProvider).getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getSecretKeyFactory("UnknownAlgorithm", NULL_PROVIDER);
      fail("Expected a getSecretKeyFactory exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getSecretKeyFactory("UnknownAlgorithm", defaultProvider);
      fail("Expected a getSecretKeyFactory exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }
  }



  /**
   * Provides test coverage for the {@code getSecureRandom} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSecureRandom()
         throws Exception
  {
    assertNotNull(CryptoHelper.getSecureRandom());
    final String defaultAlgorithm =
         CryptoHelper.getSecureRandom().getAlgorithm();
    final Provider defaultProvider =
         CryptoHelper.getSecureRandom().getProvider();

    assertNotNull(CryptoHelper.getSecureRandom(NULL_STRING));
    assertEquals(
         CryptoHelper.getSecureRandom(NULL_STRING).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(CryptoHelper.getSecureRandom(defaultAlgorithm));
    assertEquals(
         CryptoHelper.getSecureRandom(defaultAlgorithm).getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getSecureRandom("UnknownAlgorithm");
      fail("Expected a getSecureRandom exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    assertNotNull(CryptoHelper.getSecureRandom(NULL_STRING, NULL_STRING));
    assertEquals(
         CryptoHelper.getSecureRandom(NULL_STRING,
              NULL_STRING).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(CryptoHelper.getSecureRandom(defaultAlgorithm, NULL_STRING));
    assertEquals(
         CryptoHelper.getSecureRandom(defaultAlgorithm,
              NULL_STRING).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(CryptoHelper.getSecureRandom(NULL_STRING,
         defaultProvider.getName()));
    assertEquals(
         CryptoHelper.getSecureRandom(NULL_STRING,
              defaultProvider.getName()).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(CryptoHelper.getSecureRandom(defaultAlgorithm,
         defaultProvider.getName()));
    assertEquals(
         CryptoHelper.getSecureRandom(defaultAlgorithm,
              defaultProvider.getName()).getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getSecureRandom("UnknownAlgorithm", NULL_STRING);
      fail("Expected a getSecureRandom exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getSecureRandom("UnknownAlgorithm",
           defaultProvider.getName());
      fail("Expected a getSecureRandom exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getSecureRandom(NULL_STRING, "UnknownProvider");
      fail("Expected a getSecureRandom exception with unknown provider");
    }
    catch (final NoSuchProviderException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getSecureRandom("defaultAlgorithm", "UnknownProvider");
      fail("Expected a getSecureRandom exception with unknown provider");
    }
    catch (final NoSuchProviderException e)
    {
      // This was expected.
    }

    assertNotNull(CryptoHelper.getSecureRandom(NULL_STRING, NULL_PROVIDER));
    assertEquals(
         CryptoHelper.getSecureRandom(NULL_STRING,
              NULL_PROVIDER).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(
         CryptoHelper.getSecureRandom(defaultAlgorithm, NULL_PROVIDER));
    assertEquals(
         CryptoHelper.getSecureRandom(defaultAlgorithm,
              NULL_PROVIDER).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(CryptoHelper.getSecureRandom(NULL_STRING, defaultProvider));
    assertEquals(
         CryptoHelper.getSecureRandom(NULL_STRING,
              defaultProvider).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(
         CryptoHelper.getSecureRandom(defaultAlgorithm, defaultProvider));
    assertEquals(
         CryptoHelper.getSecureRandom(defaultAlgorithm,
              defaultProvider).getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getSecureRandom("UnknownAlgorithm", NULL_PROVIDER);
      fail("Expected a getSecureRandom exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getSecureRandom("UnknownAlgorithm", defaultProvider);
      fail("Expected a getSecureRandom exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }
  }



  /**
   * Provides test coverage for the {@code getSignature} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSignature()
         throws Exception
  {
    assertNotNull(CryptoHelper.getSignature("SHA256withRSA"));
    final Provider defaultProvider =
         CryptoHelper.getSignature("SHA256withRSA").getProvider();

    try
    {
      CryptoHelper.getSignature("UnknownAlgorithm");
      fail("Expected a getSignature exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    assertNotNull(CryptoHelper.getSignature("SHA256withRSA", NULL_STRING));
    assertEquals(
         CryptoHelper.getSignature("SHA256withRSA",
              NULL_STRING).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(
         CryptoHelper.getSignature("SHA256withRSA", defaultProvider.getName()));
    assertEquals(
         CryptoHelper.getSignature("SHA256withRSA",
              defaultProvider.getName()).getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getSignature("UnknownAlgorithm", NULL_STRING);
      fail("Expected a getSignature exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getSignature("UnknownAlgorithm", defaultProvider.getName());
      fail("Expected a getSignature exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getSignature("SHA256withRSA", "UnknownProvider");
      fail("Expected a getSignature exception with unknown provider");
    }
    catch (final NoSuchProviderException e)
    {
      // This was expected.
    }

    assertNotNull(CryptoHelper.getSignature("SHA256withRSA", NULL_PROVIDER));
    assertEquals(
         CryptoHelper.getSignature("SHA256withRSA",
              NULL_PROVIDER).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(
         CryptoHelper.getSignature("SHA256withRSA", defaultProvider));
    assertEquals(
         CryptoHelper.getSignature("SHA256withRSA",
              defaultProvider).getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getSignature("UnknownAlgorithm", NULL_PROVIDER);
      fail("Expected a getSignature exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getSignature("UnknownAlgorithm", defaultProvider);
      fail("Expected a getSignature exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }
  }



  /**
   * Provides test coverage for the {@code getSSLContext} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSSLContext()
         throws Exception
  {
    assertNotNull(CryptoHelper.getDefaultSSLContext());
    final Provider defaultProvider =
         CryptoHelper.getDefaultSSLContext().getProvider();


    assertNotNull(CryptoHelper.getSSLContext(SSLUtil.SSL_PROTOCOL_TLS_1_2));
    assertEquals(
         CryptoHelper.getSSLContext(SSLUtil.SSL_PROTOCOL_TLS_1_2).
              getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getSSLContext("UnknownAlgorithm");
      fail("Expected a getSSLContext exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    assertNotNull(
         CryptoHelper.getSSLContext(SSLUtil.SSL_PROTOCOL_TLS_1_2, NULL_STRING));
    assertEquals(
         CryptoHelper.getSSLContext(SSLUtil.SSL_PROTOCOL_TLS_1_2,
              NULL_STRING).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(CryptoHelper.getSSLContext(SSLUtil.SSL_PROTOCOL_TLS_1_2,
         defaultProvider.getName()));
    assertEquals(
         CryptoHelper.getSSLContext(SSLUtil.SSL_PROTOCOL_TLS_1_2,
              defaultProvider.getName()).getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getSSLContext("UnknownAlgorithm", NULL_STRING);
      fail("Expected a getSSLContext exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getSSLContext("UnknownAlgorithm", defaultProvider.getName());
      fail("Expected a getSSLContext exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getSSLContext(SSLUtil.SSL_PROTOCOL_TLS_1_2,
           "UnknownProvider");
      fail("Expected a getSSLContext exception with unknown provider");
    }
    catch (final NoSuchProviderException e)
    {
      // This was expected.
    }

    assertNotNull(
         CryptoHelper.getSSLContext(SSLUtil.SSL_PROTOCOL_TLS_1_2,
              NULL_PROVIDER));
    assertEquals(
         CryptoHelper.getSSLContext(SSLUtil.SSL_PROTOCOL_TLS_1_2,
              NULL_PROVIDER).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(
         CryptoHelper.getSSLContext(SSLUtil.SSL_PROTOCOL_TLS_1_2,
              defaultProvider));
    assertEquals(
         CryptoHelper.getSSLContext(SSLUtil.SSL_PROTOCOL_TLS_1_2,
              defaultProvider).getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getSSLContext("UnknownAlgorithm", NULL_PROVIDER);
      fail("Expected a getSSLContext exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    try
    {
      CryptoHelper.getSSLContext("UnknownAlgorithm", defaultProvider);
      fail("Expected a getSSLContext exception with unknown algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }
  }



  /**
   * Provides test coverage for the {@code getTrustManagerFactory} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetTrustManagerFactory()
         throws Exception
  {
    final String defaultAlgorithm = TrustManagerFactory.getDefaultAlgorithm();

    assertNotNull(CryptoHelper.getTrustManagerFactory(defaultAlgorithm));
    final Provider defaultProvider =
         CryptoHelper.getTrustManagerFactory(defaultAlgorithm).getProvider();

    try
    {
      CryptoHelper.getTrustManagerFactory("UnknownAlgorithm");
      fail("Expected a getTrustManagerFactory exception with unknown " +
           "algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected.
    }

    assertNotNull(
         CryptoHelper.getTrustManagerFactory(defaultAlgorithm, NULL_STRING));
    assertEquals(
         CryptoHelper.getTrustManagerFactory(defaultAlgorithm,
              NULL_STRING).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(
         CryptoHelper.getTrustManagerFactory(defaultAlgorithm,
              defaultProvider.getName()));
    assertEquals(
         CryptoHelper.getTrustManagerFactory(defaultAlgorithm,
              defaultProvider.getName()).getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getTrustManagerFactory("UnknownAlgorithm", NULL_STRING);
      fail("Expected a getTrustManagerFactory exception with unknown " +
           "algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected
    }

    try
    {
      CryptoHelper.getTrustManagerFactory("UnknownAlgorithm",
           defaultProvider.getName());
      fail("Expected a getTrustManagerFactory exception with unknown " +
           "algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected
    }

    try
    {
      CryptoHelper.getTrustManagerFactory(defaultAlgorithm, "UnknownProvider");
      fail("Expected a getTrustManagerFactory exception with unknown provider");
    }
    catch (final NoSuchProviderException e)
    {
      // This was expected
    }

    assertNotNull(
         CryptoHelper.getTrustManagerFactory(defaultAlgorithm, NULL_PROVIDER));
    assertEquals(
         CryptoHelper.getTrustManagerFactory(defaultAlgorithm,
              NULL_PROVIDER).getProvider().getName(),
         defaultProvider.getName());

    assertNotNull(
         CryptoHelper.getTrustManagerFactory(defaultAlgorithm,
              defaultProvider));
    assertEquals(
         CryptoHelper.getTrustManagerFactory(defaultAlgorithm,
              defaultProvider).getProvider().getName(),
         defaultProvider.getName());

    try
    {
      CryptoHelper.getTrustManagerFactory("UnknownAlgorithm", NULL_PROVIDER);
      fail("Expected a getTrustManagerFactory exception with unknown " +
           "algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected
    }

    try
    {
      CryptoHelper.getTrustManagerFactory("UnknownAlgorithm", defaultProvider);
      fail("Expected a getTrustManagerFactory exception with unknown " +
           "algorithm");
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This was expected
    }
  }
}
