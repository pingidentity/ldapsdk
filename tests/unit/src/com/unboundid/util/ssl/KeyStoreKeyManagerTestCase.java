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



import java.io.ByteArrayOutputStream;
import java.io.File;
import java.net.Socket;
import java.security.KeyStoreException;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLEngine;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ssl.cert.ManageCertificates;



/**
 * This class provides test coverage for the KeyStoreKeyManager class.
 */
public class KeyStoreKeyManagerTestCase
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
    KeyStoreKeyManager m =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    assertNotNull(m);

    assertNotNull(m.getKeyStoreFile());

    assertNotNull(m.getKeyStoreFormat());

    assertNull(m.getCertificateAlias());

    assertNotNull(m.getClientAliases("RSA", null));

    assertNull(m.getClientAliases("invalid", null));

    assertNotNull(m.chooseClientAlias(new String[] { "RSA" }, null,
                                      (Socket) null));

    assertNull(m.chooseClientAlias(new String[] { "invalid" }, null,
                                   (Socket) null));

    assertNotNull(m.chooseEngineClientAlias(new String[] { "RSA" }, null,
                                            (SSLEngine) null));

    assertNull(m.chooseEngineClientAlias(new String[] { "invalid" }, null,
                                         (SSLEngine) null));

    assertNotNull(m.getServerAliases("RSA", null));

    assertNull(m.getServerAliases("invalid", null));

    assertNotNull(m.chooseServerAlias("RSA", null, (Socket) null));

    assertNull(m.chooseServerAlias("invalid", null, (Socket) null));

    assertNotNull(m.chooseEngineServerAlias("RSA", null, (SSLEngine) null));

    assertNull(m.chooseEngineServerAlias("invalid", null, (SSLEngine) null));

    assertNotNull(m.getCertificateChain(getJKSKeyStoreAlias()));

    assertNull(m.getCertificateChain("nonexistent-alias"));

    assertNotNull(m.getPrivateKey(getJKSKeyStoreAlias()));

    assertNull(m.getPrivateKey("nonexistent-alias"));
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
    KeyStoreKeyManager m = new KeyStoreKeyManager(
         new File(getJKSKeyStorePath()), getJKSKeyStorePIN());
    assertNotNull(m);

    assertNotNull(m.getKeyStoreFile());

    assertNotNull(m.getKeyStoreFormat());

    assertNull(m.getCertificateAlias());

    assertNotNull(m.getClientAliases("RSA", null));

    assertNull(m.getClientAliases("invalid", null));

    assertNotNull(m.chooseClientAlias(new String[] { "RSA" }, null,
                                      (Socket) null));

    assertNull(m.chooseClientAlias(new String[] { "invalid" }, null,
                                   (Socket) null));

    assertNotNull(m.chooseEngineClientAlias(new String[] { "RSA" }, null,
                                            (SSLEngine) null));

    assertNull(m.chooseEngineClientAlias(new String[] { "invalid" }, null,
                                         (SSLEngine) null));

    assertNotNull(m.getServerAliases("RSA", null));

    assertNull(m.getServerAliases("invalid", null));

    assertNotNull(m.chooseServerAlias("RSA", null, (Socket) null));

    assertNull(m.chooseServerAlias("invalid", null, (Socket) null));

    assertNotNull(m.chooseEngineServerAlias("RSA", null, (SSLEngine) null));

    assertNull(m.chooseEngineServerAlias("invalid", null, (SSLEngine) null));

    assertNotNull(m.getCertificateChain(getJKSKeyStoreAlias()));

    assertNull(m.getCertificateChain("nonexistent-alias"));

    assertNotNull(m.getPrivateKey(getJKSKeyStoreAlias()));

    assertNull(m.getPrivateKey("nonexistent-alias"));
  }



  /**
   * Tests the second constructor using the JKS format.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2JKS()
         throws Exception
  {
    KeyStoreKeyManager m =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN(),
                                "JKS", getJKSKeyStoreAlias());
    assertNotNull(m);

    assertNotNull(m.getKeyStoreFile());

    assertNotNull(m.getKeyStoreFormat());

    assertNotNull(m.getCertificateAlias());

    assertNotNull(m.getClientAliases("RSA", null));

    assertNull(m.getClientAliases("invalid", null));

    assertNotNull(m.chooseClientAlias(new String[] { "RSA" }, null,
                                      (Socket) null));

    assertNull(m.chooseClientAlias(new String[] { "invalid" }, null,
                                   (Socket) null));

    assertNotNull(m.chooseEngineClientAlias(new String[] { "RSA" }, null,
                                            (SSLEngine) null));

    assertNull(m.chooseEngineClientAlias(new String[] { "invalid" }, null,
                                         (SSLEngine) null));

    assertNotNull(m.getServerAliases("RSA", null));

    assertNull(m.getServerAliases("invalid", null));

    assertNotNull(m.chooseServerAlias("RSA", null, (Socket) null));

    assertNull(m.chooseServerAlias("invalid", null, (Socket) null));

    assertNotNull(m.chooseEngineServerAlias("RSA", null, (SSLEngine) null));

    assertNull(m.chooseEngineServerAlias("invalid", null, (SSLEngine) null));

    assertNotNull(m.getCertificateChain(getJKSKeyStoreAlias()));

    assertNull(m.getCertificateChain("nonexistent-alias"));

    assertNotNull(m.getPrivateKey(getJKSKeyStoreAlias()));

    assertNull(m.getPrivateKey("nonexistent-alias"));
  }



  /**
   * Tests the second constructor using the JKS format.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2JKSFile()
         throws Exception
  {
    KeyStoreKeyManager m = new KeyStoreKeyManager(
         new File(getJKSKeyStorePath()), getJKSKeyStorePIN(), "JKS",
         getJKSKeyStoreAlias());
    assertNotNull(m);

    assertNotNull(m.getKeyStoreFile());

    assertNotNull(m.getKeyStoreFormat());

    assertNotNull(m.getCertificateAlias());

    assertNotNull(m.getClientAliases("RSA", null));

    assertNull(m.getClientAliases("invalid", null));

    assertNotNull(m.chooseClientAlias(new String[] { "RSA" }, null,
                                      (Socket) null));

    assertNull(m.chooseClientAlias(new String[] { "invalid" }, null,
                                   (Socket) null));

    assertNotNull(m.chooseEngineClientAlias(new String[] { "RSA" }, null,
                                            (SSLEngine) null));

    assertNull(m.chooseEngineClientAlias(new String[] { "invalid" }, null,
                                         (SSLEngine) null));

    assertNotNull(m.getServerAliases("RSA", null));

    assertNull(m.getServerAliases("invalid", null));

    assertNotNull(m.chooseServerAlias("RSA", null, (Socket) null));

    assertNull(m.chooseServerAlias("invalid", null, (Socket) null));

    assertNotNull(m.chooseEngineServerAlias("RSA", null, (SSLEngine) null));

    assertNull(m.chooseEngineServerAlias("invalid", null, (SSLEngine) null));

    assertNotNull(m.getCertificateChain(getJKSKeyStoreAlias()));

    assertNull(m.getCertificateChain("nonexistent-alias"));

    assertNotNull(m.getPrivateKey(getJKSKeyStoreAlias()));

    assertNull(m.getPrivateKey("nonexistent-alias"));
  }



  /**
   * Tests the second constructor using the PKCS12 format.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2PKCS12()
         throws Exception
  {
    KeyStoreKeyManager m =
         new KeyStoreKeyManager(getPKCS12KeyStorePath(), getPKCS12KeyStorePIN(),
                                "PKCS12", getPKCS12KeyStoreAlias());
    assertNotNull(m);

    assertNotNull(m.getKeyStoreFile());

    assertNotNull(m.getKeyStoreFormat());

    assertNotNull(m.getCertificateAlias());

    assertNotNull(m.getClientAliases("RSA", null));

    assertNull(m.getClientAliases("invalid", null));

    assertNotNull(m.chooseClientAlias(new String[] { "RSA" }, null,
                                      (Socket) null));

    assertNull(m.chooseClientAlias(new String[] { "invalid" }, null,
                                   (Socket) null));

    assertNotNull(m.chooseEngineClientAlias(new String[] { "RSA" }, null,
                                            (SSLEngine) null));

    assertNull(m.chooseEngineClientAlias(new String[] { "invalid" }, null,
                                         (SSLEngine) null));

    assertNotNull(m.getServerAliases("RSA", null));

    assertNull(m.getServerAliases("invalid", null));

    assertNotNull(m.chooseServerAlias("RSA", null, (Socket) null));

    assertNull(m.chooseServerAlias("invalid", null, (Socket) null));

    assertNotNull(m.chooseEngineServerAlias("RSA", null, (SSLEngine) null));

    assertNull(m.chooseEngineServerAlias("invalid", null, (SSLEngine) null));

    assertNotNull(m.getCertificateChain(getPKCS12KeyStoreAlias()));

    assertNull(m.getCertificateChain("nonexistent-alias"));

    assertNotNull(m.getPrivateKey(getPKCS12KeyStoreAlias()));

    assertNull(m.getPrivateKey("nonexistent-alias"));
  }



  /**
   * Tests with a {@code null} key store file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNullFile()
         throws Exception
  {
    new KeyStoreKeyManager((String) null, "password".toCharArray());
  }



  /**
   * Tests with a file that does not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { KeyStoreException.class })
  public void testNonexistentFile()
         throws Exception
  {
    File f  = createTempFile();
    f.delete();

    new KeyStoreKeyManager(f.getAbsolutePath(), "password".toCharArray());
  }



  /**
   * Tests with a file that is not a valid key store.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { KeyStoreException.class })
  public void testInvalidKeyStore()
         throws Exception
  {
    File f  = createTempFile("not a valid keystore");

    new KeyStoreKeyManager(f.getAbsolutePath(), "password".toCharArray());
  }



  /**
   * Tests with an invalid key store type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { KeyStoreException.class })
  public void testInvalidKeyStoreType()
         throws Exception
  {
    new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN(), "invalid",
                           null);
  }



  /**
   * Tests the behavior when trying to validate a key store under various
   * conditions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidateKeyStore()
         throws Exception
  {
    final File keyStoreFile = createTempFile();
    assertTrue(keyStoreFile.delete());

    // Create a key store with a self-signed certificate.
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         ManageCertificates.main(null, out, out,
              "generate-self-signed-certificate",
              "--keystore", keyStoreFile.getAbsolutePath(),
              "--keystore-password", "password",
              "--keystore-type", "JKS",
              "--alias", "server-cert",
              "--subject-dn", "CN=ds.example.com,O=Example Corp,C=US"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));


    // Make sure that an attempt to create a key manager from the key store
    // succeeds both with and without validation, both when and when not using
    // a valid alias.
    new KeyStoreKeyManager(keyStoreFile.getAbsolutePath(),
         "password".toCharArray(), "JKS", null, false);
    new KeyStoreKeyManager(keyStoreFile.getAbsolutePath(),
         "password".toCharArray(), "JKS", null, true);
    new KeyStoreKeyManager(keyStoreFile.getAbsolutePath(),
         "password".toCharArray(), "JKS", "server-cert", false);
    new KeyStoreKeyManager(keyStoreFile.getAbsolutePath(),
         "password".toCharArray(), "JKS", "server-cert", true);


    // Make sure that an attempt using an invalid alias fails when requesting
    // validation.
    new KeyStoreKeyManager(keyStoreFile.getAbsolutePath(),
         "password".toCharArray(), "JKS", "invalid", false);

    try
    {
      new KeyStoreKeyManager(keyStoreFile.getAbsolutePath(),
           "password".toCharArray(), "JKS", "invalid", true);
      fail("Expected an exception when trying to validate a key store when " +
           "using an invalid alias.");
    }
    catch (final KeyStoreException e)
    {
      // This was expected.
    }


    // Export the certificate to a PEM file.
    final File exportedCertificate = createTempFile();
    assertTrue(exportedCertificate.delete());

    out.reset();
    assertEquals(
         ManageCertificates.main(null, out, out,
              "export-certificate",
              "--keystore", keyStoreFile.getAbsolutePath(),
              "--keystore-password", "password",
              "--alias", "server-cert",
              "--output-file", exportedCertificate.getAbsolutePath(),
              "--output-format", "PEM"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));


    // Remove that self-signed certificate, leaving an empty key store.
    out.reset();
    assertEquals(
         ManageCertificates.main(null, out, out,
              "delete-certificate",
              "--keystore", keyStoreFile.getAbsolutePath(),
              "--keystore-password", "password",
              "--alias", "server-cert",
              "--no-prompt"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));


    // Verify that an attempt to create a key manager fails if validation is
    // requested when not using an alias.
    new KeyStoreKeyManager(keyStoreFile.getAbsolutePath(),
         "password".toCharArray(), "JKS", null, false);

    try
    {
      new KeyStoreKeyManager(keyStoreFile.getAbsolutePath(),
           "password".toCharArray(), "JKS", null, true);
      fail("Expected an exception when trying to validate an empty key store " +
           "when not using a alias.");
    }
    catch (final KeyStoreException e)
    {
      // This was expected.
    }


    // Verify that an attempt to create a key manager from the key store
    // fails if validation is requested when using an alias.
    new KeyStoreKeyManager(keyStoreFile.getAbsolutePath(),
         "password".toCharArray(), "JKS", "server-cert", false);

    try
    {
      new KeyStoreKeyManager(keyStoreFile.getAbsolutePath(),
           "password".toCharArray(), "JKS", "server-cert", true);
      fail("Expected an exception when trying to validate an empty key store " +
           "when using a alias.");
    }
    catch (final KeyStoreException e)
    {
      // This was expected.
    }


    // Import the exported certificate into the key store.  Since we don't have
    // a private key, this will create a trusted certificate entry rather than
    // a private key entry.
    out.reset();
    assertEquals(
         ManageCertificates.main(null, out, out,
              "import-certificate",
              "--keystore", keyStoreFile.getAbsolutePath(),
              "--keystore-password", "password",
              "--certificate-file", exportedCertificate.getAbsolutePath(),
              "--alias", "server-cert",
              "--no-prompt"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));


    // Verify that an attempt to create a key manager fails if validation is
    // requested when not using an alias.
    new KeyStoreKeyManager(keyStoreFile.getAbsolutePath(),
         "password".toCharArray(), "JKS", null, false);

    try
    {
      new KeyStoreKeyManager(keyStoreFile.getAbsolutePath(),
           "password".toCharArray(), "JKS", null, true);
      fail("Expected an exception when trying to validate a key store with " +
           "only a trusted certificate entry when not using an alias.");
    }
    catch (final KeyStoreException e)
    {
      // This was expected.
    }


    // Verify that an attempt to create a key manager from the key store
    // fails if validation is requested when using an alias.
    new KeyStoreKeyManager(keyStoreFile.getAbsolutePath(),
         "password".toCharArray(), "JKS", "server-cert", false);

    try
    {
      new KeyStoreKeyManager(keyStoreFile.getAbsolutePath(),
           "password".toCharArray(), "JKS", "server-cert", true);
      fail("Expected an exception when trying to validate a key store with " +
           "only a trusted certificate entry when using an alias.");
    }
    catch (final KeyStoreException e)
    {
      // This was expected.
    }


    // Generate a self-signed certificate with a notBefore time that is in the
    // future.
    final long tomorrowMillis =
         System.currentTimeMillis() + TimeUnit.DAYS.toMillis(1);
    final String tomorrowTimestamp =
         StaticUtils.encodeGeneralizedTime(tomorrowMillis);

    out.reset();
    assertEquals(
         ManageCertificates.main(null, out, out,
              "generate-self-signed-certificate",
              "--keystore", keyStoreFile.getAbsolutePath(),
              "--keystore-password", "password",
              "--keystore-type", "JKS",
              "--alias", "cert-not-yet-valid",
              "--subject-dn", "CN=ds.example.com,O=Example Corp,C=US",
              "--validity-start-time", tomorrowTimestamp),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));


    // Verify that an attempt to create a key manager fails if validation is
    // requested when not using an alias.
    new KeyStoreKeyManager(keyStoreFile.getAbsolutePath(),
         "password".toCharArray(), "JKS", null, false);

    try
    {
      new KeyStoreKeyManager(keyStoreFile.getAbsolutePath(),
           "password".toCharArray(), "JKS", null, true);
      fail("Expected an exception when trying to validate a key store with " +
           "a not-yet-valid key entry when not using an alias.");
    }
    catch (final KeyStoreException e)
    {
      // This was expected.
    }


    // Verify that an attempt to create a key manager from the key store
    // fails if validation is requested when using an alias.
    new KeyStoreKeyManager(keyStoreFile.getAbsolutePath(),
         "password".toCharArray(), "JKS", "cert-not-yet-valid", false);

    try
    {
      new KeyStoreKeyManager(keyStoreFile.getAbsolutePath(),
           "password".toCharArray(), "JKS", "cert-not-yet-valid", true);
      fail("Expected an exception when trying to validate a key store with " +
           "a not-yet-valid key entry when using an alias.");
    }
    catch (final KeyStoreException e)
    {
      // This was expected.
    }


    // Generate a self-signed certificate with a notAfter time that is in the
    // past.
    final long aYearAndADayAgoMillis =
         System.currentTimeMillis() - TimeUnit.DAYS.toMillis(366);
    final String aYearAndADayAgoTimestamp =
         StaticUtils.encodeGeneralizedTime(aYearAndADayAgoMillis);

    out.reset();
    assertEquals(
         ManageCertificates.main(null, out, out,
              "generate-self-signed-certificate",
              "--keystore", keyStoreFile.getAbsolutePath(),
              "--keystore-password", "password",
              "--keystore-type", "JKS",
              "--alias", "cert-expired",
              "--subject-dn", "CN=ds.example.com,O=Example Corp,C=US",
              "--validity-start-time", aYearAndADayAgoTimestamp,
              "--days-valid", "365"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));


    // Verify that an attempt to create a key manager fails if validation is
    // requested when not using an alias.
    new KeyStoreKeyManager(keyStoreFile.getAbsolutePath(),
         "password".toCharArray(), "JKS", null, false);

    try
    {
      new KeyStoreKeyManager(keyStoreFile.getAbsolutePath(),
           "password".toCharArray(), "JKS", null, true);
      fail("Expected an exception when trying to validate a key store with " +
           "an expired key entry when not using an alias.");
    }
    catch (final KeyStoreException e)
    {
      // This was expected.
    }


    // Verify that an attempt to create a key manager from the key store
    // fails if validation is requested when using an alias.
    new KeyStoreKeyManager(keyStoreFile.getAbsolutePath(),
         "password".toCharArray(), "JKS", "cert-expired", false);

    try
    {
      new KeyStoreKeyManager(keyStoreFile.getAbsolutePath(),
           "password".toCharArray(), "JKS", "cert-expired", true);
      fail("Expected an exception when trying to validate a key store with " +
           "an expired key entry when using an alias.");
    }
    catch (final KeyStoreException e)
    {
      // This was expected.
    }


    // Add another valid self-signed certificate.
    out.reset();
    assertEquals(
         ManageCertificates.main(null, out, out,
              "generate-self-signed-certificate",
              "--keystore", keyStoreFile.getAbsolutePath(),
              "--keystore-password", "password",
              "--keystore-type", "JKS",
              "--alias", "valid",
              "--subject-dn", "CN=ds.example.com,O=Example Corp,C=US"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));


    // Make sure that an attempt to create a key manager from the key store
    // succeeds both with and without validation, both when and when not using
    // a valid alias.
    new KeyStoreKeyManager(keyStoreFile.getAbsolutePath(),
         "password".toCharArray(), "JKS", null, false);
    new KeyStoreKeyManager(keyStoreFile.getAbsolutePath(),
         "password".toCharArray(), "JKS", null, true);
    new KeyStoreKeyManager(keyStoreFile.getAbsolutePath(),
         "password".toCharArray(), "JKS", "valid", false);
    new KeyStoreKeyManager(keyStoreFile.getAbsolutePath(),
         "password".toCharArray(), "JKS", "valid", true);
  }
}
