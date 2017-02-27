/*
 * Copyright 2008-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2017 UnboundID Corp.
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
import java.net.Socket;
import java.security.KeyStoreException;
import javax.net.ssl.SSLEngine;

import org.testng.annotations.Test;

import com.unboundid.util.LDAPSDKUsageException;



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
}
