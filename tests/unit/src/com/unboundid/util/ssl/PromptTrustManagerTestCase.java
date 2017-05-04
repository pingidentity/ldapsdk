/*
 * Copyright 2008-2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2017 Ping Identity Corporation
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



import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.testng.annotations.Test;

import com.unboundid.util.NullOutputStream;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides test coverage for the PromptTrustManager class.
 */
public class PromptTrustManagerTestCase
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
    PromptTrustManager m = new PromptTrustManager();

    assertNotNull(m);

    assertTrue(m.examineValidityDates());

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests the second constructor with a null accepted certificates file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NullFile()
         throws Exception
  {
    PromptTrustManager m = new PromptTrustManager(null);

    assertNotNull(m);

    assertTrue(m.examineValidityDates());

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests the second constructor with a nonexistent accepted certificates file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NonexistentFile()
         throws Exception
  {
    File f = createTempFile();
    f.delete();

    PromptTrustManager m = new PromptTrustManager(f.getAbsolutePath());

    assertNotNull(m);

    assertTrue(m.examineValidityDates());

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests the second constructor with a valid, existing accepted certificates
   * file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2ValidFile()
         throws Exception
  {
    KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    X509Certificate[] chain =
         ksManager.getCertificateChain(getJKSKeyStoreAlias());
    String signature = toLowerCase(toHex(chain[0].getSignature()));

    File f = createTempFile(signature);

    PromptTrustManager m = new PromptTrustManager(f.getAbsolutePath());

    assertNotNull(m);

    assertTrue(m.examineValidityDates());

    m.checkClientTrusted(chain, "RSA");

    m.checkServerTrusted(chain, "RSA");

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests the third constructor with a null accepted certificates file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3NullFile()
         throws Exception
  {
    PromptTrustManager m =
         new PromptTrustManager(null, false, System.in, System.out);

    assertNotNull(m);

    assertFalse(m.examineValidityDates());

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests the third constructor with a nonexistent accepted certificates file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3NonexistentFile()
         throws Exception
  {
    File f = createTempFile();
    f.delete();

    PromptTrustManager m =
         new PromptTrustManager(f.getAbsolutePath(), false, System.in,
                                System.out);

    assertNotNull(m);

    assertFalse(m.examineValidityDates());

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests the third constructor with a valid, existing accepted certificates
   * file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3ValidFile()
         throws Exception
  {
    KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    X509Certificate[] chain =
         ksManager.getCertificateChain(getJKSKeyStoreAlias());
    String signature = toLowerCase(toHex(chain[0].getSignature()));

    File f = createTempFile(signature);

    PromptTrustManager m =
         new PromptTrustManager(f.getAbsolutePath(), false, System.in,
                                System.out);

    assertNotNull(m);

    assertFalse(m.examineValidityDates());

    m.checkClientTrusted(chain, "RSA");

    m.checkServerTrusted(chain, "RSA");

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests the third constructor with an empty file.  When prompted, the
   * certificate will be trusted and the file should be updated.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testYesToPrompt()
         throws Exception
  {
    ByteArrayInputStream in = new ByteArrayInputStream(getBytes("y\n"));

    File f = createTempFile();

    PromptTrustManager m =
         new PromptTrustManager(f.getAbsolutePath(), false, in,
                                NullOutputStream.getPrintStream());

    assertNotNull(m);

    assertFalse(m.examineValidityDates());

    KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    X509Certificate[] chain =
         ksManager.getCertificateChain(getJKSKeyStoreAlias());

    assertTrue(m.wouldPrompt(chain));

    m.checkClientTrusted(chain, "RSA");

    m.checkServerTrusted(chain, "RSA");

    assertNotNull(m.getAcceptedIssuers());

    m = new PromptTrustManager(f.getAbsolutePath(), false, null, null);

    assertNotNull(m);

    assertFalse(m.examineValidityDates());

    assertFalse(m.wouldPrompt(chain));

    m.checkClientTrusted(chain, "RSA");

    m.checkServerTrusted(chain, "RSA");

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests the third constructor with an empty file.  When prompted, the
   * certificate will not be trusted and the attempt should fail.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testNoToPrompt()
         throws Exception
  {
    ByteArrayInputStream in = new ByteArrayInputStream(getBytes("n\n"));

    File f = createTempFile();

    PromptTrustManager m =
         new PromptTrustManager(f.getAbsolutePath(), false, in,
                                NullOutputStream.getPrintStream());

    assertNotNull(m);

    assertFalse(m.examineValidityDates());

    KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    X509Certificate[] chain =
         ksManager.getCertificateChain(getJKSKeyStoreAlias());

    assertTrue(m.wouldPrompt(chain));

    m.checkClientTrusted(chain, "RSA");
  }
}
