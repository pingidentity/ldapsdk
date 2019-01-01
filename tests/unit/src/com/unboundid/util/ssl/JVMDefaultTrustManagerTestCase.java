/*
 * Copyright 2017-2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2017-2019 Ping Identity Corporation
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
import java.io.FileInputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.UUID;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the JVM default trust manager.
 */
public final class JVMDefaultTrustManagerTestCase
       extends LDAPSDKTestCase
{
  /**
   * Ensure that we can successfully get and use the default trust manager
   * instance.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    final JVMDefaultTrustManager trustManager =
         JVMDefaultTrustManager.getInstance();
    assertNotNull(trustManager);

    assertNotNull(trustManager.getKeyStore());

    assertNotNull(trustManager.getCACertsFile());

    assertNotNull(trustManager.getTrustedIssuerCertificates());
    assertFalse(trustManager.getTrustedIssuerCertificates().isEmpty());

    assertNotNull(trustManager.getAcceptedIssuers());
    assertTrue(trustManager.getAcceptedIssuers().length > 0);
  }



  /**
   * Tests the behavior when trying to create a trust manager instance with a
   * java home property that isn't set in the JVM.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testCreateTrustManagerWithUnsetJavaHomeProperty()
         throws Exception
  {
    final String propertyName = UUID.randomUUID().toString();
    assertNull(System.getProperty(propertyName));

    final JVMDefaultTrustManager trustManager =
         new JVMDefaultTrustManager(propertyName);
    assertNotNull(trustManager);

    trustManager.getKeyStore();
  }



  /**
   * Tests the behavior when trying to create a trust manager instance with a
   * java home property that is set to a nonexistent directory.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testCreateTrustManagerWithNonexistentJavaHomeDirectory()
         throws Exception
  {
    final String propertyName = UUID.randomUUID().toString();
    assertNull(System.getProperty(propertyName));

    try
    {
      final File tempDir = createTempDir();
      assertTrue(tempDir.delete());

      System.setProperty(propertyName, tempDir.getAbsolutePath());

      final JVMDefaultTrustManager trustManager =
           new JVMDefaultTrustManager(propertyName);
      assertNotNull(trustManager);

      trustManager.getKeyStore();
    }
    finally
    {
      System.clearProperty(propertyName);
    }

  }



  /**
   * Tests the behavior when trying to create a trust manager instance with a
   * java home property that is set to an empty directory.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testCreateTrustManagerWithJavaHomeEmptyDirectory()
         throws Exception
  {
    final String propertyName = UUID.randomUUID().toString();
    assertNull(System.getProperty(propertyName));

    try
    {
      final File tempDir = createTempDir();

      System.setProperty(propertyName, tempDir.getAbsolutePath());

      final JVMDefaultTrustManager trustManager =
           new JVMDefaultTrustManager(propertyName);
      assertNotNull(trustManager);

      trustManager.getKeyStore();
    }
    finally
    {
      System.clearProperty(propertyName);
    }
  }



  /**
   * Tests the behavior when trying to create a trust manager instance with a
   * java home property that is set to a file rather than a directory.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testCreateTrustManagerWithJavaHomeFileInsteadOfDirectory()
         throws Exception
  {
    final String propertyName = UUID.randomUUID().toString();
    assertNull(System.getProperty(propertyName));

    try
    {
      final File tempFile = createTempFile();

      System.setProperty(propertyName, tempFile.getAbsolutePath());

      final JVMDefaultTrustManager trustManager =
           new JVMDefaultTrustManager(propertyName);
      assertNotNull(trustManager);

      trustManager.getKeyStore();
    }
    finally
    {
      System.clearProperty(propertyName);
    }
  }



  /**
   * Tests the behavior when there is a valid cacerts file in the specified
   * location.
   *
   * @param  pathComponents  The path components to the expected file, relative
   *                         to a newly-created temporary directory.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "validTestPaths")
  public void testValidFileExistsAtPath(final String[] pathComponents)
         throws Exception
  {
    final String propertyName = UUID.randomUUID().toString();
    assertNull(System.getProperty(propertyName));

    try
    {
      final File baseDir = createTempDir();
      final File targetFile =
           StaticUtils.constructPath(baseDir, pathComponents);

      final File parentDir = targetFile.getParentFile();
      assertTrue(parentDir.mkdirs());

      Files.copy(
           JVMDefaultTrustManager.getInstance().getCACertsFile().toPath(),
           targetFile.toPath());

      System.setProperty(propertyName, baseDir.getAbsolutePath());

      final JVMDefaultTrustManager trustManager =
           new JVMDefaultTrustManager(propertyName);
      assertNotNull(trustManager);

      assertNotNull(trustManager.getKeyStore());

      assertNotNull(trustManager.getCACertsFile());

      assertNotNull(trustManager.getTrustedIssuerCertificates());
      assertFalse(trustManager.getTrustedIssuerCertificates().isEmpty());

      assertNotNull(trustManager.getAcceptedIssuers());
      assertTrue(trustManager.getAcceptedIssuers().length > 0);
    }
    finally
    {
      System.clearProperty(propertyName);
    }
  }



  /**
   * Retrieves an iterator that can be used to access paths for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   *
   * @return  In iterator that can be used to access paths for testing.
   */
  @DataProvider(name = "validTestPaths")
  public Iterator<Object[]> getValidTestPaths()
         throws Exception
  {
    final ArrayList<Object[]> paths = new ArrayList<>(15);

    paths.add(new Object[]
    {
      new String[] { "lib", "security", "cacerts" }
    });

    for (final String extension : JVMDefaultTrustManager.FILE_EXTENSIONS)
    {
      paths.add(new Object[]
      {
        new String[] { "lib", "security", "cacerts" + extension }
      });
    }

    paths.add(new Object[]
    {
      new String[] { "jre", "lib", "security", "cacerts" }
    });

    for (final String extension : JVMDefaultTrustManager.FILE_EXTENSIONS)
    {
      paths.add(new Object[]
      {
        new String[] { "jre", "lib", "security", "cacerts" + extension }
      });
    }

    paths.add(new Object[]
    {
      new String[] { "some", "unexpected", "dir", "cacerts" }
    });

    for (final String extension : JVMDefaultTrustManager.FILE_EXTENSIONS)
    {
      paths.add(new Object[]
      {
        new String[] { "some", "unexpected", "dir", "cacerts" + extension }
      });
    }

    return paths.iterator();
  }



  /**
   * Tests the behavior when there is an invalid cacerts file in the specified
   * location.
   *
   * @param  pathComponents  The path components to the expected file, relative
   *                         to a newly-created temporary directory.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "validTestPaths")
  public void testInvalidFileExistsAtPath(final String[] pathComponents)
         throws Exception
  {
    final String propertyName = UUID.randomUUID().toString();
    assertNull(System.getProperty(propertyName));

    try
    {
      final File baseDir = createTempDir();
      final File targetFile =
           StaticUtils.constructPath(baseDir, pathComponents);

      final File parentDir = targetFile.getParentFile();
      assertTrue(parentDir.mkdirs());

      try (PrintStream ps = new PrintStream(targetFile))
      {
        ps.println("This is not a valid cacerts file.");
      }

      System.setProperty(propertyName, baseDir.getAbsolutePath());

      final JVMDefaultTrustManager trustManager =
           new JVMDefaultTrustManager(propertyName);
      assertNotNull(trustManager);

      try
      {
        trustManager.getKeyStore();
        fail("Expected a CertificateException from getKeyStore");
      }
      catch (final CertificateException ce)
      {
        // This was expected.
      }

      try
      {
        trustManager.getCACertsFile();
        fail("Expected a CertificateException from getCACertsFile");
      }
      catch (final CertificateException ce)
      {
        // This was expected.
      }

      try
      {
        trustManager.getTrustedIssuerCertificates();
        fail("Expected a CertificateException from getCACertsFile");
      }
      catch (final CertificateException ce)
      {
        // This was expected.
      }

      assertNotNull(trustManager.getAcceptedIssuers());
      assertEquals(trustManager.getAcceptedIssuers().length, 0);

      try
      {
        trustManager.checkTrusted(null);
        fail("Expected a CertificateException from checkTrusted");
      }
      catch (final CertificateException ce)
      {
        // This was expected.
      }
    }
    finally
    {
      System.clearProperty(propertyName);
    }
  }



  /**
   * Tests the {@code checkTrusted} method with a null chain.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testCheckTrustedWithNullChain()
         throws Exception
  {
    JVMDefaultTrustManager.getInstance().checkTrusted(null);
  }



  /**
   * Tests the {@code checkTrusted} method with an empty chain.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testCheckTrustedWithEmptyChain()
         throws Exception
  {
    JVMDefaultTrustManager.getInstance().checkTrusted(
         new X509Certificate[0]);
  }



  /**
   * Tests the behavior of the various methods for checking trust.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCheckTrustedWithSingleCertificateChain()
         throws Exception
  {
    final Date currentDate = new Date();
    for (final X509Certificate cert :
         JVMDefaultTrustManager.getInstance().getTrustedIssuerCertificates())
    {
      boolean trusted = true;

      final Date notBefore = cert.getNotBefore();
      if (currentDate.before(notBefore))
      {
        trusted = false;
      }

      final Date notAfter = cert.getNotAfter();
      if (currentDate.after(notAfter))
      {
        trusted = false;
      }

      try
      {
        JVMDefaultTrustManager.getInstance().checkClientTrusted(
             new X509Certificate[] { cert }, "Doesn't Matter");
        assertTrue(trusted);
      }
      catch (final CertificateException ce)
      {
        assertFalse(trusted);
      }

      try
      {
        JVMDefaultTrustManager.getInstance().checkServerTrusted(
             new X509Certificate[] { cert }, "Doesn't Matter");
        assertTrue(trusted);
      }
      catch (final CertificateException ce)
      {
        assertFalse(trusted);
      }
    }
  }



  /**
   * Tests the {@code checkTrusted} method with a self-signed certificate that
   * is expired.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCheckTrustedWithExpiredSelfSignedCertificate()
         throws Exception
  {
    // Open a keystore with a self-signed certificate.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File serverKeyStore = new File(resourceDir, "expired.keystore");

    final KeyStore keystore = KeyStore.getInstance("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStore))
    {
      keystore.load(inputStream, "password".toCharArray());
    }


    // Get a certificate chain from the keystore.
    final Certificate[] chain = keystore.getCertificateChain("server-cert");
    assertNotNull(chain);
    assertTrue(chain.length > 0);

    final X509Certificate[] x509Chain = new X509Certificate[chain.length];
    for (int i=0; i < chain.length; i++)
    {
      x509Chain[i] = (X509Certificate) chain[i];
    }


    // Verify that the self-signed certificate is not trusted by the JVM by
    // default.
    try
    {
      JVMDefaultTrustManager.getInstance().checkServerTrusted(x509Chain,
           "Doesn't Matter");
      fail("Expected an exception from checkServerTrusted");
    }
    catch (final CertificateException ce)
    {
      // This was expected.
    }
  }



  /**
   * Tests the {@code checkTrusted} method with a self-signed certificate that
   * is not yet valid.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCheckTrustedWithNotYetValidSelfSignedCertificate()
         throws Exception
  {
    // Open a keystore with a self-signed certificate.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File serverKeyStore = new File(resourceDir, "not-yet-valid.keystore");

    final KeyStore keystore = KeyStore.getInstance("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStore))
    {
      keystore.load(inputStream, "password".toCharArray());
    }


    // Get a certificate chain from the keystore.
    final Certificate[] chain = keystore.getCertificateChain("server-cert");
    assertNotNull(chain);
    assertTrue(chain.length > 0);

    final X509Certificate[] x509Chain = new X509Certificate[chain.length];
    for (int i=0; i < chain.length; i++)
    {
      x509Chain[i] = (X509Certificate) chain[i];
    }


    // Verify that the self-signed certificate is not trusted by the JVM by
    // default.
    try
    {
      JVMDefaultTrustManager.getInstance().checkServerTrusted(x509Chain,
           "Doesn't Matter");
      fail("Expected an exception from checkServerTrusted");
    }
    catch (final CertificateException ce)
    {
      // This was expected.
    }
  }



  /**
   * Tests the {@code checkTrusted} method with a self-signed certificate that
   * is within its validity window but will not be considered trusted by this
   * trust manager.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCheckTrustedWithSelfSignedCertificateWithinValidityWindow()
         throws Exception
  {
    // Open a keystore with a self-signed certificate.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File serverKeyStore = new File(resourceDir, "server.keystore");

    final KeyStore keystore = KeyStore.getInstance("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStore))
    {
      keystore.load(inputStream, "password".toCharArray());
    }


    // Get a certificate chain from the keystore.
    final Certificate[] chain = keystore.getCertificateChain("server-cert");
    assertNotNull(chain);
    assertTrue(chain.length > 0);

    final X509Certificate[] x509Chain = new X509Certificate[chain.length];
    for (int i=0; i < chain.length; i++)
    {
      x509Chain[i] = (X509Certificate) chain[i];
    }


    // Verify that the self-signed certificate is not trusted by the JVM by
    // default.
    try
    {
      JVMDefaultTrustManager.getInstance().checkServerTrusted(x509Chain,
           "Doesn't Matter");
      fail("Expected an exception from checkServerTrusted");
    }
    catch (final CertificateException ce)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior of the {@code chainToString} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testChainToString()
         throws Exception
  {
    final Collection<X509Certificate> certificateCollection =
         JVMDefaultTrustManager.getInstance().getTrustedIssuerCertificates();
    final X509Certificate[] certificateArray =
         new X509Certificate[certificateCollection.size()];
    certificateCollection.toArray(certificateArray);

    for (int i=0; i < certificateArray.length; i++)
    {
      final X509Certificate[] chain = new X509Certificate[i];
      System.arraycopy(certificateArray, 0, chain, 0, i);

      assertNotNull(JVMDefaultTrustManager.chainToString(chain));
    }
  }
}
