/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.util.StaticUtils;



/**
 * This class ensures that the LDAP SDK code does not call any prohibited
 * methods that may cause problems under certain cases.
 */
public final class ProhibitedMethodCallsTestCase
       extends LDAPSDKTestCase
{
  /**
   * Examines all source code files to ensure that there are no inappropriate
   * uses of the {@code System.getProperties} method.
   *
   * @param  f  The source file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "sourceCodeFiles")
  public void testSystemGetProperties(final File f)
         throws Exception
  {
    final Map<String,Set<Integer>> allowedExceptions = StaticUtils.mapOf(
         "StaticUtils.java", StaticUtils.setOf(257, 259, 272, 283));

    final Map<Integer,String> unwrappedLines =
         unwrapSourceLines(readFileLines(f));
    for (final Map.Entry<Integer,String> e : unwrappedLines.entrySet())
    {
      final int lineNumber = e.getKey();
      final String line = e.getValue();
      if (line.contains("System.getProperties"))
      {
        final Set<Integer> allowedLineNumbers =
             allowedExceptions.get(f.getName());
        if ((allowedLineNumbers != null) && allowedLineNumbers.contains(
             lineNumber))
        {
          // This is an explicitly allowed use of the method.  Don't fail
          // because of it.
          continue;
        }

        fail("Source code file " + f.getAbsolutePath() +
             " contains a forbidden use of System.getProperties, which may " +
             "fail under certain security managers.  You should replace the " +
             "call with StaticUtils.getSystemProperties.  The offense is on " +
             "the following line (at or near line " + lineNumber + "):" +
             StaticUtils.EOL + StaticUtils.EOL + line);
      }
    }
  }



  /**
   * Examines all source code files to ensure that there are no inappropriate
   * uses of the {@code System.getProperty} method.
   *
   * @param  f  The source file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "sourceCodeFiles")
  public void testSystemGetProperty(final File f)
         throws Exception
  {
    final Map<String,Set<Integer>> allowedExceptions = StaticUtils.mapOf(
         "StaticUtils.java", StaticUtils.setOf(314, 342, 346, 376, 380));

    final Map<Integer,String> unwrappedLines =
         unwrapSourceLines(readFileLines(f));
    for (final Map.Entry<Integer,String> e : unwrappedLines.entrySet())
    {
      final int lineNumber = e.getKey();
      final String line = e.getValue();
      if (line.contains("System.getProperty"))
      {
        final Set<Integer> allowedLineNumbers =
             allowedExceptions.get(f.getName());
        if ((allowedLineNumbers != null) && allowedLineNumbers.contains(
             lineNumber))
        {
          // This is an explicitly allowed use of the method.  Don't fail
          // because of it.
          continue;
        }

        fail("Source code file " + f.getAbsolutePath() +
             " contains a forbidden use of System.getProperty, which may " +
             "fail under certain security managers.  You should replace the " +
             "call with StaticUtils.getSystemProperty.  The offense is on " +
             "the following line (at or near line " + lineNumber + "):" +
             StaticUtils.EOL + StaticUtils.EOL + line);
      }
    }
  }



  /**
   * Examines all source code files to ensure that there are no inappropriate
   * uses of the {@code System.setProperty} method.
   *
   * @param  f  The source file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "sourceCodeFiles")
  public void testSystemSetProperty(final File f)
         throws Exception
  {
    final Map<String,Set<Integer>> allowedExceptions = StaticUtils.mapOf(
         "StaticUtils.java", StaticUtils.setOf(416, 421));

    final Map<Integer,String> unwrappedLines =
         unwrapSourceLines(readFileLines(f));
    for (final Map.Entry<Integer,String> e : unwrappedLines.entrySet())
    {
      final int lineNumber = e.getKey();
      final String line = e.getValue();
      if (line.contains("System.setProperty"))
      {
        final Set<Integer> allowedLineNumbers =
             allowedExceptions.get(f.getName());
        if ((allowedLineNumbers != null) && allowedLineNumbers.contains(
             lineNumber))
        {
          // This is an explicitly allowed use of the method.  Don't fail
          // because of it.
          continue;
        }

        fail("Source code file " + f.getAbsolutePath() +
             " contains a forbidden use of System.setProperty, which may " +
             "fail under certain security managers.  You should replace the " +
             "call with StaticUtils.setSystemProperty.  The offense is on " +
             "the following line (at or near line " + lineNumber + "):" +
             StaticUtils.EOL + StaticUtils.EOL + line);
      }
    }
  }



  /**
   * Examines all source code files to ensure that there are no inappropriate
   * uses of the {@code System.clearProperty} method.
   *
   * @param  f  The source file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "sourceCodeFiles")
  public void testSystemClearProperty(final File f)
         throws Exception
  {
    final Map<String,Set<Integer>> allowedExceptions = StaticUtils.mapOf(
         "StaticUtils.java", StaticUtils.setOf(412, 422, 449, 453));

    final Map<Integer,String> unwrappedLines =
         unwrapSourceLines(readFileLines(f));
    for (final Map.Entry<Integer,String> e : unwrappedLines.entrySet())
    {
      final int lineNumber = e.getKey();
      final String line = e.getValue();
      if (line.contains("System.clearProperty"))
      {
        final Set<Integer> allowedLineNumbers =
             allowedExceptions.get(f.getName());
        if ((allowedLineNumbers != null) && allowedLineNumbers.contains(
             lineNumber))
        {
          // This is an explicitly allowed use of the method.  Don't fail
          // because of it.
          continue;
        }

        fail("Source code file " + f.getAbsolutePath() +
             " contains a forbidden use of System.clearProperty, which may " +
             "fail under certain security managers.  You should replace the " +
             "call with StaticUtils.clearSystemProperty.  The offense is on " +
             "the following line (at or near line " + lineNumber + "):" +
             StaticUtils.EOL + StaticUtils.EOL + line);
      }
    }
  }



  /**
   * Examines all source code files to ensure that there are no inappropriate
   * uses of the {@code System.getenv} method.
   *
   * @param  f  The source file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "sourceCodeFiles")
  public void testSystemGetEnv(final File f)
         throws Exception
  {
    final Map<String,Set<Integer>> allowedExceptions = StaticUtils.mapOf(
         "StaticUtils.java", StaticUtils.setOf(476, 480, 505, 509));

    final Map<Integer,String> unwrappedLines =
         unwrapSourceLines(readFileLines(f));
    for (final Map.Entry<Integer,String> e : unwrappedLines.entrySet())
    {
      final int lineNumber = e.getKey();
      final String line = e.getValue();
      if (line.contains("System.getenv"))
      {
        final Set<Integer> allowedLineNumbers =
             allowedExceptions.get(f.getName());
        if ((allowedLineNumbers != null) && allowedLineNumbers.contains(
             lineNumber))
        {
          // This is an explicitly allowed use of the method.  Don't fail
          // because of it.
          continue;
        }

        fail("Source code file " + f.getAbsolutePath() +
             " contains a forbidden use of System.getenv, which may " +
             "fail under certain security managers.  You should replace the " +
             "call with StaticUtils.getEnvironmentVariable or " +
             "StaticUtils.getEnvironmentVariables.  The offense is on the " +
             "following line (at or near line " + lineNumber + "):" +
             StaticUtils.EOL + StaticUtils.EOL + line);
      }
    }
  }



  /**
   * Examines all source code files to ensure that there are no inappropriate
   * uses of the {@code Logger.setLevel} method.
   *
   * @param  f  The source file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "sourceCodeFiles")
  public void testLoggerLogLevel(final File f)
         throws Exception
  {
    final Map<String,Set<Integer>> allowedExceptions = StaticUtils.mapOf(
         "Debug.java", StaticUtils.setOf(91),
         "StaticUtils.java", StaticUtils.setOf(563, 586));

    final Map<Integer,String> unwrappedLines =
         unwrapSourceLines(readFileLines(f));
    for (final Map.Entry<Integer,String> e : unwrappedLines.entrySet())
    {
      final int lineNumber = e.getKey();
      final String line = e.getValue();
      if (line.contains("setLevel"))
      {
        final Set<Integer> allowedLineNumbers =
             allowedExceptions.get(f.getName());
        if ((allowedLineNumbers != null) && allowedLineNumbers.contains(
             lineNumber))
        {
          // This is an explicitly allowed use of the method.  Don't fail
          // because of it.
          continue;
        }

        fail("Source code file " + f.getAbsolutePath() +
             " looks like it might contain a forbidden use of " +
             "Logger.setLevel or Handler.setLevel, which may fail under " +
             "certain security managers.  You should replace the call with " +
             "StaticUtils.setLoggerLevel or StaticUtils.setLogHandlerLevel.  " +
             "The offense is on the following line (at or near line " +
             lineNumber + "):" + StaticUtils.EOL + StaticUtils.EOL + line);
      }
    }
  }



  /**
   * Examines all source code files to ensure that there are no inappropriate
   * uses of the {@code CertificateFactory.getInstance} method.
   *
   * @param  f  The source file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "sourceCodeFiles")
  public void testCertificateFactoryGetInstance(final File f)
         throws Exception
  {
    if (f.getName().equals("CryptoHelper.java"))
    {
      // We will allow this method in CryptoHelper.
      return;
    }

    final Map<Integer,String> unwrappedLines =
         unwrapSourceLines(readFileLines(f));
    for (final Map.Entry<Integer,String> e : unwrappedLines.entrySet())
    {
      final int lineNumber = e.getKey();
      final String line = e.getValue();
      if (line.contains("CertificateFactory.getInstance"))
      {
        fail("Source code file " + f.getAbsolutePath() +
             " contains a forbidden use of CertificateFactory.getInstance, " +
             "which may be inappropriate when running in FIPS mode.  You " +
             "should replace the call with " +
             "CryptoHelper.getCertificateFactory.  The offense is on the " +
             "following line (at or near line " + lineNumber + "):" +
             StaticUtils.EOL + StaticUtils.EOL + line);
      }
    }
  }



  /**
   * Examines all source code files to ensure that there are no inappropriate
   * uses of the {@code Cipher.getInstance} method.
   *
   * @param  f  The source file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "sourceCodeFiles")
  public void testCipherGetInstance(final File f)
         throws Exception
  {
    if (f.getName().equals("CryptoHelper.java"))
    {
      // We will allow this method in CryptoHelper.
      return;
    }

    final Map<Integer,String> unwrappedLines =
         unwrapSourceLines(readFileLines(f));
    for (final Map.Entry<Integer,String> e : unwrappedLines.entrySet())
    {
      final int lineNumber = e.getKey();
      final String line = e.getValue();
      if (line.contains("Cipher.getInstance"))
      {
        fail("Source code file " + f.getAbsolutePath() +
             " contains a forbidden use of Cipher.getInstance, which may be " +
             "inappropriate when running in FIPS mode.  You should replace " +
             "the call with CryptoHelper.getCipher.  The offense is on the " +
             "following line (at or near line " + lineNumber + "):" +
             StaticUtils.EOL + StaticUtils.EOL + line);
      }
    }
  }



  /**
   * Examines all source code files to ensure that there are no inappropriate
   * uses of the {@code KeyFactory.getInstance} method.
   *
   * @param  f  The source file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "sourceCodeFiles")
  public void testKeyFactoryGetInstance(final File f)
         throws Exception
  {
    if (f.getName().equals("CryptoHelper.java"))
    {
      // We will allow this method in CryptoHelper.
      return;
    }

    final Map<Integer,String> unwrappedLines =
         unwrapSourceLines(readFileLines(f));
    for (final Map.Entry<Integer,String> e : unwrappedLines.entrySet())
    {
      final int lineNumber = e.getKey();
      final String line = e.getValue();
      if (line.contains("KeyFactory.getInstance"))
      {
        fail("Source code file " + f.getAbsolutePath() +
             " contains a forbidden use of KeyFactory.getInstance, which may " +
             "be inappropriate when running in FIPS mode.  You should " +
             "replace the call with CryptoHelper.getKeyFactory.  The offense " +
             "is on the following line (at or near line " + lineNumber + "):" +
             StaticUtils.EOL + StaticUtils.EOL + line);
      }
    }
  }



  /**
   * Examines all source code files to ensure that there are no inappropriate
   * uses of the {@code KeyManagerFactory.getInstance} method.
   *
   * @param  f  The source file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "sourceCodeFiles")
  public void testKeyManagerFactoryGetInstance(final File f)
         throws Exception
  {
    if (f.getName().equals("CryptoHelper.java"))
    {
      // We will allow this method in CryptoHelper.
      return;
    }

    final Map<Integer,String> unwrappedLines =
         unwrapSourceLines(readFileLines(f));
    for (final Map.Entry<Integer,String> e : unwrappedLines.entrySet())
    {
      final int lineNumber = e.getKey();
      final String line = e.getValue();
      if (line.contains("KeyManagerFactory.getInstance"))
      {
        fail("Source code file " + f.getAbsolutePath() +
             " contains a forbidden use of KeyManagerFactory.getInstance, " +
             "which may be inappropriate when running in FIPS mode.  You " +
             "should replace the call with " +
             "CryptoHelper.getKeyManagerFactory.  The offense is on the " +
             "following line (at or near line " + lineNumber + "):" +
             StaticUtils.EOL + StaticUtils.EOL + line);
      }
    }
  }



  /**
   * Examines all source code files to ensure that there are no inappropriate
   * uses of the {@code KeyPairGenerator.getInstance} method.
   *
   * @param  f  The source file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "sourceCodeFiles")
  public void testKeyPairGeneratorGetInstance(final File f)
         throws Exception
  {
    if (f.getName().equals("CryptoHelper.java"))
    {
      // We will allow this method in CryptoHelper.
      return;
    }

    final Map<Integer,String> unwrappedLines =
         unwrapSourceLines(readFileLines(f));
    for (final Map.Entry<Integer,String> e : unwrappedLines.entrySet())
    {
      final int lineNumber = e.getKey();
      final String line = e.getValue();
      if (line.contains("KeyPairGenerator.getInstance"))
      {
        fail("Source code file " + f.getAbsolutePath() +
             " contains a forbidden use of KeyPairGenerator.getInstance, " +
             "which may be inappropriate when running in FIPS mode.  You " +
             "should replace the call with CryptoHelper.getPairGenerator.  " +
             "The offense is on the following line (at or near line " +
             lineNumber + "):" + StaticUtils.EOL + StaticUtils.EOL + line);
      }
    }
  }



  /**
   * Examines all source code files to ensure that there are no inappropriate
   * uses of the {@code KeyStore.getDefaultType} method.
   *
   * @param  f  The source file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "sourceCodeFiles")
  public void testKeyStoreGetDefaultType(final File f)
         throws Exception
  {
    if (f.getName().equals("CryptoHelper.java"))
    {
      // We will allow this method in CryptoHelper.
      return;
    }

    final Map<Integer,String> unwrappedLines =
         unwrapSourceLines(readFileLines(f));
    for (final Map.Entry<Integer,String> e : unwrappedLines.entrySet())
    {
      final int lineNumber = e.getKey();
      final String line = e.getValue();
      if (line.contains("KeyStore.getDefaultType"))
      {
        fail("Source code file " + f.getAbsolutePath() +
             " contains a forbidden use of KeyStore.getDefaultType, which " +
             "may be inappropriate when running in FIPS mode.  You should " +
             "replace the call with CryptoHelper.getDefaultKeyStoreType.  " +
             "The offense is on the following line (at or near line " +
             lineNumber + "):" + StaticUtils.EOL + StaticUtils.EOL + line);
      }
    }
  }



  /**
   * Examines all source code files to ensure that there are no inappropriate
   * uses of the {@code KeyStore.getInstance} method.
   *
   * @param  f  The source file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "sourceCodeFiles")
  public void testKeyStoreGetInstance(final File f)
         throws Exception
  {
    if (f.getName().equals("CryptoHelper.java"))
    {
      // We will allow this method in CryptoHelper.
      return;
    }

    final Map<Integer,String> unwrappedLines =
         unwrapSourceLines(readFileLines(f));
    for (final Map.Entry<Integer,String> e : unwrappedLines.entrySet())
    {
      final int lineNumber = e.getKey();
      final String line = e.getValue();
      if (line.contains("KeyStore.getInstance"))
      {
        fail("Source code file " + f.getAbsolutePath() +
             " contains a forbidden use of KeyStore.getInstance, which may " +
             "be inappropriate when running in FIPS mode.  You should " +
             "replace the call with CryptoHelper.getKeyStore.  The offense " +
             "is on the following line (at or near line " + lineNumber + "):" +
             StaticUtils.EOL + StaticUtils.EOL + line);
      }
    }
  }



  /**
   * Examines all source code files to ensure that there are no inappropriate
   * uses of the {@code Mac.getInstance} method.
   *
   * @param  f  The source file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "sourceCodeFiles")
  public void testMacGetInstance(final File f)
         throws Exception
  {
    if (f.getName().equals("CryptoHelper.java"))
    {
      // We will allow this method in CryptoHelper.
      return;
    }

    final Map<Integer,String> unwrappedLines =
         unwrapSourceLines(readFileLines(f));
    for (final Map.Entry<Integer,String> e : unwrappedLines.entrySet())
    {
      final int lineNumber = e.getKey();
      final String line = e.getValue();
      if (line.contains("Mac.getInstance"))
      {
        fail("Source code file " + f.getAbsolutePath() +
             " contains a forbidden use of Mac.getInstance, which may " +
             "be inappropriate when running in FIPS mode.  You should " +
             "replace the call with CryptoHelper.getMAC.  The offense is " +
             "on the following line (at or near line " + lineNumber + "):" +
             StaticUtils.EOL + StaticUtils.EOL + line);
      }
    }
  }



  /**
   * Examines all source code files to ensure that there are no inappropriate
   * uses of the {@code MessageDigest.getInstance} method.
   *
   * @param  f  The source file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "sourceCodeFiles")
  public void testMessageDigestGetInstance(final File f)
         throws Exception
  {
    if (f.getName().equals("CryptoHelper.java"))
    {
      // We will allow this method in CryptoHelper.
      return;
    }

    final Map<Integer,String> unwrappedLines =
         unwrapSourceLines(readFileLines(f));
    for (final Map.Entry<Integer,String> e : unwrappedLines.entrySet())
    {
      final int lineNumber = e.getKey();
      final String line = e.getValue();
      if (line.contains("MessageDigest.getInstance"))
      {
        fail("Source code file " + f.getAbsolutePath() +
             " contains a forbidden use of MessageDigest.getInstance, which " +
             "may be inappropriate when running in FIPS mode.  You should " +
             "replace the call with CryptoHelper.getMessageDigest.  The " +
             "offense is on the following line (at or near line " + lineNumber +
             "):" + StaticUtils.EOL + StaticUtils.EOL + line);
      }
    }
  }



  /**
   * Examines all source code files to ensure that there are no inappropriate
   * uses of the {@code SecretKeyFactory.getInstance} method.
   *
   * @param  f  The source file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "sourceCodeFiles")
  public void testSecretKeyFactoryGetInstance(final File f)
         throws Exception
  {
    if (f.getName().equals("CryptoHelper.java"))
    {
      // We will allow this method in CryptoHelper.
      return;
    }

    final Map<Integer,String> unwrappedLines =
         unwrapSourceLines(readFileLines(f));
    for (final Map.Entry<Integer,String> e : unwrappedLines.entrySet())
    {
      final int lineNumber = e.getKey();
      final String line = e.getValue();
      if (line.contains("SecretKeyFactory.getInstance"))
      {
        fail("Source code file " + f.getAbsolutePath() +
             " contains a forbidden use of SecretKeyFactory.getInstance, " +
             "which may be inappropriate when running in FIPS mode.  You " +
             "should replace the call with " +
             "CryptoHelper.getSecretKeyFactory.  The offense is on the " +
             "following line (at or near line " + lineNumber + "):" +
             StaticUtils.EOL + StaticUtils.EOL + line);
      }
    }
  }



  /**
   * Examines all source code files to ensure that there are no inappropriate
   * uses of the {@code SecureRandom} constructor.
   *
   * @param  f  The source file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "sourceCodeFiles")
  public void testSecureRandomConstructor(final File f)
         throws Exception
  {
    if (f.getName().equals("CryptoHelper.java"))
    {
      // We will allow this method in CryptoHelper.
      return;
    }

    final Map<Integer,String> unwrappedLines =
         unwrapSourceLines(readFileLines(f));
    for (final Map.Entry<Integer,String> e : unwrappedLines.entrySet())
    {
      final int lineNumber = e.getKey();
      final String line = e.getValue();
      if (line.contains("new SecureRandom("))
      {
        fail("Source code file " + f.getAbsolutePath() +
             " contains a forbidden use of a SecureRandom constructor, " +
             "which may be inappropriate when running in FIPS mode.  You " +
             "should replace the call with " +
             "CryptoHelper.getSecureRandom.  The offense is on the " +
             "following line (at or near line " + lineNumber + "):" +
             StaticUtils.EOL + StaticUtils.EOL + line);
      }
    }
  }



  /**
   * Examines all source code files to ensure that there are no inappropriate
   * uses of the {@code SecureRandom.getInstance} method.
   *
   * @param  f  The source file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "sourceCodeFiles")
  public void testSecureRandomGetInstance(final File f)
         throws Exception
  {
    if (f.getName().equals("CryptoHelper.java"))
    {
      // We will allow this method in CryptoHelper.
      return;
    }

    final Map<Integer,String> unwrappedLines =
         unwrapSourceLines(readFileLines(f));
    for (final Map.Entry<Integer,String> e : unwrappedLines.entrySet())
    {
      final int lineNumber = e.getKey();
      final String line = e.getValue();
      if (line.contains("SecureRandom.getInstance"))
      {
        fail("Source code file " + f.getAbsolutePath() +
             " contains a forbidden use of SecureRandom.getInstance, " +
             "which may be inappropriate when running in FIPS mode.  You " +
             "should replace the call with " +
             "CryptoHelper.getSecureRandom.  The offense is on the " +
             "following line (at or near line " + lineNumber + "):" +
             StaticUtils.EOL + StaticUtils.EOL + line);
      }
    }
  }



  /**
   * Examines all source code files to ensure that there are no inappropriate
   * uses of the {@code Signature.getInstance} method.
   *
   * @param  f  The source file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "sourceCodeFiles")
  public void testSignatureGetInstance(final File f)
         throws Exception
  {
    if (f.getName().equals("CryptoHelper.java"))
    {
      // We will allow this method in CryptoHelper.
      return;
    }

    final Map<Integer,String> unwrappedLines =
         unwrapSourceLines(readFileLines(f));
    for (final Map.Entry<Integer,String> e : unwrappedLines.entrySet())
    {
      final int lineNumber = e.getKey();
      final String line = e.getValue();
      if (line.contains("Signature.getInstance"))
      {
        fail("Source code file " + f.getAbsolutePath() +
             " contains a forbidden use of Signature.getInstance, which may " +
             "be inappropriate when running in FIPS mode.  You should " +
             "replace the call with CryptoHelper.getSignature.  The offense " +
             "is on the following line (at or near line " + lineNumber + "):" +
             StaticUtils.EOL + StaticUtils.EOL + line);
      }
    }
  }



  /**
   * Examines all source code files to ensure that there are no inappropriate
   * uses of the {@code SSLContext.getDefault} method.
   *
   * @param  f  The source file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "sourceCodeFiles")
  public void testSSLContextGetDefault(final File f)
         throws Exception
  {
    if (f.getName().equals("CryptoHelper.java") ||
         f.getName().equals("TLSCipherSuiteSelector.java"))
    {
      // We will allow this method in CryptoHelper.
      return;
    }

    final Map<Integer,String> unwrappedLines =
         unwrapSourceLines(readFileLines(f));
    for (final Map.Entry<Integer,String> e : unwrappedLines.entrySet())
    {
      final int lineNumber = e.getKey();
      final String line = e.getValue();
      if (line.contains("SSLContext.getDefault"))
      {
        fail("Source code file " + f.getAbsolutePath() +
             " contains a forbidden use of SSLContext.getDefault, which may " +
             "be inappropriate when running in FIPS mode.  You should " +
             "replace the call with CryptoHelper.getDefaultSSLContext.  The " +
             "offense is on the following line (at or near line " + lineNumber +
             "):" + StaticUtils.EOL + StaticUtils.EOL + line);
      }
    }
  }



  /**
   * Examines all source code files to ensure that there are no inappropriate
   * uses of the {@code SSLContext.getInstance} method.
   *
   * @param  f  The source file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "sourceCodeFiles")
  public void testSSLContextGetInstance(final File f)
         throws Exception
  {
    if (f.getName().equals("CryptoHelper.java"))
    {
      // We will allow this method in CryptoHelper.
      return;
    }

    final Map<Integer,String> unwrappedLines =
         unwrapSourceLines(readFileLines(f));
    for (final Map.Entry<Integer,String> e : unwrappedLines.entrySet())
    {
      final int lineNumber = e.getKey();
      final String line = e.getValue();
      if (line.contains("SSLContext.getInstance"))
      {
        fail("Source code file " + f.getAbsolutePath() +
             " contains a forbidden use of SSLContext.getInstance, which may " +
             "be inappropriate when running in FIPS mode.  You should " +
             "replace the call with CryptoHelper.getSSLContext.  The offense " +
             "is on the following line (at or near line " + lineNumber + "):" +
             StaticUtils.EOL + StaticUtils.EOL + line);
      }
    }
  }



  /**
   * Examines all source code files to ensure that there are no inappropriate
   * uses of the {@code TrustManagerFactory.getInstance} method.
   *
   * @param  f  The source file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "sourceCodeFiles")
  public void testTrustManagerFactoryGetInstance(final File f)
         throws Exception
  {
    if (f.getName().equals("CryptoHelper.java"))
    {
      // We will allow this method in CryptoHelper.
      return;
    }

    final Map<Integer,String> unwrappedLines =
         unwrapSourceLines(readFileLines(f));
    for (final Map.Entry<Integer,String> e : unwrappedLines.entrySet())
    {
      final int lineNumber = e.getKey();
      final String line = e.getValue();
      if (line.contains("TrustManagerFactory.getInstance"))
      {
        fail("Source code file " + f.getAbsolutePath() +
             " contains a forbidden use of SSLContext.getInstance, which may " +
             "be inappropriate when running in FIPS mode.  You should " +
             "replace the call with CryptoHelper.getSSLContext.  The offense " +
             "is on the following line (at or near line " + lineNumber + "):" +
             StaticUtils.EOL + StaticUtils.EOL + line);
      }
    }
  }



  /**
   * Retrieves an iterator that may be used to access all of the files in the
   * LDAP SDK source code.
   *
   * @return  An iterator that may be used to access all of the files in the
   *          LDAP SDK source code.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name = "sourceCodeFiles")
  public Iterator<Object[]> getSourceCodeFiles()
         throws Exception
  {
    final List<Object[]> sourceCodeFiles = new ArrayList<>(100);

    final File baseDir = new File(System.getProperty("basedir"));
    assertNotNull(baseDir);
    assertTrue(baseDir.exists());
    assertTrue(baseDir.isDirectory());
    assertTrue(baseDir.listFiles().length > 0);

    final File srcDir = new File(baseDir, "src");
    assertNotNull(srcDir);
    assertTrue(srcDir.exists());
    assertTrue(srcDir.isDirectory());
    assertTrue(srcDir.listFiles().length > 0);

    getSourceFiles(srcDir, sourceCodeFiles);

    return sourceCodeFiles.iterator();
  }



  /**
   * Recursively adds all of the source files in the specified directory to the
   * provided list.
   *
   * @param  dir    The directory containing the files to examine.
   * @param  files  The list to which all source code files should be added.
   *                Each array should contain a single non-{@code null} item,
   *                which is a {@code File} object.
   *
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void getSourceFiles(final File dir, final List<Object[]> files)
          throws Exception
  {
    for (final File f : dir.listFiles())
    {
      if (f.isDirectory())
      {
        getSourceFiles(f, files);
      }
      else if (f.getName().endsWith(".java"))
      {
        files.add(new Object[] { f });
      }
    }
  }



  /**
   * Unwraps long lines in the specified list of source code lines so that
   * method calls should not be split across multiple lines.
   *
   * @param  sourceLines  The list of lines to be examined.
   *
   * @return  A list of unwrapped lines.
   */
  private static Map<Integer,String> unwrapSourceLines(
                                          final List<String> sourceLines)
  {
    final Map<Integer,String> unwrappedLines = new LinkedHashMap<>(
         StaticUtils.computeMapCapacity(sourceLines.size()));

    int currentLineNumber = 1;
    int currentStatementStartingLineNumber = 1;
    final StringBuilder completeLine = new StringBuilder();
    for (final String line : sourceLines)
    {
      if (line.isEmpty())
      {
        if (completeLine.length() == 0)
        {
          currentStatementStartingLineNumber++;
        }
        currentLineNumber++;
        continue;
      }

      if (line.endsWith(";") || line.endsWith("{") || line.endsWith("}"))
      {
        completeLine.append(line);
        unwrappedLines.put(currentStatementStartingLineNumber,
             completeLine.toString());
        completeLine.setLength(0);
        currentStatementStartingLineNumber = currentLineNumber + 1;
      }

      currentLineNumber++;
    }

    assertEquals(completeLine.length(), 0);
    return unwrappedLines;
  }
}
