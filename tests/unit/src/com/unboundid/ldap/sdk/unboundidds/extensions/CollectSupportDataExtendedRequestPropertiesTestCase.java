/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.unboundidds.tasks.CollectSupportDataSecurityLevel;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the collect support data
 * extended request properties.
 */
public final class CollectSupportDataExtendedRequestPropertiesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with the default set of properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultProperties()
         throws Exception
  {
    CollectSupportDataExtendedRequestProperties p =
         new CollectSupportDataExtendedRequestProperties();
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior for the archive file name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testArchiveFileName()
         throws Exception
  {
    CollectSupportDataExtendedRequestProperties p =
         new CollectSupportDataExtendedRequestProperties();
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setArchiveFileName("csd.zip");
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNotNull(p.getArchiveFileName());
    assertEquals(p.getArchiveFileName(), "csd.zip");

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setArchiveFileName(null);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior for the encryption passphrase.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEncryptionPassphrase()
         throws Exception
  {
    CollectSupportDataExtendedRequestProperties p =
         new CollectSupportDataExtendedRequestProperties();
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setEncryptionPassphrase("string");
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNotNull(p.getEncryptionPassphrase());
    assertEquals(p.getEncryptionPassphrase(),
         new ASN1OctetString((byte) 0x81, "string"));

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setEncryptionPassphrase((String) null);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setEncryptionPassphrase("bytes".getBytes());
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNotNull(p.getEncryptionPassphrase());
    assertEquals(p.getEncryptionPassphrase(),
         new ASN1OctetString((byte) 0x81, "bytes"));

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setEncryptionPassphrase((byte[]) null);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setEncryptionPassphrase(new ASN1OctetString("octetString"));
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNotNull(p.getEncryptionPassphrase());
    assertEquals(p.getEncryptionPassphrase(),
         new ASN1OctetString((byte) 0x81, "octetString"));

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setEncryptionPassphrase((ASN1OctetString) null);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior for the include expensive data flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeExpensiveData()
         throws Exception
  {
    CollectSupportDataExtendedRequestProperties p =
         new CollectSupportDataExtendedRequestProperties();
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setIncludeExpensiveData(true);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNotNull(p.getIncludeExpensiveData());
    assertTrue(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setIncludeExpensiveData(null);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setIncludeExpensiveData(false);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNotNull(p.getIncludeExpensiveData());
    assertFalse(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior for the include replication state dump flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeReplicationStateDump()
         throws Exception
  {
    CollectSupportDataExtendedRequestProperties p =
         new CollectSupportDataExtendedRequestProperties();
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setIncludeReplicationStateDump(true);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNotNull(p.getIncludeReplicationStateDump());
    assertTrue(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setIncludeReplicationStateDump(null);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setIncludeReplicationStateDump(false);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNotNull(p.getIncludeReplicationStateDump());
    assertFalse(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior for the include binary files flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeBinaryFiles()
         throws Exception
  {
    CollectSupportDataExtendedRequestProperties p =
         new CollectSupportDataExtendedRequestProperties();
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setIncludeBinaryFiles(true);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNotNull(p.getIncludeBinaryFiles());
    assertTrue(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setIncludeBinaryFiles(null);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setIncludeBinaryFiles(false);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNotNull(p.getIncludeBinaryFiles());
    assertFalse(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior for the include extension source flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeExtensionSource()
         throws Exception
  {
    CollectSupportDataExtendedRequestProperties p =
         new CollectSupportDataExtendedRequestProperties();
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setIncludeExtensionSource(true);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNotNull(p.getIncludeExtensionSource());
    assertTrue(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setIncludeExtensionSource(null);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setIncludeExtensionSource(false);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNotNull(p.getIncludeExtensionSource());
    assertFalse(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior for the use sequential mode flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUseSequentialMode()
         throws Exception
  {
    CollectSupportDataExtendedRequestProperties p =
         new CollectSupportDataExtendedRequestProperties();
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setUseSequentialMode(true);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNotNull(p.getUseSequentialMode());
    assertTrue(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setUseSequentialMode(null);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setUseSequentialMode(false);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNotNull(p.getUseSequentialMode());
    assertFalse(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior for the security level property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSecurityLevel()
         throws Exception
  {
    CollectSupportDataExtendedRequestProperties p =
         new CollectSupportDataExtendedRequestProperties();
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    for (final CollectSupportDataSecurityLevel level :
         CollectSupportDataSecurityLevel.values())
    {
      p.setSecurityLevel(level);
      p = new CollectSupportDataExtendedRequestProperties(p);

      assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

      assertNull(p.getIncludeExpensiveData());

      assertNull(p.getIncludeReplicationStateDump());

      assertNull(p.getIncludeBinaryFiles());

      assertNull(p.getIncludeExtensionSource());

      assertNull(p.getUseSequentialMode());

      assertNotNull(p.getSecurityLevel());
      assertEquals(p.getSecurityLevel(), level);

      assertNull(p.getJStackCount());

      assertNull(p.getReportCount());

      assertNull(p.getReportIntervalSeconds());

      assertNull(p.getLogCaptureWindow());

      assertNull(p.getComment());

      assertNull(p.getProxyToServerAddress());

      assertNull(p.getProxyToServerPort());

      assertNull(p.getMaximumFragmentSizeBytes());

      assertNotNull(p.toString());
    }


    p.setSecurityLevel(null);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior for the jstack count property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testJStackCount()
         throws Exception
  {
    CollectSupportDataExtendedRequestProperties p =
         new CollectSupportDataExtendedRequestProperties();
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setJStackCount(5);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNotNull(p.getJStackCount());
    assertEquals(p.getJStackCount().intValue(), 5);

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setJStackCount(null);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());

    try
    {
      p.setJStackCount(-1);
      fail("Expected an exception");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior for the report count property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReportCount()
         throws Exception
  {
    CollectSupportDataExtendedRequestProperties p =
         new CollectSupportDataExtendedRequestProperties();
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setReportCount(4);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNotNull(p.getReportCount());
    assertEquals(p.getReportCount().intValue(), 4);

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setReportCount(null);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());

    try
    {
      p.setReportCount(-1);
      fail("Expected an exception");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior for the report interval seconds property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReportIntervalSeconds()
         throws Exception
  {
    CollectSupportDataExtendedRequestProperties p =
         new CollectSupportDataExtendedRequestProperties();
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setReportIntervalSeconds(3);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNotNull(p.getReportIntervalSeconds());
    assertEquals(p.getReportIntervalSeconds().intValue(), 3);

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setReportIntervalSeconds(null);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());

    try
    {
      p.setReportIntervalSeconds(0);
      fail("Expected an exception");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior for the log capture window property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLogCaptureWindow()
         throws Exception
  {
    CollectSupportDataExtendedRequestProperties p =
         new CollectSupportDataExtendedRequestProperties();
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setLogCaptureWindow(
         ToolDefaultCollectSupportDataLogCaptureWindow.getInstance());
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNotNull(p.getLogCaptureWindow());
    assertTrue(p.getLogCaptureWindow() instanceof
         ToolDefaultCollectSupportDataLogCaptureWindow);

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setLogCaptureWindow(null);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior for the comment property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testComment()
         throws Exception
  {
    CollectSupportDataExtendedRequestProperties p =
         new CollectSupportDataExtendedRequestProperties();
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setComment("foo");
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNotNull(p.getComment());
    assertEquals(p.getComment(), "foo");

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setComment(null);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior for the proxy to server properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProxyToServer()
         throws Exception
  {
    CollectSupportDataExtendedRequestProperties p =
         new CollectSupportDataExtendedRequestProperties();
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setProxyToServer("ds.example.com", 636);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNotNull(p.getProxyToServerAddress());
    assertEquals(p.getProxyToServerAddress(), "ds.example.com");

    assertNotNull(p.getProxyToServerPort());
    assertEquals(p.getProxyToServerPort().intValue(), 636);

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setProxyToServer(null, null);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());

    try
    {
      p.setProxyToServer(null, 1234);
      fail("Expected an exception");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected.
    }

    try
    {
      p.setProxyToServer("", 1234);
      fail("Expected an exception");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected.
    }

    try
    {
      p.setProxyToServer("ds.example.com", null);
      fail("Expected an exception");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected.
    }

    try
    {
      p.setProxyToServer("ds.example.com", 123_456);
      fail("Expected an exception");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected.
    }

    try
    {
      p.setProxyToServer("ds.example.com", 0);
      fail("Expected an exception");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior for the maximum fragment size bytes property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMaximumFragmentSizeBytes()
         throws Exception
  {
    CollectSupportDataExtendedRequestProperties p =
         new CollectSupportDataExtendedRequestProperties();
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setMaximumFragmentSizeBytes(12_345_678);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNotNull(p.getMaximumFragmentSizeBytes());
    assertEquals(p.getMaximumFragmentSizeBytes().intValue(), 12_345_678);

    assertNotNull(p.toString());


    p.setMaximumFragmentSizeBytes(null);
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior when all properties are set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllProperties()
         throws Exception
  {
    CollectSupportDataExtendedRequestProperties p =
         new CollectSupportDataExtendedRequestProperties();
    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNull(p.getArchiveFileName());

    assertNull(p.getEncryptionPassphrase());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getJStackCount());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getLogCaptureWindow());

    assertNull(p.getComment());

    assertNull(p.getProxyToServerAddress());

    assertNull(p.getProxyToServerPort());

    assertNull(p.getMaximumFragmentSizeBytes());

    assertNotNull(p.toString());


    p.setArchiveFileName("csd.zip");
    p.setEncryptionPassphrase("password");
    p.setIncludeExpensiveData(true);
    p.setIncludeReplicationStateDump(true);
    p.setIncludeBinaryFiles(true);
    p.setIncludeExtensionSource(true);
    p.setUseSequentialMode(true);
    p.setSecurityLevel(CollectSupportDataSecurityLevel.OBSCURE_SECRETS);
    p.setJStackCount(1);
    p.setReportCount(2);
    p.setReportIntervalSeconds(3);
    p.setLogCaptureWindow(
         new DurationCollectSupportDataLogCaptureWindow(123_456L));
    p.setComment("comment");
    p.setProxyToServer("backend.example.com", 1636);
    p.setMaximumFragmentSizeBytes(12_345_678);

    p = new CollectSupportDataExtendedRequestProperties(p);

    assertNotNull(p.getArchiveFileName());
    assertEquals(p.getArchiveFileName(), "csd.zip");

    assertNotNull(p.getEncryptionPassphrase());
    assertEquals(p.getEncryptionPassphrase().stringValue(), "password");

    assertNotNull(p.getIncludeExpensiveData());
    assertTrue(p.getIncludeExpensiveData());

    assertNotNull(p.getIncludeReplicationStateDump());
    assertTrue(p.getIncludeReplicationStateDump());

    assertNotNull(p.getIncludeBinaryFiles());
    assertTrue(p.getIncludeBinaryFiles());

    assertNotNull(p.getIncludeExtensionSource());
    assertTrue(p.getIncludeExtensionSource());

    assertNotNull(p.getUseSequentialMode());
    assertTrue(p.getUseSequentialMode());

    assertNotNull(p.getSecurityLevel());
    assertEquals(p.getSecurityLevel(),
         CollectSupportDataSecurityLevel.OBSCURE_SECRETS);

    assertNotNull(p.getJStackCount());
    assertEquals(p.getJStackCount().intValue(), 1);

    assertNotNull(p.getReportCount());
    assertEquals(p.getReportCount().intValue(), 2);

    assertNotNull(p.getReportIntervalSeconds());
    assertEquals(p.getReportIntervalSeconds().intValue(), 3);

    assertNotNull(p.getLogCaptureWindow());
    assertTrue(p.getLogCaptureWindow() instanceof
         DurationCollectSupportDataLogCaptureWindow);

    assertNotNull(p.getComment());
    assertEquals(p.getComment(), "comment");

    assertNotNull(p.getProxyToServerAddress());
    assertEquals(p.getProxyToServerAddress(), "backend.example.com");

    assertNotNull(p.getProxyToServerPort());
    assertEquals(p.getProxyToServerPort().intValue(), 1636);

    assertNotNull(p.getMaximumFragmentSizeBytes());
    assertEquals(p.getMaximumFragmentSizeBytes().intValue(), 12_345_678);

    assertNotNull(p.toString());

    try
    {
      p.setMaximumFragmentSizeBytes(0);
      fail("Expected an exception");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected.
    }
  }
}
