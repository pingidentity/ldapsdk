/*
 * Copyright 2022-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2025 Ping Identity Corporation
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
 * Copyright (C) 2022-2025 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import java.io.File;
import java.util.concurrent.TimeUnit;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the topology registry trust
 * manager properties.
 */
public final class TopologyRegistryTrustManagerPropertiesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the default values for all properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultProperties()
         throws Exception
  {
    final File f = createTempFile();
    final TopologyRegistryTrustManagerProperties properties =
         new TopologyRegistryTrustManagerProperties(f.getAbsolutePath());

    assertEquals(properties.getConfigurationFile(), f);

    assertEquals(properties.getCacheDurationMillis(), 300_000L);

    assertFalse(properties.requirePeerCertificateInTopologyRegistry());

    assertFalse(properties.ignorePeerCertificateValidityWindow());

    assertFalse(properties.ignoreIssuerCertificateValidityWindow());

    assertNotNull(properties.toString());
    assertFalse(properties.toString().isEmpty());
  }



  /**
   * Tests the properties for the configuration file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConfigurationFile()
         throws Exception
  {
    final File originalFile = createTempFile();
    final TopologyRegistryTrustManagerProperties properties =
         new TopologyRegistryTrustManagerProperties(originalFile);

    assertEquals(properties.getConfigurationFile(), originalFile);

    assertEquals(properties.getCacheDurationMillis(), 300_000L);

    assertFalse(properties.requirePeerCertificateInTopologyRegistry());

    assertFalse(properties.ignorePeerCertificateValidityWindow());

    assertFalse(properties.ignoreIssuerCertificateValidityWindow());

    assertNotNull(properties.toString());
    assertFalse(properties.toString().isEmpty());


    final File newFile = createTempFile();
    properties.setConfigurationFile(newFile);

    assertEquals(properties.getConfigurationFile(), newFile);

    assertEquals(properties.getCacheDurationMillis(), 300_000L);

    assertFalse(properties.requirePeerCertificateInTopologyRegistry());

    assertFalse(properties.ignorePeerCertificateValidityWindow());

    assertFalse(properties.ignoreIssuerCertificateValidityWindow());

    assertNotNull(properties.toString());
    assertFalse(properties.toString().isEmpty());
  }



  /**
   * Tests the properties for the cache duration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCacheDuration()
         throws Exception
  {
    final File f = createTempFile();
    final TopologyRegistryTrustManagerProperties properties =
         new TopologyRegistryTrustManagerProperties(f);

    assertEquals(properties.getConfigurationFile(), f);

    assertEquals(properties.getCacheDurationMillis(), 300_000L);

    assertFalse(properties.requirePeerCertificateInTopologyRegistry());

    assertFalse(properties.ignorePeerCertificateValidityWindow());

    assertFalse(properties.ignoreIssuerCertificateValidityWindow());

    assertNotNull(properties.toString());
    assertFalse(properties.toString().isEmpty());


    properties.setCacheDuration(0L, TimeUnit.MILLISECONDS);

    assertEquals(properties.getConfigurationFile(), f);

    assertEquals(properties.getCacheDurationMillis(), 0L);

    assertFalse(properties.requirePeerCertificateInTopologyRegistry());

    assertFalse(properties.ignorePeerCertificateValidityWindow());

    assertFalse(properties.ignoreIssuerCertificateValidityWindow());

    assertNotNull(properties.toString());
    assertFalse(properties.toString().isEmpty());


    properties.setCacheDuration(123L, TimeUnit.MINUTES);

    assertEquals(properties.getConfigurationFile(), f);

    assertEquals(properties.getCacheDurationMillis(), (123L * 60_000L));

    assertFalse(properties.requirePeerCertificateInTopologyRegistry());

    assertFalse(properties.ignorePeerCertificateValidityWindow());

    assertFalse(properties.ignoreIssuerCertificateValidityWindow());

    assertNotNull(properties.toString());
    assertFalse(properties.toString().isEmpty());


    properties.setCacheDuration(-1L, TimeUnit.MINUTES);

    assertEquals(properties.getConfigurationFile(), f);

    assertEquals(properties.getCacheDurationMillis(), 0L);

    assertFalse(properties.requirePeerCertificateInTopologyRegistry());

    assertFalse(properties.ignorePeerCertificateValidityWindow());

    assertFalse(properties.ignoreIssuerCertificateValidityWindow());

    assertNotNull(properties.toString());
    assertFalse(properties.toString().isEmpty());
  }



  /**
   * Tests the properties requiring the peer certificate to be present in the
   * topology registry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequirePeerCertificateInTopologyRegistry()
         throws Exception
  {
    final File f = createTempFile();
    final TopologyRegistryTrustManagerProperties properties =
         new TopologyRegistryTrustManagerProperties(f);

    assertEquals(properties.getConfigurationFile(), f);

    assertEquals(properties.getCacheDurationMillis(), 300_000L);

    assertFalse(properties.requirePeerCertificateInTopologyRegistry());

    assertFalse(properties.ignorePeerCertificateValidityWindow());

    assertFalse(properties.ignoreIssuerCertificateValidityWindow());

    assertNotNull(properties.toString());
    assertFalse(properties.toString().isEmpty());


    properties.setRequirePeerCertificateInTopologyRegistry(true);

    assertEquals(properties.getConfigurationFile(), f);

    assertEquals(properties.getCacheDurationMillis(), 300_000L);

    assertTrue(properties.requirePeerCertificateInTopologyRegistry());

    assertFalse(properties.ignorePeerCertificateValidityWindow());

    assertFalse(properties.ignoreIssuerCertificateValidityWindow());

    assertNotNull(properties.toString());
    assertFalse(properties.toString().isEmpty());


    properties.setRequirePeerCertificateInTopologyRegistry(false);

    assertEquals(properties.getConfigurationFile(), f);

    assertEquals(properties.getCacheDurationMillis(), 300_000L);

    assertFalse(properties.requirePeerCertificateInTopologyRegistry());

    assertFalse(properties.ignorePeerCertificateValidityWindow());

    assertFalse(properties.ignoreIssuerCertificateValidityWindow());

    assertNotNull(properties.toString());
    assertFalse(properties.toString().isEmpty());
  }



  /**
   * Tests the properties for ignoring peer certificate validity.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIgnorePeerCertificateValidityWindow()
         throws Exception
  {
    final File f = createTempFile();
    final TopologyRegistryTrustManagerProperties properties =
         new TopologyRegistryTrustManagerProperties(f);

    assertEquals(properties.getConfigurationFile(), f);

    assertEquals(properties.getCacheDurationMillis(), 300_000L);

    assertFalse(properties.requirePeerCertificateInTopologyRegistry());

    assertFalse(properties.ignorePeerCertificateValidityWindow());

    assertFalse(properties.ignoreIssuerCertificateValidityWindow());

    assertNotNull(properties.toString());
    assertFalse(properties.toString().isEmpty());


    properties.setIgnorePeerCertificateValidityWindow(true);

    assertEquals(properties.getConfigurationFile(), f);

    assertEquals(properties.getCacheDurationMillis(), 300_000L);

    assertFalse(properties.requirePeerCertificateInTopologyRegistry());

    assertTrue(properties.ignorePeerCertificateValidityWindow());

    assertFalse(properties.ignoreIssuerCertificateValidityWindow());

    assertNotNull(properties.toString());
    assertFalse(properties.toString().isEmpty());


    properties.setIgnorePeerCertificateValidityWindow(false);

    assertEquals(properties.getConfigurationFile(), f);

    assertEquals(properties.getCacheDurationMillis(), 300_000L);

    assertFalse(properties.requirePeerCertificateInTopologyRegistry());

    assertFalse(properties.ignorePeerCertificateValidityWindow());

    assertFalse(properties.ignoreIssuerCertificateValidityWindow());

    assertNotNull(properties.toString());
    assertFalse(properties.toString().isEmpty());
  }



  /**
   * Tests the properties for ignoring issuer certificate validity.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIgnoreIssuerCertificateValidityWindow()
         throws Exception
  {
    final File f = createTempFile();
    final TopologyRegistryTrustManagerProperties properties =
         new TopologyRegistryTrustManagerProperties(f);

    assertEquals(properties.getConfigurationFile(), f);

    assertEquals(properties.getCacheDurationMillis(), 300_000L);

    assertFalse(properties.requirePeerCertificateInTopologyRegistry());

    assertFalse(properties.ignorePeerCertificateValidityWindow());

    assertFalse(properties.ignoreIssuerCertificateValidityWindow());

    assertNotNull(properties.toString());
    assertFalse(properties.toString().isEmpty());


    properties.setIgnoreIssuerCertificateValidityWindow(true);

    assertEquals(properties.getConfigurationFile(), f);

    assertEquals(properties.getCacheDurationMillis(), 300_000L);

    assertFalse(properties.requirePeerCertificateInTopologyRegistry());

    assertFalse(properties.ignorePeerCertificateValidityWindow());

    assertTrue(properties.ignoreIssuerCertificateValidityWindow());

    assertNotNull(properties.toString());
    assertFalse(properties.toString().isEmpty());


    properties.setIgnoreIssuerCertificateValidityWindow(false);

    assertEquals(properties.getConfigurationFile(), f);

    assertEquals(properties.getCacheDurationMillis(), 300_000L);

    assertFalse(properties.requirePeerCertificateInTopologyRegistry());

    assertFalse(properties.ignorePeerCertificateValidityWindow());

    assertFalse(properties.ignoreIssuerCertificateValidityWindow());

    assertNotNull(properties.toString());
    assertFalse(properties.toString().isEmpty());
  }
}
