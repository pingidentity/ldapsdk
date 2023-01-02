/*
 * Copyright 2022-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2023 Ping Identity Corporation
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
 * Copyright (C) 2022-2023 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.monitors;



import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Map;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.StaticUtils;



/**
 * This class provides test coverage for the X509CertificateMonitorEntry class.
 */
public class X509CertificateMonitorEntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the constructor with a valid entry with all
   * values present.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorAllValues()
         throws Exception
  {
    final Date currentTime = new Date();
    final Date notBeforeTime = new Date(currentTime.getTime() - 86_400_000L);
    final Date notAfterTime = new Date(currentTime.getTime() + 86_400_000L);

    Entry e = new Entry(
         "dn: cn=Test Certificate,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-x509-certificate-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Test Certificate",
         "subject: CN=Subject,O=Example Corp,C=US",
         "issuer: CN=Issuer,O=Example Corp,C=US",
         "serial-number: 12345",
         "not-valid-before: " +
              StaticUtils.encodeGeneralizedTime(notBeforeTime),
         "not-valid-after: " + StaticUtils.encodeGeneralizedTime(notAfterTime),
         "expires: 1 day",
         "expires-seconds: 86400",
         "currently-valid: true",
         "invalid-reason: None",
         "component-name: JKS Key Manager Provider",
         "component-type: Key Manager Provider",
         "context-type: provider",
         "provider-type: file-based",
         "keystore-type: JKS",
         "keystore-file: config/keystore",
         "alias: server-cert",
         "dependent-component: 'HTTPS Connection Handler' connection handler",
         "dependent-component: 'LDAP Connection Handler' connection handler",
         "dependent-component: 'LDAPS Connection Handler' connection handler",
         "property: listener-certificate");

    final X509CertificateMonitorEntry me = new X509CertificateMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-x509-certificate-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
         X509CertificateMonitorEntry.class.getName());

    assertNotNull(me.getSubjectDN());
    assertDNsEqual(me.getSubjectDN(), "CN=Subject,O=Example Corp,C=US");

    assertNotNull(me.getIssuerSubjectDN());
    assertDNsEqual(me.getIssuerSubjectDN(), "CN=Issuer,O=Example Corp,C=US");

    assertNotNull(me.getNotValidBefore());
    assertEquals(me.getNotValidBefore(), notBeforeTime);

    assertNotNull(me.getNotValidAfter());
    assertEquals(me.getNotValidAfter(), notAfterTime);

    assertNotNull(me.getSecondsUntilExpiration());
    assertEquals(me.getSecondsUntilExpiration().longValue(), 86_400L);

    assertNotNull(me.getHumanReadableTimeUntilExpiration());
    assertEquals(me.getHumanReadableTimeUntilExpiration(), "1 day");

    assertNotNull(me.getCurrentlyValid());
    assertTrue(me.getCurrentlyValid());

    assertNotNull(me.getInvalidReason());
    assertEquals(me.getInvalidReason(), "None");

    assertNotNull(me.getSerialNumber());
    assertEquals(me.getSerialNumber(), "12345");

    assertNotNull(me.getContextType());
    assertEquals(me.getContextType(), "provider");

    assertNotNull(me.getComponentType());
    assertEquals(me.getComponentType(), "Key Manager Provider");

    assertNotNull(me.getComponentName());
    assertEquals(me.getComponentName(), "JKS Key Manager Provider");

    assertNotNull(me.getKeyStoreType());
    assertEquals(me.getKeyStoreType(), "JKS");

    assertNotNull(me.getKeyStoreFile());
    assertEquals(me.getKeyStoreFile(), "config/keystore");

    assertNotNull(me.getAlias());
    assertEquals(me.getAlias(), "server-cert");

    assertNotNull(me.getProviderType());
    assertEquals(me.getProviderType(), "file-based");

    assertNotNull(me.getDependentComponents());
    assertEquals(me.getDependentComponents(),
         Arrays.asList(
              "'HTTPS Connection Handler' connection handler",
              "'LDAP Connection Handler' connection handler",
              "'LDAPS Connection Handler' connection handler"));

    assertNotNull(me.getProperties());
    assertEquals(me.getProperties(),
         Collections.singletonList("listener-certificate"));

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    final Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertFalse(me.getMonitorAttributes().isEmpty());

    assertNotNull(attrs.get("subject"));
    assertDNsEqual(attrs.get("subject").getStringValue(),
         "CN=Subject,O=Example Corp,C=US");

    assertNotNull(attrs.get("issuer"));
    assertDNsEqual(attrs.get("issuer").getStringValue(),
         "CN=Issuer,O=Example Corp,C=US");

    assertNotNull(attrs.get("not-valid-before"));
    assertEquals(attrs.get("not-valid-before").getDateValue(),
         notBeforeTime);

    assertNotNull(attrs.get("not-valid-after"));
    assertEquals(attrs.get("not-valid-after").getDateValue(),
         notAfterTime);

    assertNotNull(attrs.get("expires-seconds"));
    assertEquals(attrs.get("expires-seconds").getLongValue().longValue(),
         86_400L);

    assertNotNull(attrs.get("expires"));
    assertEquals(attrs.get("expires").getStringValue(),
         "1 day");

    assertNotNull(attrs.get("currently-valid"));
    assertTrue(attrs.get("currently-valid").getBooleanValue());

    assertNotNull(attrs.get("invalid-reason"));
    assertEquals(attrs.get("invalid-reason").getStringValue(),
         "None");

    assertNotNull(attrs.get("serial-number"));
    assertEquals(attrs.get("serial-number").getStringValue(),
         "12345");

    assertNotNull(attrs.get("context-type"));
    assertEquals(attrs.get("context-type").getStringValue(),
         "provider");

    assertNotNull(attrs.get("component-type"));
    assertEquals(attrs.get("component-type").getStringValue(),
         "Key Manager Provider");

    assertNotNull(attrs.get("component-name"));
    assertEquals(attrs.get("component-name").getStringValue(),
         "JKS Key Manager Provider");

    assertNotNull(attrs.get("keystore-type"));
    assertEquals(attrs.get("keystore-type").getStringValue(),
         "JKS");

    assertNotNull(attrs.get("keystore-file"));
    assertEquals(attrs.get("keystore-file").getStringValue(),
         "config/keystore");

    assertNotNull(attrs.get("alias"));
    assertEquals(attrs.get("alias").getStringValue(),
         "server-cert");

    assertNotNull(attrs.get("provider-type"));
    assertEquals(attrs.get("provider-type").getStringValue(),
         "file-based");

    assertNotNull(attrs.get("dependent-component"));
    assertEquals(attrs.get("dependent-component").getStringValues(),
         Arrays.asList(
              "'HTTPS Connection Handler' connection handler",
              "'LDAP Connection Handler' connection handler",
              "'LDAPS Connection Handler' connection handler"));

    assertNotNull(attrs.get("property"));
    assertEquals(attrs.get("property").getStringValues(),
         Collections.singletonList("listener-certificate"));
  }



  /**
   * Provides test coverage for the constructor with a valid entry with no
   * values present.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorNoValues()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=Test Certificate,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-x509-certificate-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Test Certificate");

    final X509CertificateMonitorEntry me = new X509CertificateMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-x509-certificate-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
         X509CertificateMonitorEntry.class.getName());

    assertNull(me.getSubjectDN());

    assertNull(me.getIssuerSubjectDN());

    assertNull(me.getNotValidBefore());

    assertNull(me.getNotValidAfter());

    assertNull(me.getSecondsUntilExpiration());

    assertNull(me.getHumanReadableTimeUntilExpiration());

    assertNull(me.getCurrentlyValid());

    assertNull(me.getInvalidReason());

    assertNull(me.getSerialNumber());

    assertNull(me.getContextType());

    assertNull(me.getComponentType());

    assertNull(me.getComponentName());

    assertNull(me.getKeyStoreType());

    assertNull(me.getKeyStoreFile());

    assertNull(me.getAlias());

    assertNull(me.getProviderType());

    assertNotNull(me.getDependentComponents());
    assertTrue(me.getDependentComponents().isEmpty());

    assertNotNull(me.getProperties());
    assertTrue(me.getProperties().isEmpty());

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    final Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertTrue(me.getMonitorAttributes().isEmpty());
  }
}
