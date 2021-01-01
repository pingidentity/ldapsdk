/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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



import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the RootDSE class.
 */
public class RootDSETestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a root DSE entry created with all of the possible attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    Entry e = new Entry(
         "dn: ",
         "objectClass: top",
         "objectClass: ds-root-dse",
         "altServer: ldap://server1.example.com/",
         "altServer: ldap://server2.example.com/",
         "changelog: cn=changelog",
         "firstChangeNumber: 1234",
         "lastChangeNumber: 5678",
         "lastPurgedChangeNumber: 1233",
         "namingContexts: dc=example,dc=com",
         "namingContexts: o=test",
         "subschemaSubentry: cn=schema",
         "supportedAuthPasswordSchemes: SHA-1",
         "supportedControl: 1.2.3.4",
         "supportedExtension: 1.2.3.5",
         "supportedFeatures: 1.2.3.6",
         "supportedLDAPVersion: 3",
         "supportedSASLMechanisms: ANONYMOUS",
         "supportedSASLMechanisms: CRAM-MD5",
         "supportedSASLMechanisms: DIGEST-MD5",
         "supportedSASLMechanisms: EXTERNAL",
         "supportedSASLMechanisms: PLAIN",
         "vendorName: Ping Identity Corporation",
         "vendorVersion: UnboundID Directory Server 1.2.3");

    RootDSE rootDSE = new RootDSE(e);
    assertNotNull(rootDSE);

    assertNotNull(rootDSE.getAltServerURIs());
    assertEquals(rootDSE.getAltServerURIs().length, 2);

    assertNotNull(rootDSE.getChangelogDN());
    assertEquals(new DN(rootDSE.getChangelogDN()), new DN("cn=changelog"));

    assertNotNull(rootDSE.getFirstChangeNumber());
    assertEquals(rootDSE.getFirstChangeNumber(), Long.valueOf(1234));

    assertNotNull(rootDSE.getLastChangeNumber());
    assertEquals(rootDSE.getLastChangeNumber(), Long.valueOf(5678));

    assertNotNull(rootDSE.getLastPurgedChangeNumber());
    assertEquals(rootDSE.getLastPurgedChangeNumber(), Long.valueOf(1233));

    assertNotNull(rootDSE.getNamingContextDNs());
    assertEquals(rootDSE.getNamingContextDNs().length, 2);

    assertNotNull(rootDSE.getSubschemaSubentryDN());

    assertNotNull(rootDSE.getSupportedAuthPasswordSchemeNames());
    assertEquals(rootDSE.getSupportedAuthPasswordSchemeNames().length, 1);
    assertTrue(rootDSE.supportsAuthPasswordScheme("SHA-1"));
    assertFalse(rootDSE.supportsAuthPasswordScheme("unsupported"));

    assertNotNull(rootDSE.getSupportedControlOIDs());
    assertEquals(rootDSE.getSupportedControlOIDs().length, 1);
    assertEquals(rootDSE.getSupportedControlOIDs()[0], "1.2.3.4");
    assertTrue(rootDSE.supportsControl("1.2.3.4"));
    assertFalse(rootDSE.supportsControl("1.2.3.3"));

    assertNotNull(rootDSE.getSupportedExtendedOperationOIDs());
    assertEquals(rootDSE.getSupportedExtendedOperationOIDs().length, 1);
    assertEquals(rootDSE.getSupportedExtendedOperationOIDs()[0], "1.2.3.5");
    assertTrue(rootDSE.supportsExtendedOperation("1.2.3.5"));
    assertFalse(rootDSE.supportsExtendedOperation("1.2.3.3"));

    assertNotNull(rootDSE.getSupportedFeatureOIDs());
    assertEquals(rootDSE.getSupportedFeatureOIDs().length, 1);
    assertEquals(rootDSE.getSupportedFeatureOIDs()[0], "1.2.3.6");
    assertTrue(rootDSE.supportsFeature("1.2.3.6"));
    assertFalse(rootDSE.supportsFeature("1.2.3.3"));

    assertNotNull(rootDSE.getSupportedLDAPVersions());
    assertEquals(rootDSE.getSupportedLDAPVersions().length, 1);
    assertEquals(rootDSE.getSupportedLDAPVersions()[0], 3);
    assertTrue(rootDSE.supportsLDAPVersion(3));
    assertFalse(rootDSE.supportsLDAPVersion(2));

    assertNotNull(rootDSE.getSupportedSASLMechanismNames());
    assertEquals(rootDSE.getSupportedSASLMechanismNames().length, 5);
    assertTrue(rootDSE.supportsSASLMechanism("EXTERNAL"));
    assertFalse(rootDSE.supportsSASLMechanism("GSSAPI"));

    assertNotNull(rootDSE.getVendorName());
    assertEquals(rootDSE.getVendorName(), "Ping Identity Corporation");

    assertNotNull(rootDSE.getVendorVersion());
    assertEquals(rootDSE.getVendorVersion(),
                 "UnboundID Directory Server 1.2.3");
  }



  /**
   * Tests the ability to get the server root DSE and invoke methods on it.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetRootDSE()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection connection = getAdminConnection();
    RootDSE rootDSE = connection.getRootDSE();
    connection.close();

    assertNotNull(rootDSE);

    rootDSE.getAltServerURIs();
    rootDSE.getChangelogDN();
    rootDSE.getFirstChangeNumber();
    rootDSE.getLastChangeNumber();
    rootDSE.getLastPurgedChangeNumber();
    rootDSE.getNamingContextDNs();
    rootDSE.getSubschemaSubentryDN();
    rootDSE.getVendorName();
    rootDSE.getVendorVersion();

    String[] authPWSchemes = rootDSE.getSupportedAuthPasswordSchemeNames();
    if (authPWSchemes != null)
    {
      for (String schemeName : authPWSchemes)
      {
        assertTrue(rootDSE.supportsAuthPasswordScheme(schemeName));
      }
    }
    assertFalse(rootDSE.supportsAuthPasswordScheme("foo"));

    String[] controlOIDs = rootDSE.getSupportedControlOIDs();
    if (controlOIDs != null)
    {
      for (String oid : controlOIDs)
      {
        assertTrue(rootDSE.supportsControl(oid));
      }
    }
    assertFalse(rootDSE.supportsControl("1.2.3.4"));

    String[] extopOIDs = rootDSE.getSupportedExtendedOperationOIDs();
    if (extopOIDs != null)
    {
      for (String oid : extopOIDs)
      {
        assertTrue(rootDSE.supportsExtendedOperation(oid));
      }
    }
    assertFalse(rootDSE.supportsExtendedOperation("1.2.3.4"));

    String[] featureOIDs = rootDSE.getSupportedFeatureOIDs();
    if (featureOIDs != null)
    {
      for (String oid : featureOIDs)
      {
        assertTrue(rootDSE.supportsFeature(oid));
      }
    }
    assertFalse(rootDSE.supportsFeature("1.2.3.4"));

    int[] ldapVersions = rootDSE.getSupportedLDAPVersions();
    if (ldapVersions != null)
    {
      for (int ldapVersion : ldapVersions)
      {
        assertTrue(rootDSE.supportsLDAPVersion(ldapVersion));
      }
    }
    assertFalse(rootDSE.supportsLDAPVersion(0));

    String[] saslMechanisms = rootDSE.getSupportedSASLMechanismNames();
    if (saslMechanisms != null)
    {
      for (String mech : saslMechanisms)
      {
        assertTrue(rootDSE.supportsSASLMechanism(mech));
      }
    }
    assertFalse(rootDSE.supportsSASLMechanism("foo"));
  }
}
