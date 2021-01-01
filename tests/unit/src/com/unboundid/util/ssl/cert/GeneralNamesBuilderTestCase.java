/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
package com.unboundid.util.ssl.cert;



import java.net.InetAddress;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.OID;



/**
 * This class provides a set of test cases for the GeneralNamesBuilder class.
 */
public final class GeneralNamesBuilderTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests an empty builder instance.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyBuilder()
         throws Exception
  {
    final GeneralNamesBuilder builder = new GeneralNamesBuilder();

    assertNotNull(builder.getOtherNames());
    assertTrue(builder.getOtherNames().isEmpty());

    assertNotNull(builder.getRFC822Names());
    assertTrue(builder.getRFC822Names().isEmpty());

    assertNotNull(builder.getDNSNames());
    assertTrue(builder.getDNSNames().isEmpty());

    assertNotNull(builder.getX400Addresses());
    assertTrue(builder.getX400Addresses().isEmpty());

    assertNotNull(builder.getDirectoryNames());
    assertTrue(builder.getDirectoryNames().isEmpty());

    assertNotNull(builder.getEDIPartyNames());
    assertTrue(builder.getEDIPartyNames().isEmpty());

    assertNotNull(builder.getUniformResourceIdentifiers());
    assertTrue(builder.getUniformResourceIdentifiers().isEmpty());

    assertNotNull(builder.getIPAddresses());
    assertTrue(builder.getIPAddresses().isEmpty());

    assertNotNull(builder.getRegisteredIDs());
    assertTrue(builder.getRegisteredIDs().isEmpty());

    assertNotNull(builder.build().toString());
  }



  /**
   * Tests adding a value to the set of other names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddOtherName()
         throws Exception
  {
    final GeneralNamesBuilder builder = new GeneralNamesBuilder();

    assertNotNull(builder.getOtherNames());
    assertTrue(builder.getOtherNames().isEmpty());

    builder.addOtherName(new OID("1.2.3.4"), new ASN1OctetString("foo"));

    assertNotNull(builder.getOtherNames());
    assertFalse(builder.getOtherNames().isEmpty());
    assertEquals(builder.getOtherNames().size(), 1);
    assertEquals(builder.getOtherNames().get(0).getFirst(), new OID("1.2.3.4"));
    assertEquals(builder.getOtherNames().get(0).getSecond(),
         new ASN1OctetString("foo"));

    assertNotNull(builder.getRFC822Names());
    assertTrue(builder.getRFC822Names().isEmpty());

    assertNotNull(builder.getDNSNames());
    assertTrue(builder.getDNSNames().isEmpty());

    assertNotNull(builder.getX400Addresses());
    assertTrue(builder.getX400Addresses().isEmpty());

    assertNotNull(builder.getDirectoryNames());
    assertTrue(builder.getDirectoryNames().isEmpty());

    assertNotNull(builder.getEDIPartyNames());
    assertTrue(builder.getEDIPartyNames().isEmpty());

    assertNotNull(builder.getUniformResourceIdentifiers());
    assertTrue(builder.getUniformResourceIdentifiers().isEmpty());

    assertNotNull(builder.getIPAddresses());
    assertTrue(builder.getIPAddresses().isEmpty());

    assertNotNull(builder.getRegisteredIDs());
    assertTrue(builder.getRegisteredIDs().isEmpty());

    assertNotNull(builder.build().toString());
  }



  /**
   * Tests adding a value to the set of RFC 822 names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddRFC822Name()
         throws Exception
  {
    final GeneralNamesBuilder builder = new GeneralNamesBuilder();

    assertNotNull(builder.getRFC822Names());
    assertTrue(builder.getRFC822Names().isEmpty());

    builder.addRFC822Name("user@example.com");

    assertNotNull(builder.getRFC822Names());
    assertFalse(builder.getRFC822Names().isEmpty());
    assertEquals(builder.getRFC822Names().size(), 1);
    assertEquals(builder.getRFC822Names().get(0), "user@example.com");

    assertNotNull(builder.getOtherNames());
    assertTrue(builder.getOtherNames().isEmpty());

    assertNotNull(builder.getDNSNames());
    assertTrue(builder.getDNSNames().isEmpty());

    assertNotNull(builder.getX400Addresses());
    assertTrue(builder.getX400Addresses().isEmpty());

    assertNotNull(builder.getDirectoryNames());
    assertTrue(builder.getDirectoryNames().isEmpty());

    assertNotNull(builder.getEDIPartyNames());
    assertTrue(builder.getEDIPartyNames().isEmpty());

    assertNotNull(builder.getUniformResourceIdentifiers());
    assertTrue(builder.getUniformResourceIdentifiers().isEmpty());

    assertNotNull(builder.getIPAddresses());
    assertTrue(builder.getIPAddresses().isEmpty());

    assertNotNull(builder.getRegisteredIDs());
    assertTrue(builder.getRegisteredIDs().isEmpty());

    assertNotNull(builder.build().toString());
  }



  /**
   * Tests adding a value to the set of DNS names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddDNSName()
         throws Exception
  {
    final GeneralNamesBuilder builder = new GeneralNamesBuilder();

    assertNotNull(builder.getDNSNames());
    assertTrue(builder.getDNSNames().isEmpty());

    builder.addDNSName("ldap.example.com");

    assertNotNull(builder.getDNSNames());
    assertFalse(builder.getDNSNames().isEmpty());
    assertEquals(builder.getDNSNames().size(), 1);
    assertEquals(builder.getDNSNames().get(0), "ldap.example.com");

    assertNotNull(builder.getOtherNames());
    assertTrue(builder.getOtherNames().isEmpty());

    assertNotNull(builder.getRFC822Names());
    assertTrue(builder.getRFC822Names().isEmpty());

    assertNotNull(builder.getX400Addresses());
    assertTrue(builder.getX400Addresses().isEmpty());

    assertNotNull(builder.getDirectoryNames());
    assertTrue(builder.getDirectoryNames().isEmpty());

    assertNotNull(builder.getEDIPartyNames());
    assertTrue(builder.getEDIPartyNames().isEmpty());

    assertNotNull(builder.getUniformResourceIdentifiers());
    assertTrue(builder.getUniformResourceIdentifiers().isEmpty());

    assertNotNull(builder.getIPAddresses());
    assertTrue(builder.getIPAddresses().isEmpty());

    assertNotNull(builder.getRegisteredIDs());
    assertTrue(builder.getRegisteredIDs().isEmpty());

    assertNotNull(builder.build().toString());
  }



  /**
   * Tests adding a value to the set of X.400 addresses.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddX400Address()
         throws Exception
  {
    final GeneralNamesBuilder builder = new GeneralNamesBuilder();

    assertNotNull(builder.getX400Addresses());
    assertTrue(builder.getX400Addresses().isEmpty());

    builder.addX400Address(new ASN1OctetString("foo"));

    assertNotNull(builder.getX400Addresses());
    assertFalse(builder.getX400Addresses().isEmpty());
    assertEquals(builder.getX400Addresses().size(), 1);
    assertEquals(builder.getX400Addresses().get(0), new ASN1OctetString("foo"));

    assertNotNull(builder.getOtherNames());
    assertTrue(builder.getOtherNames().isEmpty());

    assertNotNull(builder.getRFC822Names());
    assertTrue(builder.getRFC822Names().isEmpty());

    assertNotNull(builder.getDNSNames());
    assertTrue(builder.getDNSNames().isEmpty());

    assertNotNull(builder.getDirectoryNames());
    assertTrue(builder.getDirectoryNames().isEmpty());

    assertNotNull(builder.getEDIPartyNames());
    assertTrue(builder.getEDIPartyNames().isEmpty());

    assertNotNull(builder.getUniformResourceIdentifiers());
    assertTrue(builder.getUniformResourceIdentifiers().isEmpty());

    assertNotNull(builder.getIPAddresses());
    assertTrue(builder.getIPAddresses().isEmpty());

    assertNotNull(builder.getRegisteredIDs());
    assertTrue(builder.getRegisteredIDs().isEmpty());

    assertNotNull(builder.build().toString());
  }



  /**
   * Tests adding a value to the set of directory names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddDirectoryName()
         throws Exception
  {
    final GeneralNamesBuilder builder = new GeneralNamesBuilder();

    assertNotNull(builder.getDirectoryNames());
    assertTrue(builder.getDirectoryNames().isEmpty());

    builder.addDirectoryName(new DN("dc=example,dc=com"));

    assertNotNull(builder.getDirectoryNames());
    assertFalse(builder.getDirectoryNames().isEmpty());
    assertEquals(builder.getDirectoryNames().size(), 1);
    assertEquals(builder.getDirectoryNames().get(0),
         new DN("dc=example,dc=com"));

    assertNotNull(builder.getOtherNames());
    assertTrue(builder.getOtherNames().isEmpty());

    assertNotNull(builder.getRFC822Names());
    assertTrue(builder.getRFC822Names().isEmpty());

    assertNotNull(builder.getDNSNames());
    assertTrue(builder.getDNSNames().isEmpty());

    assertNotNull(builder.getX400Addresses());
    assertTrue(builder.getX400Addresses().isEmpty());

    assertNotNull(builder.getEDIPartyNames());
    assertTrue(builder.getEDIPartyNames().isEmpty());

    assertNotNull(builder.getUniformResourceIdentifiers());
    assertTrue(builder.getUniformResourceIdentifiers().isEmpty());

    assertNotNull(builder.getIPAddresses());
    assertTrue(builder.getIPAddresses().isEmpty());

    assertNotNull(builder.getRegisteredIDs());
    assertTrue(builder.getRegisteredIDs().isEmpty());

    assertNotNull(builder.build().toString());
  }



  /**
   * Tests adding a value to the set of EDI party names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddEDIPartyName()
         throws Exception
  {
    final GeneralNamesBuilder builder = new GeneralNamesBuilder();

    assertNotNull(builder.getEDIPartyNames());
    assertTrue(builder.getEDIPartyNames().isEmpty());

    builder.addEDIPartyName(new ASN1OctetString("foo"));

    assertNotNull(builder.getEDIPartyNames());
    assertFalse(builder.getEDIPartyNames().isEmpty());
    assertEquals(builder.getEDIPartyNames().size(), 1);
    assertEquals(builder.getEDIPartyNames().get(0), new ASN1OctetString("foo"));

    assertNotNull(builder.getOtherNames());
    assertTrue(builder.getOtherNames().isEmpty());

    assertNotNull(builder.getRFC822Names());
    assertTrue(builder.getRFC822Names().isEmpty());

    assertNotNull(builder.getDNSNames());
    assertTrue(builder.getDNSNames().isEmpty());

    assertNotNull(builder.getX400Addresses());
    assertTrue(builder.getX400Addresses().isEmpty());

    assertNotNull(builder.getDirectoryNames());
    assertTrue(builder.getDirectoryNames().isEmpty());

    assertNotNull(builder.getUniformResourceIdentifiers());
    assertTrue(builder.getUniformResourceIdentifiers().isEmpty());

    assertNotNull(builder.getIPAddresses());
    assertTrue(builder.getIPAddresses().isEmpty());

    assertNotNull(builder.getRegisteredIDs());
    assertTrue(builder.getRegisteredIDs().isEmpty());

    assertNotNull(builder.build().toString());
  }



  /**
   * Tests adding a value to the set of uniform resource identifiers.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddUniformResourceIdentifier()
         throws Exception
  {
    final GeneralNamesBuilder builder = new GeneralNamesBuilder();

    assertNotNull(builder.getUniformResourceIdentifiers());
    assertTrue(builder.getUniformResourceIdentifiers().isEmpty());

    builder.addUniformResourceIdentifier("ldap:///dc=example,dc=com");

    assertNotNull(builder.getUniformResourceIdentifiers());
    assertFalse(builder.getUniformResourceIdentifiers().isEmpty());
    assertEquals(builder.getUniformResourceIdentifiers().size(), 1);
    assertEquals(builder.getUniformResourceIdentifiers().get(0),
         "ldap:///dc=example,dc=com");

    assertNotNull(builder.getOtherNames());
    assertTrue(builder.getOtherNames().isEmpty());

    assertNotNull(builder.getRFC822Names());
    assertTrue(builder.getRFC822Names().isEmpty());

    assertNotNull(builder.getDNSNames());
    assertTrue(builder.getDNSNames().isEmpty());

    assertNotNull(builder.getX400Addresses());
    assertTrue(builder.getX400Addresses().isEmpty());

    assertNotNull(builder.getDirectoryNames());
    assertTrue(builder.getDirectoryNames().isEmpty());

    assertNotNull(builder.getEDIPartyNames());
    assertTrue(builder.getEDIPartyNames().isEmpty());

    assertNotNull(builder.getIPAddresses());
    assertTrue(builder.getIPAddresses().isEmpty());

    assertNotNull(builder.getRegisteredIDs());
    assertTrue(builder.getRegisteredIDs().isEmpty());

    assertNotNull(builder.build().toString());
  }



  /**
   * Tests adding a value to the set of IP addresses.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddIPAddress()
         throws Exception
  {
    final GeneralNamesBuilder builder = new GeneralNamesBuilder();

    assertNotNull(builder.getIPAddresses());
    assertTrue(builder.getIPAddresses().isEmpty());

    builder.addIPAddress(InetAddress.getByName("127.0.0.1"));

    assertNotNull(builder.getIPAddresses());
    assertFalse(builder.getIPAddresses().isEmpty());
    assertEquals(builder.getIPAddresses().size(), 1);
    assertEquals(builder.getIPAddresses().get(0).getHostAddress(), "127.0.0.1");

    assertNotNull(builder.getOtherNames());
    assertTrue(builder.getOtherNames().isEmpty());

    assertNotNull(builder.getRFC822Names());
    assertTrue(builder.getRFC822Names().isEmpty());

    assertNotNull(builder.getDNSNames());
    assertTrue(builder.getDNSNames().isEmpty());

    assertNotNull(builder.getX400Addresses());
    assertTrue(builder.getX400Addresses().isEmpty());

    assertNotNull(builder.getDirectoryNames());
    assertTrue(builder.getDirectoryNames().isEmpty());

    assertNotNull(builder.getEDIPartyNames());
    assertTrue(builder.getEDIPartyNames().isEmpty());

    assertNotNull(builder.getUniformResourceIdentifiers());
    assertTrue(builder.getUniformResourceIdentifiers().isEmpty());

    assertNotNull(builder.getRegisteredIDs());
    assertTrue(builder.getRegisteredIDs().isEmpty());

    assertNotNull(builder.build().toString());
  }



  /**
   * Tests adding a value to the set of registered IDs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddRegisteredID()
         throws Exception
  {
    final GeneralNamesBuilder builder = new GeneralNamesBuilder();

    assertNotNull(builder.getRegisteredIDs());
    assertTrue(builder.getRegisteredIDs().isEmpty());

    builder.addRegisteredID(new OID("1.2.3.4"));

    assertNotNull(builder.getRegisteredIDs());
    assertFalse(builder.getRegisteredIDs().isEmpty());
    assertEquals(builder.getRegisteredIDs().size(), 1);
    assertEquals(builder.getRegisteredIDs().get(0), new OID("1.2.3.4"));

    assertNotNull(builder.getOtherNames());
    assertTrue(builder.getOtherNames().isEmpty());

    assertNotNull(builder.getRFC822Names());
    assertTrue(builder.getRFC822Names().isEmpty());

    assertNotNull(builder.getDNSNames());
    assertTrue(builder.getDNSNames().isEmpty());

    assertNotNull(builder.getX400Addresses());
    assertTrue(builder.getX400Addresses().isEmpty());

    assertNotNull(builder.getDirectoryNames());
    assertTrue(builder.getDirectoryNames().isEmpty());

    assertNotNull(builder.getEDIPartyNames());
    assertTrue(builder.getEDIPartyNames().isEmpty());

    assertNotNull(builder.getUniformResourceIdentifiers());
    assertTrue(builder.getUniformResourceIdentifiers().isEmpty());

    assertNotNull(builder.getIPAddresses());
    assertTrue(builder.getIPAddresses().isEmpty());

    assertNotNull(builder.build().toString());
  }



  /**
   * Tests using a builder to create values of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBuilderWithEverything()
         throws Exception
  {
    final GeneralNamesBuilder builder = new GeneralNamesBuilder().
         addOtherName(new OID("1.2.3.4"), new ASN1OctetString("1")).
         addRFC822Name("user@example.com").addDNSName("ldap.example.com").
         addX400Address(new ASN1OctetString("2")).
         addDirectoryName(new DN("dc=example,dc=com")).
         addEDIPartyName(new ASN1OctetString("3")).
         addUniformResourceIdentifier("ldap:///dc=example,dc=com").
         addIPAddress(InetAddress.getByName("127.0.0.1")).
         addRegisteredID(new OID("1.2.3.5"));

    assertNotNull(builder.getOtherNames());
    assertFalse(builder.getOtherNames().isEmpty());
    assertEquals(builder.getOtherNames().size(), 1);
    assertEquals(builder.getOtherNames().get(0).getFirst(), new OID("1.2.3.4"));
    assertEquals(builder.getOtherNames().get(0).getSecond(),
         new ASN1OctetString("1"));

    assertNotNull(builder.getRFC822Names());
    assertFalse(builder.getRFC822Names().isEmpty());
    assertEquals(builder.getRFC822Names().size(), 1);
    assertEquals(builder.getRFC822Names().get(0), "user@example.com");

    assertNotNull(builder.getDNSNames());
    assertFalse(builder.getDNSNames().isEmpty());
    assertEquals(builder.getDNSNames().size(), 1);
    assertEquals(builder.getDNSNames().get(0), "ldap.example.com");

    assertNotNull(builder.getX400Addresses());
    assertFalse(builder.getX400Addresses().isEmpty());
    assertEquals(builder.getX400Addresses().size(), 1);
    assertEquals(builder.getX400Addresses().get(0), new ASN1OctetString("2"));

    assertNotNull(builder.getDirectoryNames());
    assertFalse(builder.getDirectoryNames().isEmpty());
    assertEquals(builder.getDirectoryNames().size(), 1);
    assertEquals(builder.getDirectoryNames().get(0),
         new DN("dc=example,dc=com"));

    assertNotNull(builder.getEDIPartyNames());
    assertFalse(builder.getEDIPartyNames().isEmpty());
    assertEquals(builder.getEDIPartyNames().size(), 1);
    assertEquals(builder.getEDIPartyNames().get(0), new ASN1OctetString("3"));

    assertNotNull(builder.getUniformResourceIdentifiers());
    assertFalse(builder.getUniformResourceIdentifiers().isEmpty());
    assertEquals(builder.getUniformResourceIdentifiers().size(), 1);
    assertEquals(builder.getUniformResourceIdentifiers().get(0),
         "ldap:///dc=example,dc=com");

    assertNotNull(builder.getIPAddresses());
    assertFalse(builder.getIPAddresses().isEmpty());
    assertEquals(builder.getIPAddresses().size(), 1);
    assertEquals(builder.getIPAddresses().get(0).getHostAddress(), "127.0.0.1");

    assertNotNull(builder.getRegisteredIDs());
    assertFalse(builder.getRegisteredIDs().isEmpty());
    assertEquals(builder.getRegisteredIDs().size(), 1);
    assertEquals(builder.getRegisteredIDs().get(0), new OID("1.2.3.5"));

    assertNotNull(builder.build().toString());
  }
}
