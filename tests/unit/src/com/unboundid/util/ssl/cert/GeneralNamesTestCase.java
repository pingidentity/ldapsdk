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
 * This class provides a set of test cases for the GeneralNames class.
 */
public final class GeneralNamesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with an empty set of names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyNames()
         throws Exception
  {
    GeneralNames names = new GeneralNamesBuilder().build();

    names = new GeneralNames(names.encode());

    assertNotNull(names.getOtherNames());
    assertTrue(names.getOtherNames().isEmpty());

    assertNotNull(names.getRFC822Names());
    assertTrue(names.getRFC822Names().isEmpty());

    assertNotNull(names.getDNSNames());
    assertTrue(names.getDNSNames().isEmpty());

    assertNotNull(names.getX400Addresses());
    assertTrue(names.getX400Addresses().isEmpty());

    assertNotNull(names.getDirectoryNames());
    assertTrue(names.getDirectoryNames().isEmpty());

    assertNotNull(names.getEDIPartyNames());
    assertTrue(names.getEDIPartyNames().isEmpty());

    assertNotNull(names.getUniformResourceIdentifiers());
    assertTrue(names.getUniformResourceIdentifiers().isEmpty());

    assertNotNull(names.getIPAddresses());
    assertTrue(names.getIPAddresses().isEmpty());

    assertNotNull(names.getRegisteredIDs());
    assertTrue(names.getRegisteredIDs().isEmpty());

    assertNotNull(names.toString());
  }



  /**
   * Tests the behavior with multiple values for all names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleValuesForAllNames()
         throws Exception
  {
    GeneralNames names = new GeneralNamesBuilder().
         addOtherName(new OID("1.2.3.4"), new ASN1OctetString("otherName1")).
         addOtherName(new OID("1.2.3.5"), new ASN1OctetString("otherName2")).
         addRFC822Name("user1@example.com").
         addRFC822Name("user2@example.com").
         addDNSName("ldap1.example.com").
         addDNSName("ldap2.example.com").
         addX400Address(new ASN1OctetString("x.400Address1")).
         addX400Address(new ASN1OctetString("x.400Address2")).
         addDirectoryName(new DN("dc=example,dc=com")).
         addDirectoryName(new DN("o=example.com")).
         addEDIPartyName(new ASN1OctetString("ediPartyName1")).
         addEDIPartyName(new ASN1OctetString("ediPartyName2")).
         addUniformResourceIdentifier("ldap://ds1.example.com:389/").
         addUniformResourceIdentifier("ldap://ds2.example.com:389/").
         addIPAddress(InetAddress.getByName("127.0.0.1")).
         addIPAddress(InetAddress.getByName("::1")).
         addRegisteredID(new OID("1.2.3.6")).
         addRegisteredID(new OID("1.2.3.7")).
         build();

    names = new GeneralNames(names.encode());

    assertNotNull(names.getOtherNames());
    assertFalse(names.getOtherNames().isEmpty());
    assertEquals(names.getOtherNames().size(), 2);
    assertEquals(names.getOtherNames().get(0).getFirst(), new OID("1.2.3.4"));
    assertEquals(names.getOtherNames().get(0).getSecond(),
         new ASN1OctetString("otherName1"));
    assertEquals(names.getOtherNames().get(1).getFirst(), new OID("1.2.3.5"));
    assertEquals(names.getOtherNames().get(1).getSecond(),
         new ASN1OctetString("otherName2"));

    assertNotNull(names.getRFC822Names());
    assertFalse(names.getRFC822Names().isEmpty());
    assertEquals(names.getRFC822Names().size(), 2);
    assertEquals(names.getRFC822Names().get(0), "user1@example.com");
    assertEquals(names.getRFC822Names().get(1), "user2@example.com");

    assertNotNull(names.getDNSNames());
    assertFalse(names.getDNSNames().isEmpty());
    assertEquals(names.getDNSNames().size(), 2);
    assertEquals(names.getDNSNames().get(0), "ldap1.example.com");
    assertEquals(names.getDNSNames().get(1), "ldap2.example.com");

    assertNotNull(names.getX400Addresses());
    assertFalse(names.getX400Addresses().isEmpty());
    assertEquals(names.getX400Addresses().size(), 2);
    assertEquals(
         names.getX400Addresses().get(0).decodeAsOctetString().stringValue(),
         "x.400Address1");
    assertEquals(
         names.getX400Addresses().get(1).decodeAsOctetString().stringValue(),
         "x.400Address2");

    assertNotNull(names.getDirectoryNames());
    assertFalse(names.getDirectoryNames().isEmpty());
    assertEquals(names.getDirectoryNames().size(), 2);
    assertEquals(names.getDirectoryNames().get(0), new DN("dc=example,dc=com"));
    assertEquals(names.getDirectoryNames().get(1), new DN("o=example.com"));

    assertNotNull(names.getEDIPartyNames());
    assertFalse(names.getEDIPartyNames().isEmpty());
    assertEquals(names.getEDIPartyNames().size(), 2);
    assertEquals(
         names.getEDIPartyNames().get(0).decodeAsOctetString().stringValue(),
         "ediPartyName1");
    assertEquals(
         names.getEDIPartyNames().get(1).decodeAsOctetString().stringValue(),
         "ediPartyName2");

    assertNotNull(names.getUniformResourceIdentifiers());
    assertFalse(names.getUniformResourceIdentifiers().isEmpty());
    assertEquals(names.getUniformResourceIdentifiers().size(), 2);
    assertEquals(names.getUniformResourceIdentifiers().get(0),
         "ldap://ds1.example.com:389/");
    assertEquals(names.getUniformResourceIdentifiers().get(1),
         "ldap://ds2.example.com:389/");

    assertNotNull(names.getIPAddresses());
    assertFalse(names.getIPAddresses().isEmpty());
    assertEquals(names.getIPAddresses().size(), 2);
    assertEquals(names.getIPAddresses().get(0),
         InetAddress.getByName("127.0.0.1"));
    assertEquals(names.getIPAddresses().get(1),
         InetAddress.getByName("::1"));

    assertNotNull(names.getRegisteredIDs());
    assertFalse(names.getRegisteredIDs().isEmpty());
    assertEquals(names.getRegisteredIDs().size(), 2);
    assertEquals(names.getRegisteredIDs().get(0),
         new OID("1.2.3.6"));
    assertEquals(names.getRegisteredIDs().get(1),
         new OID("1.2.3.7"));

    assertNotNull(names.toString());
  }



  /**
   * Tests the behavior when trying to encode a general names element that
   * contains non-ASCII characters in an IA5String element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testEncodeInvalidIA5Value()
         throws Exception
  {
    new GeneralNamesBuilder().addDNSName("jalape\u00f1o").build().encode();
  }



  /**
   * Tests the behavior when trying to encode a general names element that
   * contains a malformed OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testEncodeInvalidOIDValue()
         throws Exception
  {
    // The first component of an OID must be between 0 and 2.
    new GeneralNamesBuilder().addRegisteredID(new OID("1234.5678")).build().
         encode();
  }



  /**
   * Tests the behavior when trying to decode an ASN.1 element that is not a
   * valid sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeElementNotSequence()
         throws Exception
  {
    new GeneralNames(new ASN1OctetString("not a valid sequence"));
  }
}
