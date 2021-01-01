/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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



import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the list configurations extended
 * result.
 */
public final class ListConfigurationsExtendedResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a list configurations result without any controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithoutControls()
         throws Exception
  {
    ListConfigurationsExtendedResult r =
         new ListConfigurationsExtendedResult(123, ResultCode.SUCCESS, null,
              null, null, "config.ldif",
              Arrays.asList("config.ldif.1234", "config.ldif.5678"),
              Arrays.asList("config-20130101000000Z", "config-20130102000000Z",
                   "config-20130103000000Z", "config-20130104000000Z"));

    r = new ListConfigurationsExtendedResult(r);
    assertNotNull(r);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.27");

    assertNotNull(r.getValue());

    assertNotNull(r.getActiveFileName());
    assertEquals(r.getActiveFileName(), "config.ldif");

    assertNotNull(r.getBaselineFileNames());
    assertEquals(r.getBaselineFileNames().size(), 2);
    assertTrue(r.getBaselineFileNames().contains("config.ldif.1234"));
    assertTrue(r.getBaselineFileNames().contains("config.ldif.5678"));

    assertNotNull(r.getArchivedFileNames());
    assertEquals(r.getArchivedFileNames().size(), 4);
    assertTrue(r.getArchivedFileNames().contains("config-20130101000000Z"));
    assertTrue(r.getArchivedFileNames().contains("config-20130102000000Z"));
    assertTrue(r.getArchivedFileNames().contains("config-20130103000000Z"));
    assertTrue(r.getArchivedFileNames().contains("config-20130104000000Z"));

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests a list configurations result with controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithControls()
         throws Exception
  {
    final String[] referralURLs =
    {
      "ldap://ds1.example.com/dc=example,dc=com",
      "ldap://ds2.example.com/dc=example,dc=com"
    };

    ListConfigurationsExtendedResult r =
         new ListConfigurationsExtendedResult(123, ResultCode.SUCCESS,
              "diagnostic message", "dc=matched,dc=dn", referralURLs,
              "config.ldif",
              Arrays.asList("config.ldif.1234", "config.ldif.5678"),
              Arrays.asList("config-20130101000000Z", "config-20130102000000Z",
                   "config-20130103000000Z", "config-20130104000000Z"),
              new Control("1.2.3.4"), new Control("1.2.3.5"));

    r = new ListConfigurationsExtendedResult(r);
    assertNotNull(r);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.27");

    assertNotNull(r.getValue());

    assertNotNull(r.getActiveFileName());
    assertEquals(r.getActiveFileName(), "config.ldif");

    assertNotNull(r.getBaselineFileNames());
    assertEquals(r.getBaselineFileNames().size(), 2);
    assertTrue(r.getBaselineFileNames().contains("config.ldif.1234"));
    assertTrue(r.getBaselineFileNames().contains("config.ldif.5678"));

    assertNotNull(r.getArchivedFileNames());
    assertEquals(r.getArchivedFileNames().size(), 4);
    assertTrue(r.getArchivedFileNames().contains("config-20130101000000Z"));
    assertTrue(r.getArchivedFileNames().contains("config-20130102000000Z"));
    assertTrue(r.getArchivedFileNames().contains("config-20130103000000Z"));
    assertTrue(r.getArchivedFileNames().contains("config-20130104000000Z"));

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 2);

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when creating an error result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateErrorResult()
         throws Exception
  {
    ListConfigurationsExtendedResult r =
         new ListConfigurationsExtendedResult(123,
              ResultCode.UNWILLING_TO_PERFORM, "Not supported", null, null,
              null, null, null);

    r = new ListConfigurationsExtendedResult(r);
    assertNotNull(r);

    assertNull(r.getOID());

    assertNull(r.getValue());

    assertNull(r.getActiveFileName());

    assertNotNull(r.getBaselineFileNames());
    assertTrue(r.getBaselineFileNames().isEmpty());

    assertNotNull(r.getArchivedFileNames());
    assertTrue(r.getArchivedFileNames().isEmpty());

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to decode a generic extended result whose
   * value is not an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new ListConfigurationsExtendedResult(new ExtendedResult(123,
         ResultCode.SUCCESS, null, null, null, "1.3.6.1.4.1.30221.2.6.27",
         new ASN1OctetString("foo"), null));
  }



  /**
   * Tests the behavior when trying to decode a generic extended result whose
   * value sequence contains an element with an invalid configuration type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueInvalidConfigType()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "config.ldif"),
         new ASN1OctetString((byte) 0x85, "invalid"));

    new ListConfigurationsExtendedResult(new ExtendedResult(123,
         ResultCode.SUCCESS, null, null, null, "1.3.6.1.4.1.30221.2.6.27",
         new ASN1OctetString(valueSequence.encode()), null));
  }



  /**
   * Tests the behavior when trying to decode a generic extended result whose
   * value sequence does not include the active config file name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueMissingActiveFileName()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x81, "config.ldif.1234"));

    new ListConfigurationsExtendedResult(new ExtendedResult(123,
         ResultCode.SUCCESS, null, null, null, "1.3.6.1.4.1.30221.2.6.27",
         new ASN1OctetString(valueSequence.encode()), null));
  }
}
