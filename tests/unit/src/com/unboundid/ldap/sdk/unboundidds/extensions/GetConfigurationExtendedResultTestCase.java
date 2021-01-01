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



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the get configuration extended
 * result.
 */
public final class GetConfigurationExtendedResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * The bytes that comprise a test configuration.
   */
  private static final byte[] TEST_CONFIG_FILE_BYTES =
       ("dn: cn=config" + StaticUtils.EOL +
        "objectClass: top" + StaticUtils.EOL +
        "objectClass: ds-cfg-root-config" + StaticUtils.EOL +
        "cn=config" + StaticUtils.EOL + StaticUtils.EOL).getBytes();



  /**
   * Tests the behavior when trying to create a success result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessfulResult()
         throws Exception
  {
    GetConfigurationExtendedResult r = new GetConfigurationExtendedResult(123,
         ResultCode.SUCCESS, null, null, null, GetConfigurationType.ACTIVE,
         "config.ldif", TEST_CONFIG_FILE_BYTES);

    r = new GetConfigurationExtendedResult(r);
    assertNotNull(r);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.29");

    assertNotNull(r.getValue());

    assertNotNull(r.getConfigurationType());
    assertEquals(r.getConfigurationType(), GetConfigurationType.ACTIVE);

    assertNotNull(r.getFileName());
    assertEquals(r.getFileName(), "config.ldif");

    assertNotNull(r.getFileData());
    assertEquals(r.getFileData(), TEST_CONFIG_FILE_BYTES);

    assertNotNull(r.getFileDataInputStream());

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to create a failure result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailureResult()
         throws Exception
  {
    final String[] referralURLs =
    {
      "ldap://ds1.example.com/dc=example,dc=com",
      "ldap://ds2.example.com/dc=example,dc=com"
    };

    GetConfigurationExtendedResult r = new GetConfigurationExtendedResult(123,
         ResultCode.UNWILLING_TO_PERFORM, "diagnostic message",
         "dc=matched,dc=dn", referralURLs, null, null, null,
         new Control("1.2.3.4"), new Control("1.2.3.5"));

    r = new GetConfigurationExtendedResult(r);
    assertNotNull(r);

    assertNull(r.getOID());

    assertNull(r.getValue());

    assertNull(r.getConfigurationType());

    assertNull(r.getFileName());

    assertNull(r.getFileData());

    assertNull(r.getFileDataInputStream());

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to decode a result whose value is not a
   * valid ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new GetConfigurationExtendedResult(new ExtendedResult(123,
         ResultCode.SUCCESS, null, null, null, "1.3.6.1.4.1.30221.2.6.29",
         new ASN1OctetString("foo"), null));
  }



  /**
   * Tests the behavior when trying to decode a result whose value sequence
   * recognizes an unexpected configuration type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidConfigType()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Enumerated((byte) 0x80, 123),
         new ASN1OctetString((byte) 0x81, "config.ldif"),
         new ASN1OctetString((byte) 0x82, TEST_CONFIG_FILE_BYTES));

    new GetConfigurationExtendedResult(new ExtendedResult(123,
         ResultCode.SUCCESS, null, null, null, "1.3.6.1.4.1.30221.2.6.29",
         new ASN1OctetString(valueSequence.encode()), null));
  }
}
