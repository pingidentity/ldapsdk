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



import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.IntermediateResponse;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.unboundidds.tasks.CollectSupportDataSecurityLevel;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the collect support data extended
 * request.
 */
public final class CollectSupportDataExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a version of the extended request with a default set of properties
   * and no controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequestWithDefaultSettings()
         throws Exception
  {
    final TestCollectSupportDataIntermediateResponseListener listener =
         new TestCollectSupportDataIntermediateResponseListener();

    CollectSupportDataExtendedRequest r = new CollectSupportDataExtendedRequest(
         new CollectSupportDataExtendedRequestProperties(), listener);

    r = new CollectSupportDataExtendedRequest(r, listener);

    r = new CollectSupportDataExtendedRequest(
         new CollectSupportDataExtendedRequestProperties(r), listener);

    r = r.duplicate();

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.64");

    assertNotNull(r.getValue());

    assertNotNull(r.getCollectSupportDataIntermediateResponseListener());
    assertTrue(r.getCollectSupportDataIntermediateResponseListener() instanceof
         TestCollectSupportDataIntermediateResponseListener);

    assertNull(r.getArchiveFileName());

    assertNull(r.getEncryptionPassphrase());

    assertNull(r.getIncludeExpensiveData());

    assertNull(r.getIncludeReplicationStateDump());

    assertNull(r.getIncludeBinaryFiles());

    assertNull(r.getIncludeExpensiveData());

    assertNull(r.getUseSequentialMode());

    assertNull(r.getSecurityLevel());

    assertNull(r.getJStackCount());

    assertNull(r.getReportCount());

    assertNull(r.getReportIntervalSeconds());

    assertNull(r.getLogCaptureWindow());

    assertNull(r.getComment());

    assertNull(r.getProxyToServerAddress());

    assertNull(r.getProxyToServerPort());

    assertNull(r.getMaximumFragmentSizeBytes());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertFalse(r.getExtendedRequestName().isEmpty());

    assertNotNull(r.toString());
  }



  /**
   * Tests a version of the extended request with a non-default set of
   * properties.  It will also include request controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequestWithNonDefaultSettings()
         throws Exception
  {
    final TestCollectSupportDataIntermediateResponseListener listener =
         new TestCollectSupportDataIntermediateResponseListener();

    final CollectSupportDataExtendedRequestProperties properties =
         new CollectSupportDataExtendedRequestProperties();
    properties.setArchiveFileName("csd.zip");
    properties.setEncryptionPassphrase("password");
    properties.setIncludeExpensiveData(true);
    properties.setIncludeReplicationStateDump(false);
    properties.setIncludeBinaryFiles(true);
    properties.setIncludeExtensionSource(false);
    properties.setUseSequentialMode(true);
    properties.setSecurityLevel(CollectSupportDataSecurityLevel.MAXIMUM);
    properties.setJStackCount(1);
    properties.setReportCount(2);
    properties.setReportIntervalSeconds(3);
    properties.setLogCaptureWindow(
         ToolDefaultCollectSupportDataLogCaptureWindow.getInstance());
    properties.setComment("comment");
    properties.setProxyToServer("ds.example.com", 636);
    properties.setMaximumFragmentSizeBytes(123_456);

    CollectSupportDataExtendedRequest r = new CollectSupportDataExtendedRequest(
         properties, listener, new Control("1.2.3.4"), new Control("1.2.3.5"));

    r = new CollectSupportDataExtendedRequest(
         new CollectSupportDataExtendedRequestProperties(r), listener,
         r.getControls());

    r = new CollectSupportDataExtendedRequest(r, listener);

    r = r.duplicate();

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.64");

    assertNotNull(r.getValue());

    assertNotNull(r.getCollectSupportDataIntermediateResponseListener());
    assertTrue(r.getCollectSupportDataIntermediateResponseListener() instanceof
         TestCollectSupportDataIntermediateResponseListener);

    assertNotNull(r.getArchiveFileName());
    assertEquals(r.getArchiveFileName(), "csd.zip");

    assertNotNull(r.getEncryptionPassphrase());
    assertEquals(r.getEncryptionPassphrase().stringValue(), "password");

    assertNotNull(r.getIncludeExpensiveData());
    assertTrue(r.getIncludeExpensiveData());

    assertNotNull(r.getIncludeReplicationStateDump());
    assertFalse(r.getIncludeReplicationStateDump());

    assertNotNull(r.getIncludeBinaryFiles());
    assertTrue(r.getIncludeBinaryFiles());

    assertNotNull(r.getIncludeExtensionSource());
    assertFalse(r.getIncludeExtensionSource());

    assertNotNull(r.getUseSequentialMode());
    assertTrue(r.getUseSequentialMode());

    assertNotNull(r.getSecurityLevel());
    assertEquals(r.getSecurityLevel(),
         CollectSupportDataSecurityLevel.MAXIMUM);

    assertNotNull(r.getJStackCount());
    assertEquals(r.getJStackCount().intValue(), 1);

    assertNotNull(r.getReportCount());
    assertEquals(r.getReportCount().intValue(), 2);

    assertNotNull(r.getReportIntervalSeconds());
    assertEquals(r.getReportIntervalSeconds().intValue(), 3);

    assertNotNull(r.getLogCaptureWindow());
    assertTrue(r.getLogCaptureWindow() instanceof
         ToolDefaultCollectSupportDataLogCaptureWindow);

    assertNotNull(r.getComment());
    assertEquals(r.getComment(), "comment");

    assertNotNull(r.getProxyToServerAddress());
    assertEquals(r.getProxyToServerAddress(), "ds.example.com");

    assertNotNull(r.getProxyToServerPort());
    assertEquals(r.getProxyToServerPort().intValue(), 636);

    assertNotNull(r.getMaximumFragmentSizeBytes());
    assertEquals(r.getMaximumFragmentSizeBytes().intValue(), 123_456);

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getExtendedRequestName());
    assertFalse(r.getExtendedRequestName().isEmpty());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when using the various security levels.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSecurityLevels()
         throws Exception
  {
    final TestCollectSupportDataIntermediateResponseListener listener =
         new TestCollectSupportDataIntermediateResponseListener();

    final CollectSupportDataExtendedRequestProperties properties =
         new CollectSupportDataExtendedRequestProperties();

    for (final CollectSupportDataSecurityLevel securityLevel :
         CollectSupportDataSecurityLevel.values())
    {
      properties.setSecurityLevel(securityLevel);

      CollectSupportDataExtendedRequest r =
           new CollectSupportDataExtendedRequest(properties, listener);

      r = new CollectSupportDataExtendedRequest(r, listener);

      r = r.duplicate();

      assertNotNull(r.getOID());
      assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.64");

      assertNotNull(r.getValue());

      assertNotNull(r.getCollectSupportDataIntermediateResponseListener());
      assertTrue(r.getCollectSupportDataIntermediateResponseListener()
           instanceof TestCollectSupportDataIntermediateResponseListener);

      assertNull(r.getArchiveFileName());

      assertNull(r.getEncryptionPassphrase());

      assertNull(r.getIncludeExpensiveData());

      assertNull(r.getIncludeReplicationStateDump());

      assertNull(r.getIncludeBinaryFiles());

      assertNull(r.getIncludeExpensiveData());

      assertNull(r.getUseSequentialMode());

      assertNotNull(r.getSecurityLevel());
      assertEquals(r.getSecurityLevel(), securityLevel);

      assertNull(r.getJStackCount());

      assertNull(r.getReportCount());

      assertNull(r.getReportIntervalSeconds());

      assertNull(r.getLogCaptureWindow());

      assertNull(r.getComment());

      assertNull(r.getProxyToServerAddress());

      assertNull(r.getProxyToServerPort());

      assertNull(r.getMaximumFragmentSizeBytes());

      assertNotNull(r.getControls());
      assertEquals(r.getControls().length, 0);

      assertNotNull(r.getExtendedRequestName());
      assertFalse(r.getExtendedRequestName().isEmpty());

      assertNotNull(r.toString());
    }
  }



  /**
   * Tests the behavior when using the various log capture window types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLogCaptureWindows()
         throws Exception
  {
    final TestCollectSupportDataIntermediateResponseListener listener =
         new TestCollectSupportDataIntermediateResponseListener();

    final CollectSupportDataExtendedRequestProperties properties =
         new CollectSupportDataExtendedRequestProperties();

    for (final CollectSupportDataLogCaptureWindow lcw :
         Arrays.asList(
              ToolDefaultCollectSupportDataLogCaptureWindow.getInstance(),
              new DurationCollectSupportDataLogCaptureWindow(123_456L),
              new TimeWindowCollectSupportDataLogCaptureWindow(
                   (System.currentTimeMillis() - 3_600_000L),
                   System.currentTimeMillis()),
              new TimeWindowCollectSupportDataLogCaptureWindow(
                   (System.currentTimeMillis() - 600_000L),
                   System.currentTimeMillis()),
              new HeadAndTailSizeCollectSupportDataLogCaptureWindow(123, 456)))
    {
      properties.setLogCaptureWindow(lcw);

      CollectSupportDataExtendedRequest r =
           new CollectSupportDataExtendedRequest(properties, listener);

      r = new CollectSupportDataExtendedRequest(r, listener);

      r = r.duplicate();

      assertNotNull(r.getOID());
      assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.64");

      assertNotNull(r.getValue());

      assertNotNull(r.getCollectSupportDataIntermediateResponseListener());
      assertTrue(r.getCollectSupportDataIntermediateResponseListener()
           instanceof TestCollectSupportDataIntermediateResponseListener);

      assertNull(r.getArchiveFileName());

      assertNull(r.getEncryptionPassphrase());

      assertNull(r.getIncludeExpensiveData());

      assertNull(r.getIncludeReplicationStateDump());

      assertNull(r.getIncludeBinaryFiles());

      assertNull(r.getIncludeExpensiveData());

      assertNull(r.getUseSequentialMode());

      assertNull(r.getSecurityLevel());

      assertNull(r.getJStackCount());

      assertNull(r.getReportCount());

      assertNull(r.getReportIntervalSeconds());

      assertNotNull(r.getLogCaptureWindow());
      assertEquals(r.getLogCaptureWindow().getClass(), lcw.getClass());

      assertNull(r.getComment());

      assertNull(r.getProxyToServerAddress());

      assertNull(r.getProxyToServerPort());

      assertNull(r.getMaximumFragmentSizeBytes());

      assertNotNull(r.getControls());
      assertEquals(r.getControls().length, 0);

      assertNotNull(r.getExtendedRequestName());
      assertFalse(r.getExtendedRequestName().isEmpty());

      assertNotNull(r.toString());
    }
  }



  /**
   * Tests the behavior of the intermediate response returned method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIntermediateResponseReturned()
         throws Exception
  {
    final TestCollectSupportDataIntermediateResponseListener listener =
         new TestCollectSupportDataIntermediateResponseListener();

    final CollectSupportDataExtendedRequest r =
         new CollectSupportDataExtendedRequest(
              new CollectSupportDataExtendedRequestProperties(), listener);


    // Test with a valid output message sent to standard output.
    r.intermediateResponseReturned(
         new CollectSupportDataOutputIntermediateResponse(
              CollectSupportDataOutputStream.STANDARD_OUTPUT,
              "standard output message"));

    assertNotNull(listener.getStandardOutputMessages());
    assertEquals(listener.getStandardOutputMessages().size(), 1);

    assertNotNull(listener.getStandardErrorMessages());
    assertEquals(listener.getStandardErrorMessages().size(), 0);

    assertNotNull(listener.getArchiveData());
    assertEquals(listener.getArchiveData().length, 0);

    assertNotNull(listener.getOtherResponses());
    assertEquals(listener.getOtherResponses().size(), 0);


    // Test with a valid output message sent to standard error.
    listener.clear();

    r.intermediateResponseReturned(
         new CollectSupportDataOutputIntermediateResponse(
              CollectSupportDataOutputStream.STANDARD_ERROR,
              "standard error message"));

    assertNotNull(listener.getStandardOutputMessages());
    assertEquals(listener.getStandardOutputMessages().size(), 0);

    assertNotNull(listener.getStandardErrorMessages());
    assertEquals(listener.getStandardErrorMessages().size(), 1);

    assertNotNull(listener.getArchiveData());
    assertEquals(listener.getArchiveData().length, 0);

    assertNotNull(listener.getOtherResponses());
    assertEquals(listener.getOtherResponses().size(), 0);


    // Test with a malformed output message sent to standard error.
    listener.clear();

    r.intermediateResponseReturned(
         new IntermediateResponse("1.3.6.1.4.1.30221.2.6.65",
              new ASN1OctetString("malformed")));

    assertNotNull(listener.getStandardOutputMessages());
    assertEquals(listener.getStandardOutputMessages().size(), 0);

    assertNotNull(listener.getStandardErrorMessages());
    assertEquals(listener.getStandardErrorMessages().size(), 0);

    assertNotNull(listener.getArchiveData());
    assertEquals(listener.getArchiveData().length, 0);

    assertNotNull(listener.getOtherResponses());
    assertEquals(listener.getOtherResponses().size(), 1);


    // Test with a valid archive fragment.
    listener.clear();

    r.intermediateResponseReturned(
         new CollectSupportDataArchiveFragmentIntermediateResponse(
              "csd.zip", 123_456L, true, StaticUtils.byteArray(1, 2, 3, 4, 5)));

    assertNotNull(listener.getStandardOutputMessages());
    assertEquals(listener.getStandardOutputMessages().size(), 0);

    assertNotNull(listener.getStandardErrorMessages());
    assertEquals(listener.getStandardErrorMessages().size(), 0);

    assertNotNull(listener.getArchiveData());
    assertEquals(listener.getArchiveData().length, 5);

    assertNotNull(listener.getOtherResponses());
    assertEquals(listener.getOtherResponses().size(), 0);


    // Test with a malformed archive fragment.
    listener.clear();

    r.intermediateResponseReturned(
         new IntermediateResponse("1.3.6.1.4.1.30221.2.6.66",
              new ASN1OctetString("malformed")));

    assertNotNull(listener.getStandardOutputMessages());
    assertEquals(listener.getStandardOutputMessages().size(), 0);

    assertNotNull(listener.getStandardErrorMessages());
    assertEquals(listener.getStandardErrorMessages().size(), 0);

    assertNotNull(listener.getArchiveData());
    assertEquals(listener.getArchiveData().length, 0);

    assertNotNull(listener.getOtherResponses());
    assertEquals(listener.getOtherResponses().size(), 1);


    // Test with some other type of intermediate response.
    listener.clear();

    r.intermediateResponseReturned(
         new IntermediateResponse("1.2.3.4", new ASN1OctetString("foo")));

    assertNotNull(listener.getStandardOutputMessages());
    assertEquals(listener.getStandardOutputMessages().size(), 0);

    assertNotNull(listener.getStandardErrorMessages());
    assertEquals(listener.getStandardErrorMessages().size(), 0);

    assertNotNull(listener.getArchiveData());
    assertEquals(listener.getArchiveData().length, 0);

    assertNotNull(listener.getOtherResponses());
    assertEquals(listener.getOtherResponses().size(), 1);
  }



  /**
   * Tests the behavior when trying to send the request to an in-memory
   * directory server instance.  The in-memory directory server doesn't support
   * this type of operation, but it will at least provide coverage for the
   * process method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProcess()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    try (LDAPConnection conn = ds.getConnection())
    {
      final TestCollectSupportDataIntermediateResponseListener listener =
           new TestCollectSupportDataIntermediateResponseListener();

      final CollectSupportDataExtendedRequest r =
           new CollectSupportDataExtendedRequest(
                new CollectSupportDataExtendedRequestProperties(), listener);

      assertResultCodeNot(conn, r, ResultCode.SUCCESS);
    }
  }



  /**
   * Tests the behavior when trying to decode an extended request that does not
   * have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNoValue()
         throws Exception
  {
    final TestCollectSupportDataIntermediateResponseListener listener =
         new TestCollectSupportDataIntermediateResponseListener();

    new CollectSupportDataExtendedRequest(
         new ExtendedRequest("1.3.6.1.4.1.30221.2.6.64"),
         listener);
  }



  /**
   * Tests the behavior when trying to decode an extended request that has a
   * malformed value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedValue()
         throws Exception
  {
    final TestCollectSupportDataIntermediateResponseListener listener =
         new TestCollectSupportDataIntermediateResponseListener();

    new CollectSupportDataExtendedRequest(
         new ExtendedRequest("1.3.6.1.4.1.30221.2.6.64",
              new ASN1OctetString("malformed")),
         listener);
  }



  /**
   * Tests the behavior when trying to decode an extended request that has an
   * undefined security level.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeUndefinedSecurityLevel()
         throws Exception
  {
    final TestCollectSupportDataIntermediateResponseListener listener =
         new TestCollectSupportDataIntermediateResponseListener();

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Enumerated((byte) 0x86, 1234));

    new CollectSupportDataExtendedRequest(
         new ExtendedRequest("1.3.6.1.4.1.30221.2.6.64",
              new ASN1OctetString(valueSequence.encode())),
         listener);
  }



  /**
   * Tests the behavior when trying to decode an extended request that has an
   * undefined log capture window.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeUndefinedLogCaptureWindow()
         throws Exception
  {
    final TestCollectSupportDataIntermediateResponseListener listener =
         new TestCollectSupportDataIntermediateResponseListener();

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Element((byte) 0xAB,
              new ASN1OctetString("malformed").encode()));

    new CollectSupportDataExtendedRequest(
         new ExtendedRequest("1.3.6.1.4.1.30221.2.6.64",
              new ASN1OctetString(valueSequence.encode())),
         listener);
  }
}
