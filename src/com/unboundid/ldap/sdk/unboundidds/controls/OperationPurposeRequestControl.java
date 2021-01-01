/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.util.ArrayList;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a request control that can be used by the client to
 * identify the purpose of the associated operation.  It can be used in
 * conjunction with any kind of operation, and may be used to provide
 * information about the reason for that operation, as well as about the client
 * application used to generate the request.  This may be very useful for
 * debugging and auditing purposes.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 * <BR>
 * The criticality for this control may be either {@code true} or {@code false}.
 * It must have a value with the following encoding:
 * <PRE>
 *   OperationPurposeRequest ::= SEQUENCE {
 *        applicationName     [0] OCTET STRING OPTIONAL,
 *        applicationVersion  [1] OCTET STRING OPTIONAL,
 *        codeLocation        [2] OCTET STRING OPTIONAL,
 *        requestPurpose      [3] OCTET STRING OPTIONAL
 *        ... }
 * </PRE>
 * At least one of the elements in the value sequence must be present.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates a sample authentication consisting of a
 * search to find a user followed by a bind to verify that user's password.
 * Both the search and bind requests will include operation purpose controls
 * with information about the reason for the request.  Note that for the sake
 * of brevity and clarity, error handling has been omitted from this example.
 * <PRE>
 * SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
 *      SearchScope.SUB, Filter.createEqualityFilter("uid", uidValue),
 *      "1.1");
 * searchRequest.addControl(new OperationPurposeRequestControl(appName,
 *      appVersion, 0,  "Retrieve the entry for a user with a given uid"));
 * Entry userEntry = connection.searchForEntry(searchRequest);
 *
 * SimpleBindRequest bindRequest = new SimpleBindRequest(userEntry.getDN(),
 *      password, new OperationPurposeRequestControl(appName, appVersion, 0,
 *      "Bind as a user to verify the provided credentials."));
 * BindResult bindResult = connection.bind(bindRequest);
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class OperationPurposeRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.19) for the operation purpose request
   * control.
   */
  @NotNull public static final String OPERATION_PURPOSE_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.19";



  /**
   * The BER type for the element that specifies the application name.
   */
  private static final byte TYPE_APP_NAME = (byte) 0x80;



  /**
   * The BER type for the element that specifies the application version.
   */
  private static final byte TYPE_APP_VERSION = (byte) 0x81;



  /**
   * The BER type for the element that specifies the code location.
   */
  private static final byte TYPE_CODE_LOCATION = (byte) 0x82;



  /**
   * The BER type for the element that specifies the request purpose.
   */
  private static final byte TYPE_REQUEST_PURPOSE = (byte) 0x83;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5552051862785419833L;



  // The application name for this control, if any.
  @Nullable private final String applicationName;

  // The application version for this control, if any.
  @Nullable private final String applicationVersion;

  // The code location for this control, if any.
  @Nullable private final String codeLocation;

  // The request purpose for this control, if any.
  @Nullable private final String requestPurpose;



  /**
   * Creates a new operation purpose request control with the provided
   * information.  It will not be critical.  If the generateCodeLocation
   * argument has a value of {@code false}, then at least one of the
   * applicationName, applicationVersion, and requestPurpose arguments must
   * be non-{@code null}.
   *
   * @param  applicationName     The name of the application generating the
   *                             associated request.  It may be {@code null} if
   *                             this should not be included in the control.
   * @param  applicationVersion  Information about the version of the
   *                             application generating the associated request.
   *                             It may be {@code null} if this should not be
   *                             included in the control.
   * @param  codeLocationFrames  Indicates that the code location should be
   *                             automatically generated with a condensed stack
   *                             trace for the current thread, using the
   *                             specified number of stack frames.  A value that
   *                             is less than or equal to zero indicates an
   *                             unlimited number of stack frames should be
   *                             included.
   * @param  requestPurpose      A string identifying the purpose of the
   *                             associated request.  It may be {@code null} if
   *                             this should not be included in the control.
   */
  public OperationPurposeRequestControl(@Nullable final String applicationName,
              @Nullable final String applicationVersion,
              final int codeLocationFrames,
              @Nullable final String requestPurpose)
  {
    this(false, applicationName, applicationVersion,
         generateStackTrace(codeLocationFrames), requestPurpose);
  }



  /**
   * Creates a new operation purpose request control with the provided
   * information.  At least one of the applicationName, applicationVersion,
   * codeLocation, and requestPurpose arguments must be non-{@code null}.
   *
   * @param  isCritical          Indicates whether the control should be
   *                             considered critical.
   * @param  applicationName     The name of the application generating the
   *                             associated request.  It may be {@code null} if
   *                             this should not be included in the control.
   * @param  applicationVersion  Information about the version of the
   *                             application generating the associated request.
   *                             It may be {@code null} if this should not be
   *                             included in the control.
   * @param  codeLocation        Information about the location in the
   *                             application code in which the associated
   *                             request is generated (e.g., the class and/or
   *                             method name, or any other useful identifier).
   *                             It may be {@code null} if this should not be
   *                             included in the control.
   * @param  requestPurpose      A string identifying the purpose of the
   *                             associated request.  It may be {@code null} if
   *                             this should not be included in the control.
   */
  public OperationPurposeRequestControl(final boolean isCritical,
              @Nullable final String applicationName,
              @Nullable final String applicationVersion,
              @Nullable final String codeLocation,
              @Nullable final String requestPurpose)
  {
    super(OPERATION_PURPOSE_REQUEST_OID, isCritical,
         encodeValue(applicationName, applicationVersion, codeLocation,
              requestPurpose));

    this.applicationName    = applicationName;
    this.applicationVersion = applicationVersion;
    this.codeLocation       = codeLocation;
    this.requestPurpose     = requestPurpose;
  }



  /**
   * Creates a new operation purpose request control which is decoded from the
   * provided generic control.
   *
   * @param  control  The generic control to be decoded as an operation purpose
   *                  request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as an
   *                         operation purpose request control.
   */
  public OperationPurposeRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_OP_PURPOSE_NO_VALUE.get());
    }

    final ASN1Element[] valueElements;
    try
    {
      valueElements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_OP_PURPOSE_VALUE_NOT_SEQUENCE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    if (valueElements.length == 0)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_OP_PURPOSE_VALUE_SEQUENCE_EMPTY.get());
    }


    String appName    = null;
    String appVersion = null;
    String codeLoc    = null;
    String reqPurpose = null;
    for (final ASN1Element e : valueElements)
    {
      switch (e.getType())
      {
        case TYPE_APP_NAME:
          appName = ASN1OctetString.decodeAsOctetString(e).stringValue();
          break;

        case TYPE_APP_VERSION:
          appVersion = ASN1OctetString.decodeAsOctetString(e).stringValue();
          break;

        case TYPE_CODE_LOCATION:
          codeLoc = ASN1OctetString.decodeAsOctetString(e).stringValue();
          break;

        case TYPE_REQUEST_PURPOSE:
          reqPurpose = ASN1OctetString.decodeAsOctetString(e).stringValue();
          break;

        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_OP_PURPOSE_VALUE_UNSUPPORTED_ELEMENT.get(
                    StaticUtils.toHex(e.getType())));
      }
    }

    applicationName    = appName;
    applicationVersion = appVersion;
    codeLocation       = codeLoc;
    requestPurpose     = reqPurpose;
  }



  /**
   * Generates a compact stack trace for the current thread,  The stack trace
   * elements will start with the last frame to call into this class (so that
   * frames referencing this class, and anything called by this class in the
   * process of getting the stack trace will be omitted).  Elements will be
   * space-delimited and will contain the unqualified class name, a period,
   * the method name, a colon, and the source line number.
   *
   * @param  numFrames  The maximum number of frames to capture in the stack
   *                    trace.
   *
   * @return  The generated stack trace for the current thread.
   */
  @NotNull()
  private static String generateStackTrace(final int numFrames)
  {
    final StringBuilder buffer = new StringBuilder();
    final int n = (numFrames > 0) ? numFrames : Integer.MAX_VALUE;

    int c = 0;
    boolean skip = true;
    for (final StackTraceElement e : Thread.currentThread().getStackTrace())
    {
      final String className = e.getClassName();
      if (className.equals(OperationPurposeRequestControl.class.getName()))
      {
        skip = false;
        continue;
      }
      else if (skip)
      {
        continue;
      }

      if (buffer.length() > 0)
      {
        buffer.append(' ');
      }

      final int lastPeriodPos = className.lastIndexOf('.');
      if (lastPeriodPos > 0)
      {
        buffer.append(className.substring(lastPeriodPos+1));
      }
      else
      {
        buffer.append(className);
      }

      buffer.append('.');
      buffer.append(e.getMethodName());
      buffer.append(':');
      buffer.append(e.getLineNumber());

      c++;
      if (c >= n)
      {
        break;
      }
    }

    return buffer.toString();
  }



  /**
   * Encodes the provided information into a form suitable for use as the value
   * of this control.
   *
   * @param  applicationName     The name of the application generating the
   *                             associated request.  It may be {@code null} if
   *                             this should not be included in the control.
   * @param  applicationVersion  Information about the version of the
   *                             application generating the associated request.
   *                             It may be {@code null} if this should not be
   *                             included in the control.
   * @param  codeLocation        Information about the location in the
   *                             application code in which the associated
   *                             request is generated (e.g., the class and/or
   *                             method name, or any other useful identifier).
   *                             It may be {@code null} if this should not be
   *                             included in the control.
   * @param  requestPurpose      A string identifying the purpose of the
   *                             associated request.  It may be {@code null} if
   *                             this should not be included in the control.
   *
   * @return  The encoded value for this control.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
               @Nullable final String applicationName,
               @Nullable final String applicationVersion,
               @Nullable final String codeLocation,
               @Nullable final String requestPurpose)
  {
    Validator.ensureFalse((applicationName == null) &&
         (applicationVersion == null) && (codeLocation == null) &&
         (requestPurpose == null));

    final ArrayList<ASN1Element> elements = new ArrayList<>(4);

    if (applicationName != null)
    {
      elements.add(new ASN1OctetString(TYPE_APP_NAME, applicationName));
    }

    if (applicationVersion != null)
    {
      elements.add(new ASN1OctetString(TYPE_APP_VERSION, applicationVersion));
    }

    if (codeLocation != null)
    {
      elements.add(new ASN1OctetString(TYPE_CODE_LOCATION, codeLocation));
    }

    if (requestPurpose != null)
    {
      elements.add(new ASN1OctetString(TYPE_REQUEST_PURPOSE, requestPurpose));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the name of the application that generated the associated
   * request, if available.
   *
   * @return  The name of the application that generated the associated request,
   *          or {@code null} if that is not available.
   */
  @Nullable()
  public String getApplicationName()
  {
    return applicationName;
  }



  /**
   * Retrieves information about the version of the application that generated
   * the associated request, if available.
   *
   * @return  Information about the version of the application that generated
   *          the associated request, or {@code null} if that is not available.
   */
  @Nullable()
  public String getApplicationVersion()
  {
    return applicationVersion;
  }



  /**
   * Retrieves information about the location in the application code in which
   * the associated request was created, if available.
   *
   * @return  Information about the location in the application code in which
   *          the associated request was created, or {@code null} if that is not
   *          available.
   */
  @Nullable()
  public String getCodeLocation()
  {
    return codeLocation;
  }



  /**
   * Retrieves a message with information about the purpose of the associated
   * request, if available.
   *
   * @return  A message with information about the purpose of the associated
   *          request, or {@code null} if that is not available.
   */
  @Nullable()
  public String getRequestPurpose()
  {
    return requestPurpose;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_OP_PURPOSE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("OperationPurposeRequestControl(isCritical=");
    buffer.append(isCritical());

    if (applicationName != null)
    {
      buffer.append(", appName='");
      buffer.append(applicationName);
      buffer.append('\'');
    }


    if (applicationVersion != null)
    {
      buffer.append(", appVersion='");
      buffer.append(applicationVersion);
      buffer.append('\'');
    }


    if (codeLocation != null)
    {
      buffer.append(", codeLocation='");
      buffer.append(codeLocation);
      buffer.append('\'');
    }


    if (requestPurpose != null)
    {
      buffer.append(", purpose='");
      buffer.append(requestPurpose);
      buffer.append('\'');
    }

    buffer.append(')');
  }
}
