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



import java.util.ArrayList;
import java.util.List;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a SASL ANONYMOUS bind request implementation as described
 * in <A HREF="http://www.ietf.org/rfc/rfc4505.txt">RFC 4505</A>.  Binding with
 * The ANONYMOUS SASL mechanism is essentially equivalent to using an anonymous
 * simple bind (i.e., a simple bind with an empty password), although the SASL
 * ANONYMOUS mechanism does provide the ability to include additional trace
 * information with the request that may be logged or otherwise handled by
 * the server.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for performing an ANONYMOUS
 * bind, including a trace string of "Demo Application" against a directory
 * server:
 * <PRE>
 * ANONYMOUSBindRequest bindRequest =
 *      new ANONYMOUSBindRequest("Demo Application");
 * BindResult bindResult;
 * try
 * {
 *   bindResult = connection.bind(bindRequest);
 *   // If we get here, then the bind was successful.
 * }
 * catch (LDAPException le)
 * {
 *   // The bind failed for some reason.
 *   bindResult = new BindResult(le.toLDAPResult());
 *   ResultCode resultCode = le.getResultCode();
 *   String errorMessageFromServer = le.getDiagnosticMessage();
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ANONYMOUSBindRequest
       extends SASLBindRequest
{
  /**
   * The name for the ANONYMOUS SASL mechanism.
   */
  @NotNull public static final String ANONYMOUS_MECHANISM_NAME = "ANONYMOUS";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4259102841471750866L;



  // The trace string that should be included in the bind request, if available.
  @Nullable private final String traceString;



  /**
   * Creates a new SASL ANONYMOUS bind request with no trace string and no
   * controls.
   */
  public ANONYMOUSBindRequest()
  {
    this(null, NO_CONTROLS);
  }



  /**
   * Creates a new SASL ANONYMOUS bind request with the provided trace string
   * and no controls.
   *
   * @param  traceString  The trace string to include in the bind request, or
   *                      {@code null} if no trace string is to be provided.
   */
  public ANONYMOUSBindRequest(@Nullable final String traceString)
  {
    this(traceString, NO_CONTROLS);
  }



  /**
   * Creates a new SASL ANONYMOUS bind request with the provided set of controls
   * and no trace string.
   *
   * @param  controls     The set of controls to include in the request.
   */
  public ANONYMOUSBindRequest(@Nullable final Control... controls)
  {
    this(null, controls);
  }



  /**
   * Creates a new SASL ANONYMOUS bind request with the provided trace string
   * and controls.
   *
   * @param  traceString  The trace string to include in the bind request, or
   *                      {@code null} if no trace string is to be provided.
   * @param  controls     The set of controls to include in the request.
   */
  public ANONYMOUSBindRequest(@Nullable final String traceString,
                              @Nullable final Control... controls)
  {
    super(controls);

    this.traceString = traceString;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getSASLMechanismName()
  {
    return ANONYMOUS_MECHANISM_NAME;
  }



  /**
   * Retrieves the trace string that will be included with the bind request.
   *
   * @return  The trace string that will be included with the bind request, or
   *          {@code null} if there is to be no trace string.
   */
  @Nullable()
  public String getTraceString()
  {
    return traceString;
  }



  /**
   * Sends this bind request to the target server over the provided connection
   * and returns the corresponding response.
   *
   * @param  connection  The connection to use to send this bind request to the
   *                     server and read the associated response.
   * @param  depth       The current referral depth for this request.  It should
   *                     always be one for the initial request, and should only
   *                     be incremented when following referrals.
   *
   * @return  The bind response read from the server.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  @Override()
  @NotNull()
  protected BindResult process(@NotNull final LDAPConnection connection,
                               final int depth)
            throws LDAPException
  {
    ASN1OctetString credentials = null;
    if ((traceString != null) && (! traceString.isEmpty()))
    {
      credentials = new ASN1OctetString(traceString);
    }

    return sendBindRequest(connection, null, credentials, getControls(),
                           getResponseTimeoutMillis(connection));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ANONYMOUSBindRequest getRebindRequest(@NotNull final String host,
                                               final int port)
  {
    return new ANONYMOUSBindRequest(traceString, getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ANONYMOUSBindRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ANONYMOUSBindRequest duplicate(@Nullable final Control[] controls)
  {
    final ANONYMOUSBindRequest bindRequest =
         new ANONYMOUSBindRequest(traceString, controls);
    bindRequest.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return bindRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ANONYMOUSBindRequest(");
    if (traceString != null)
    {
      buffer.append(", trace='");
      buffer.append(traceString);
      buffer.append('\'');
    }

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      buffer.append(", controls={");
      for (int i=0; i < controls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(controls[i]);
      }
      buffer.append('}');
    }

    buffer.append(')');
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toCode(@NotNull final List<String> lineList,
                     @NotNull final String requestID,
                     final int indentSpaces, final boolean includeProcessing)
  {
    // Create the request variable.
    final ArrayList<ToCodeArgHelper> constructorArgs = new ArrayList<>(2);
    constructorArgs.add(ToCodeArgHelper.createString(traceString,
         "Trace String"));

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      constructorArgs.add(ToCodeArgHelper.createControlArray(controls,
           "Bind Controls"));
    }

    ToCodeHelper.generateMethodCall(lineList, indentSpaces,
         "ANONYMOUSBindRequest", requestID + "Request",
         "new ANONYMOUSBindRequest", constructorArgs);


    // Add lines for processing the request and obtaining the result.
    if (includeProcessing)
    {
      // Generate a string with the appropriate indent.
      final StringBuilder buffer = new StringBuilder();
      for (int i=0; i < indentSpaces; i++)
      {
        buffer.append(' ');
      }
      final String indent = buffer.toString();

      lineList.add("");
      lineList.add(indent + "try");
      lineList.add(indent + '{');
      lineList.add(indent + "  BindResult " + requestID +
           "Result = connection.bind(" + requestID + "Request);");
      lineList.add(indent + "  // The bind was processed successfully.");
      lineList.add(indent + '}');
      lineList.add(indent + "catch (LDAPException e)");
      lineList.add(indent + '{');
      lineList.add(indent + "  // The bind failed.  Maybe the following will " +
           "help explain why.");
      lineList.add(indent + "  // Note that the connection is now likely in " +
           "an unauthenticated state.");
      lineList.add(indent + "  ResultCode resultCode = e.getResultCode();");
      lineList.add(indent + "  String message = e.getMessage();");
      lineList.add(indent + "  String matchedDN = e.getMatchedDN();");
      lineList.add(indent + "  String[] referralURLs = e.getReferralURLs();");
      lineList.add(indent + "  Control[] responseControls = " +
           "e.getResponseControls();");
      lineList.add(indent + '}');
    }
  }
}
