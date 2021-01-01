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
package com.unboundid.ldap.sdk;



import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides a mechanism for performing SASL authentication in a
 * generic manner.  The caller is responsible for properly encoding the
 * credentials (if any) and interpreting the result.  Further, if the requested
 * SASL mechanism is one that requires multiple stages, then the caller is
 * responsible for all processing in each stage.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GenericSASLBindRequest
       extends SASLBindRequest
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7740968332104559230L;



  // The SASL credentials that should be used for the bind request.
  @Nullable private final ASN1OctetString credentials;

  // The bind DN to use for the bind request.
  @Nullable private final String bindDN;

  // The name of the SASL mechanism that should be used for the bind request.
  @NotNull private final String mechanism;



  /**
   * Creates a new generic SASL bind request with the provided information.
   *
   * @param  bindDN       The bind DN that should be used for the request.  It
   *                      may be {@code null} if the target identity should be
   *                      derived from the credentials or some other source.
   * @param  mechanism    The name of the mechanism that should be used for the
   *                      SASL bind.  It must not be {@code null}.
   * @param  credentials  The credentials that should be used for the SASL bind.
   *                      It may be {@code null} if no credentials should be
   *                      used.
   * @param  controls     The set of controls to include in the SASL bind
   *                      request.  It may be {@code null} or empty if no
   *                      request controls are needed.
   */
  public GenericSASLBindRequest(@Nullable final String bindDN,
                                @NotNull final String mechanism,
                                @Nullable final ASN1OctetString credentials,
                                @Nullable final Control... controls)
  {
    super(controls);

    Validator.ensureNotNull(mechanism);

    this.bindDN      = bindDN;
    this.mechanism   = mechanism;
    this.credentials = credentials;
  }



  /**
   * Retrieves the bind DN for this SASL bind request, if any.
   *
   * @return  The bind DN for this SASL bind request, or {@code null} if the
   *          target identity should be determined from the credentials or some
   *          other mechanism.
   */
  @Nullable()
  public String getBindDN()
  {
    return bindDN;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getSASLMechanismName()
  {
    return mechanism;
  }



  /**
   * Retrieves the credentials for the SASL bind request, if any.
   *
   * @return  The credentials for the SASL bind request, or {@code null} if
   *          there are none.
   */
  @Nullable()
  public ASN1OctetString getCredentials()
  {
    return credentials;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected BindResult process(@NotNull final LDAPConnection connection,
                               final int depth)
            throws LDAPException
  {
    return sendBindRequest(connection, bindDN, credentials, getControls(),
         getResponseTimeoutMillis(connection));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public GenericSASLBindRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public GenericSASLBindRequest duplicate(@Nullable final Control[] controls)
  {
    return new GenericSASLBindRequest(bindDN, mechanism, credentials,
         controls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GenericSASLBindRequest(mechanism='");
    buffer.append(mechanism);
    buffer.append('\'');

    if (bindDN != null)
    {
      buffer.append(", bindDN='");
      buffer.append(bindDN);
      buffer.append('\'');
    }

    if (credentials != null)
    {
      buffer.append(", credentials=byte[");
      buffer.append(credentials.getValueLength());
      buffer.append(']');
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
    final ArrayList<ToCodeArgHelper> constructorArgs = new ArrayList<>(4);
    constructorArgs.add(ToCodeArgHelper.createString(bindDN, "Bind DN"));
    constructorArgs.add(ToCodeArgHelper.createString(mechanism,
         "SASL Mechanism Name"));
    constructorArgs.add(ToCodeArgHelper.createByteArray(
         "---redacted-SASL-credentials".getBytes(StandardCharsets.UTF_8), true,
         "SASL Credentials"));

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      constructorArgs.add(ToCodeArgHelper.createControlArray(controls,
           "Bind Controls"));
    }

    ToCodeHelper.generateMethodCall(lineList, indentSpaces,
         "GenericSASLBindRequest", requestID + "Request",
         "new GenericSASLBindRequest", constructorArgs);


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
      lineList.add(indent + '{');
      lineList.add(indent + "  BindResult " + requestID +
           "Result = connection.bind(" + requestID + "Request);");
      lineList.add(indent + "  // The bind was processed successfully.");
      lineList.add(indent + '}');
      lineList.add(indent + "catch (SASLBindInProgressException e)");
      lineList.add(indent + '{');
      lineList.add(indent + "  // The SASL bind requires multiple stages.  " +
           "Continue it here.");
      lineList.add(indent + "  // Do not attempt to use the connection for " +
           "any other purpose until bind processing has completed.");
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
