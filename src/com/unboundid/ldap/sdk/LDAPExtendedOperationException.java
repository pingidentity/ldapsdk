/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines an exception that can be thrown if the server returns an
 * extended response that indicates that the operation did not complete
 * successfully.  This may be used to obtain access to any response OID and/or
 * value that may have been included in the extended result.
 */
@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class LDAPExtendedOperationException
       extends LDAPException
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5674215690199642408L;



  // The extended result for this exception.
  @NotNull private final ExtendedResult extendedResult;



  /**
   * Creates a new LDAP extended operation exception from the provided extended
   * result.
   *
   * @param  extendedResult  The extended result to use to create this
   *                         exception.
   */
  public LDAPExtendedOperationException(
              @NotNull final ExtendedResult extendedResult)
  {
    super(extendedResult);

    this.extendedResult = extendedResult;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPResult toLDAPResult()
  {
    return extendedResult;
  }



  /**
   * Retrieves the extended result that was returned by the server.
   *
   * @return  The extended result that was returned by the server.
   */
  @NotNull()
  public ExtendedResult getExtendedResult()
  {
    return extendedResult;
  }



  /**
   * Retrieves the response OID from the extended result, if any.
   *
   * @return  The response OID from the extended result, or {@code null} if the
   *          result did not include an OID.
   */
  @Nullable()
  public String getResponseOID()
  {
    return extendedResult.getOID();
  }



  /**
   * Retrieves the response value from the extended result, if any.
   *
   * @return  The response value from the extended result, or {@code null} if
   *          the result did not include a value.
   */
  @Nullable()
  public ASN1OctetString getResponseValue()
  {
    return extendedResult.getValue();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    super.toString(buffer);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer,
                       final boolean includeCause,
                       final boolean includeStackTrace)
  {
    buffer.append("LDAPException(resultCode=");
    buffer.append(getResultCode());

    final String errorMessage = getMessage();
    final String diagnosticMessage = getDiagnosticMessage();
    if ((errorMessage != null) && (! errorMessage.equals(diagnosticMessage)))
    {
      buffer.append(", errorMessage='");
      buffer.append(errorMessage);
      buffer.append('\'');
    }

    final String responseOID = getResponseOID();
    if (responseOID != null)
    {
      buffer.append(", responseOID='");
      buffer.append(responseOID);
      buffer.append('\'');
    }

    final String responseName = extendedResult.getExtendedResultName();
    if ((responseName != null) && (! responseName.equals(responseOID)))
    {
      buffer.append(", responseName='");
      buffer.append(responseName);
      buffer.append('\'');
    }

    if (diagnosticMessage != null)
    {
      buffer.append(", diagnosticMessage='");
      buffer.append(diagnosticMessage);
      buffer.append('\'');
    }

    final String matchedDN = getMatchedDN();
    if (matchedDN != null)
    {
      buffer.append(", matchedDN='");
      buffer.append(matchedDN);
      buffer.append('\'');
    }

    final String[] referralURLs = getReferralURLs();
    if (referralURLs.length > 0)
    {
      buffer.append(", referralURLs={");

      for (int i=0; i < referralURLs.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append('\'');
        buffer.append(referralURLs[i]);
        buffer.append('\'');
      }

      buffer.append('}');
    }

    final Control[] responseControls = getResponseControls();
    if (responseControls.length > 0)
    {
      buffer.append(", responseControls={");

      for (int i=0; i < responseControls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(responseControls[i]);
      }

      buffer.append('}');
    }

    if (includeStackTrace)
    {
      buffer.append(", trace='");
      StaticUtils.getStackTrace(getStackTrace(), buffer);
      buffer.append('\'');
    }

    final String ldapSDKVersionString = ", ldapSDKVersion=" +
         Version.NUMERIC_VERSION_STRING + ", revision=" + Version.REVISION_ID;
    if (buffer.indexOf(ldapSDKVersionString) < 0)
    {
      buffer.append(ldapSDKVersionString);
    }

    buffer.append(')');
  }
}
