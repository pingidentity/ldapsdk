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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.util.ArrayList;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.util.Base64;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONBuffer;



/**
 * This class provides an {@link LDAPSearchOutputHandler} instance that formats
 * results in JSON.
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
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
final class JSONLDAPSearchOutputHandler
      extends LDAPSearchOutputHandler
{
  // A list that may be used in the course of formatting result lines.
  @NotNull private final ArrayList<String> formattedLines;

  // The JSON buffer used to construct the formatted output.
  @NotNull private final JSONBuffer jsonBuffer;

  // The associated LDAPSearch tool instance.
  @NotNull private final LDAPSearch ldapSearch;



  /**
   * Creates a new instance of this output handler.
   *
   * @param  ldapSearch  The {@link LDAPSearch} tool instance.
   */
  JSONLDAPSearchOutputHandler(@NotNull final LDAPSearch ldapSearch)
  {
    this.ldapSearch = ldapSearch;

    formattedLines = new ArrayList<>(10);
    jsonBuffer = new JSONBuffer(null, 0, true);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void formatHeader()
  {
    // No header is required for this format.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void formatSearchResultEntry(@NotNull final SearchResultEntry entry)
  {
    jsonBuffer.clear();
    jsonBuffer.beginObject();
    jsonBuffer.appendString("result-type", "entry");
    jsonBuffer.appendString("dn", entry.getDN());

    jsonBuffer.beginArray("attributes");
    for (final Attribute a : entry.getAttributes())
    {
      jsonBuffer.beginObject();
      jsonBuffer.appendString("name", a.getName());
      jsonBuffer.beginArray("values");

      for (final String value : a.getValues())
      {
        jsonBuffer.appendString(value);
      }
      jsonBuffer.endArray();
      jsonBuffer.endObject();
    }
    jsonBuffer.endArray();

    handleControls(entry.getControls());

    jsonBuffer.endObject();

    ldapSearch.writeOut(jsonBuffer.toString());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void formatSearchResultReference(
                   @NotNull final SearchResultReference ref)
  {
    jsonBuffer.clear();
    jsonBuffer.beginObject();
    jsonBuffer.appendString("result-type", "reference");

    jsonBuffer.beginArray("referral-urls");
    for (final String url : ref.getReferralURLs())
    {
      jsonBuffer.appendString(url);
    }
    jsonBuffer.endArray();

    handleControls(ref.getControls());

    jsonBuffer.endObject();

    ldapSearch.writeOut(jsonBuffer.toString());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void formatResult(@NotNull final LDAPResult result)
  {
    jsonBuffer.clear();
    jsonBuffer.beginObject();

    if (result instanceof SearchResult)
    {
      jsonBuffer.appendString("result-type", "search-result");
    }
    else
    {
      jsonBuffer.appendString("result-type", "ldap-result");
    }

    jsonBuffer.appendNumber("result-code", result.getResultCode().intValue());
    jsonBuffer.appendString("result-code-name",
         result.getResultCode().getName());

    final String diagnosticMessage = result.getDiagnosticMessage();
    if (diagnosticMessage != null)
    {
      jsonBuffer.appendString("diagnostic-message", diagnosticMessage);
    }

    final String matchedDN = result.getMatchedDN();
    if (matchedDN != null)
    {
      jsonBuffer.appendString("matched-dn", matchedDN);
    }

    final String[] referralURLs = result.getReferralURLs();
    if ((referralURLs != null) && (referralURLs.length > 0))
    {
      jsonBuffer.beginArray("referral-urls");
      for (final String url : referralURLs)
      {
        jsonBuffer.appendString(url);
      }
      jsonBuffer.endArray();
    }

    if (result instanceof SearchResult)
    {
      final SearchResult searchResult = (SearchResult) result;
      jsonBuffer.appendNumber("entries-returned", searchResult.getEntryCount());
      jsonBuffer.appendNumber("references-returned",
           searchResult.getReferenceCount());
    }

    handleControls(result.getResponseControls());

    jsonBuffer.endObject();

    ldapSearch.writeOut(jsonBuffer.toString());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void formatUnsolicitedNotification(
                   @NotNull final LDAPConnection connection,
                   @NotNull final ExtendedResult notification)
  {
    jsonBuffer.clear();
    jsonBuffer.beginObject();

    jsonBuffer.appendString("result-type", "unsolicited-notification");

    final String oid = notification.getOID();
    if (oid != null)
    {
      jsonBuffer.appendString("oid", oid);
    }

    if (notification.hasValue())
    {
      jsonBuffer.appendString("base64-encoded-value",
           Base64.encode(notification.getValue().getValue()));
    }

    jsonBuffer.appendNumber("result-code",
         notification.getResultCode().intValue());
    jsonBuffer.appendString("result-code-name",
         notification.getResultCode().getName());

    final String diagnosticMessage = notification.getDiagnosticMessage();
    if (diagnosticMessage != null)
    {
      jsonBuffer.appendString("diagnostic-message", diagnosticMessage);
    }

    final String matchedDN = notification.getMatchedDN();
    if (matchedDN != null)
    {
      jsonBuffer.appendString("matched-dn", matchedDN);
    }

    final String[] referralURLs = notification.getReferralURLs();
    if ((referralURLs != null) && (referralURLs.length > 0))
    {
      jsonBuffer.beginArray("referral-urls");
      for (final String url : referralURLs)
      {
        jsonBuffer.appendString(url);
      }
      jsonBuffer.endArray();
    }

    handleControls(notification.getResponseControls());

    formattedLines.clear();
    ResultUtils.formatUnsolicitedNotification(formattedLines, notification,
         false, 0, Integer.MAX_VALUE);
    jsonBuffer.beginArray("formatted-unsolicited-notification-lines");
    for (final String line : formattedLines)
    {
      jsonBuffer.appendString(line.trim());
    }
    jsonBuffer.endArray();

    jsonBuffer.endObject();

    ldapSearch.writeOut(jsonBuffer.toString());
  }



  /**
   * Handles the necessary processing for the provided set of controls.
   *
   * @param  controls  The controls to be processed.
   */
  private void handleControls(@Nullable final Control[] controls)
  {
    if ((controls == null) || (controls.length == 0))
    {
      return;
    }

    jsonBuffer.beginArray("controls");

    for (final Control c : controls)
    {
      jsonBuffer.beginObject();
      jsonBuffer.appendString("oid", c.getOID());
      jsonBuffer.appendBoolean("criticality", c.isCritical());

      if (c.hasValue())
      {
        jsonBuffer.appendString("base64-encoded-value",
             Base64.encode(c.getValue().getValue()));
      }

      formattedLines.clear();
      ResultUtils.formatResponseControl(formattedLines, c, false, 0,
           Integer.MAX_VALUE);
      jsonBuffer.beginArray("formatted-control-lines");
      for (final String line : formattedLines)
      {
        jsonBuffer.appendString(line.trim());
      }
      jsonBuffer.endArray();

      jsonBuffer.endObject();
    }

    jsonBuffer.endArray();
  }
}
