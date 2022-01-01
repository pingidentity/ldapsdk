/*
 * Copyright 2017-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2022 Ping Identity Corporation
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
 * Copyright (C) 2017-2022 Ping Identity Corporation
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



import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.CompareResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPRuntimeException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.util.Base64;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONBuffer;
import com.unboundid.util.json.JSONException;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides an {@link LDAPResultWriter} instance that formats results
 * in JSON.
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
public final class JSONLDAPResultWriter
       extends LDAPResultWriter
{
  // A list that may be used in the course of formatting result lines.
  @NotNull private final ArrayList<String> formattedLines;

  // The JSON buffer used to construct the formatted output.
  @NotNull private final JSONBuffer jsonBuffer;



  /**
   * Creates a new instance of this LDAP result writer.
   *
   * @param  outputStream  The output stream to which output will be written.
   */
  public JSONLDAPResultWriter(@NotNull final OutputStream outputStream)
  {
    super(outputStream);

    formattedLines = new ArrayList<>(10);
    jsonBuffer = new JSONBuffer(null, 0, true);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void writeComment(@NotNull final String comment)
  {
    // Comments will not be written in this format.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void writeHeader()
  {
    // No header is required for this format.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void writeSearchResultEntry(@NotNull final SearchResultEntry entry)
  {
    jsonBuffer.clear();
    toJSON(entry, jsonBuffer, formattedLines);
    println(jsonBuffer.toString());
  }



  /**
   * Encodes the provided entry as a JSON object.
   *
   * @param  entry  The entry to be encoded as a JSON object.  It must not be
   *                {@code null}.
   *
   * @return  The JSON object containing the encoded representation of the
   *          entry.
   */
  @NotNull()
  public static JSONObject toJSON(@NotNull final Entry entry)
  {
    try
    {
      final JSONBuffer jsonBuffer = new JSONBuffer();
      toJSON(entry, jsonBuffer);
      return jsonBuffer.toJSONObject();
    }
    catch (final JSONException e)
    {
      // This should never happen.
      Debug.debugException(e);
      throw new LDAPRuntimeException(new LDAPException(
           ResultCode.ENCODING_ERROR, e.getMessage(), e));
    }
  }



  /**
   * Appends a JSON object representation of the provided entry to the given
   * buffer.
   *
   * @param  entry       The entry to be encoded as a JSON object.  It must not
   *                     be {@code null}.
   * @param  jsonBuffer  The JSON buffer to which the encoded representation
   *                     of the entry is to be appended.  It must not be
   *                     {@code null}.
   */
  public static void toJSON(@NotNull final Entry entry,
                            @NotNull final JSONBuffer jsonBuffer)
  {
    toJSON(entry, jsonBuffer, null);
  }



  /**
   * Appends a JSON object representation of the provided entry to the given
   * buffer.
   *
   * @param  entry           The entry to be encoded as a JSON object.  It must
   *                         not be {@code null}.
   * @param  jsonBuffer      The JSON buffer to which the encoded representation
   *                         of the entry is to be appended.  It must not be
   *                         {@code null}.
   * @param  formattedLines  A list that will be used for temporary storage
   *                         during processing.  It must not be {@code null},
   *                         must be updatable, and must not contain any data
   *                         that you care about being preserved.
   */
  private static void toJSON(@NotNull final Entry entry,
                             @NotNull final JSONBuffer jsonBuffer,
                             @Nullable final List<String> formattedLines)
  {
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

    if (entry instanceof SearchResultEntry)
    {
      final SearchResultEntry searchResultEntry = (SearchResultEntry) entry;
      final Control[] controls = searchResultEntry.getControls();
      if ((controls != null) && (controls.length > 0))
      {
        if (formattedLines == null)
        {
          handleControls(controls, jsonBuffer, new ArrayList<String>());
        }
        else
        {
          handleControls(controls, jsonBuffer, formattedLines);
        }
      }
    }

    jsonBuffer.endObject();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void writeSearchResultReference(
                   @NotNull final SearchResultReference ref)
  {
    jsonBuffer.clear();
    toJSON(ref, jsonBuffer, formattedLines);
    println(jsonBuffer.toString());
  }



  /**
   * Encodes the provided search result reference as a JSON object.
   *
   * @param  ref  The search result reference to be encoded as a JSON object.
   *              It must not be {@code null}.
   *
   * @return  The JSON object containing the encoded representation of the
   *          search result reference.
   */
  @NotNull()
  public static JSONObject toJSON(
              @NotNull final SearchResultReference ref)
  {
    try
    {
      final JSONBuffer jsonBuffer = new JSONBuffer();
      toJSON(ref, jsonBuffer);
      return jsonBuffer.toJSONObject();
    }
    catch (final JSONException e)
    {
      // This should never happen.
      Debug.debugException(e);
      throw new LDAPRuntimeException(new LDAPException(
           ResultCode.ENCODING_ERROR, e.getMessage(), e));
    }
  }



  /**
   * Appends a JSON object representation of the provided search result
   * reference to the given buffer.
   *
   * @param  ref         The search result reference to be encoded as a JSON
   *                     object.  It must not be {@code null}.
   * @param  jsonBuffer  The JSON buffer to which the encoded representation
   *                     of the reference is to be appended.  It must not be
   *                     {@code null}.
   */
  public static void toJSON(@NotNull final SearchResultReference ref,
                            @NotNull final JSONBuffer jsonBuffer)
  {
    toJSON(ref, jsonBuffer, null);
  }



  /**
   * Appends a JSON object representation of the provided search result
   * reference to the given buffer.
   *
   * @param  ref             The search result reference to be encoded as a JSON
   *                         object.  It must not be {@code null}.
   * @param  jsonBuffer      The JSON buffer to which the encoded representation
   *                         of the reference is to be appended.  It must not be
   *                         {@code null}.
   * @param  formattedLines  A list that will be used for temporary storage
   *                         during processing.  It must not be {@code null},
   *                         must be updatable, and must not contain any data
   *                         that you care about being preserved.
   */
  private static void toJSON(@NotNull final SearchResultReference ref,
                             @NotNull final JSONBuffer jsonBuffer,
                             @Nullable final List<String> formattedLines)
  {
    jsonBuffer.beginObject();
    jsonBuffer.appendString("result-type", "reference");

    jsonBuffer.beginArray("referral-urls");
    for (final String url : ref.getReferralURLs())
    {
      jsonBuffer.appendString(url);
    }
    jsonBuffer.endArray();

    final Control[] controls = ref.getControls();
    if ((controls != null) && (controls.length > 0))
    {
      if (formattedLines == null)
      {
        handleControls(controls, jsonBuffer, new ArrayList<String>());
      }
      else
      {
        handleControls(controls, jsonBuffer, formattedLines);
      }
    }

    jsonBuffer.endObject();

  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void writeResult(@NotNull final LDAPResult result)
  {
    jsonBuffer.clear();
    toJSON(result, jsonBuffer, formattedLines);
    println(jsonBuffer.toString());
  }



  /**
   * Encodes the provided LDAP result as a JSON object.
   *
   * @param  result  The LDAP result to be encoded as a JSON object.  It must
   *                 not be {@code null}.
   *
   * @return  The JSON object containing the encoded representation of the
   *          LDAP result.
   */
  @NotNull()
  public static JSONObject toJSON(@NotNull final LDAPResult result)
  {
    try
    {
      final JSONBuffer jsonBuffer = new JSONBuffer();
      toJSON(result, jsonBuffer);
      return jsonBuffer.toJSONObject();
    }
    catch (final JSONException e)
    {
      // This should never happen.
      Debug.debugException(e);
      throw new LDAPRuntimeException(new LDAPException(
           ResultCode.ENCODING_ERROR, e.getMessage(), e));
    }
  }



  /**
   * Appends a JSON object representation of the provided entry to the given
   * buffer.
   *
   * @param  result      The LDAP result to be encoded as a JSON object.  It
   *                     must not be {@code null}.
   * @param  jsonBuffer  The JSON buffer to which the encoded representation
   *                     of the LDAP result is to be appended.  It must not be
   *                     {@code null}.
   */
  public static void toJSON(@NotNull final LDAPResult result,
                            @NotNull final JSONBuffer jsonBuffer)
  {
    toJSON(result, jsonBuffer, null);
  }



  /**
   * Appends a JSON object representation of the provided LDAP result to the
   * given buffer.
   *
   * @param  result          The LDAP result to be encoded as a JSON object.  It
   *                         must not be {@code null}.
   * @param  jsonBuffer      The JSON buffer to which the encoded representation
   *                         of the LDAP result is to be appended.  It must not
   *                         be {@code null}.
   * @param  formattedLines  A list that will be used for temporary storage
   *                         during processing.  It must not be {@code null},
   *                         must be updatable, and must not contain any data
   *                         that you care about being preserved.
   */
  private static void toJSON(@NotNull final LDAPResult result,
                             @NotNull final JSONBuffer jsonBuffer,
                             @Nullable final List<String> formattedLines)
  {
    jsonBuffer.beginObject();

    if (result instanceof SearchResult)
    {
      jsonBuffer.appendString("result-type", "search-result");
    }
    else if (result instanceof BindResult)
    {
      jsonBuffer.appendString("result-type", "bind-result");
    }
    else if (result instanceof CompareResult)
    {
      jsonBuffer.appendString("result-type", "compare-result");
    }
    else if (result instanceof ExtendedResult)
    {
      jsonBuffer.appendString("result-type", "extended-result");
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
    else if (result instanceof ExtendedResult)
    {
      final ExtendedResult extendedResult = (ExtendedResult) result;
      final String oid = extendedResult.getOID();
      if (oid != null)
      {
        jsonBuffer.appendString("oid", oid);
      }

      if (extendedResult.hasValue())
      {
        jsonBuffer.appendString("base64-encoded-value",
             Base64.encode(extendedResult.getValue().getValue()));
      }
    }

    final Control[] controls = result.getResponseControls();
    if ((controls != null) && (controls.length > 0))
    {
      if (formattedLines == null)
      {
        handleControls(controls, jsonBuffer, new ArrayList<String>());
      }
      else
      {
        handleControls(controls, jsonBuffer, formattedLines);
      }
    }

    jsonBuffer.endObject();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void writeUnsolicitedNotification(
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

    println(jsonBuffer.toString());
  }



  /**
   * Handles the necessary processing for the provided set of controls.
   *
   * @param  controls  The controls to be processed.  It may be {@code null} or
   *                   empty if there are no controls to be processed.
   */
  private void handleControls(@Nullable final Control[] controls)
  {
    handleControls(controls, jsonBuffer, formattedLines);
  }



  /**
   * Handles the necessary processing for the provided set of controls.
   *
   * @param  controls        The controls to be processed.  It must not be
   *                         {@code null} or emtpy.
   * @param  jsonBuffer      The buffer to which the encoded representation of
   *                         the controls should be appended.  It must not be
   *                         {@code null}.
   * @param  formattedLines  A list that will be used for temporary storage
   *                         during processing.  It must not be {@code null},
   *                         must be updatable, and must not contain any data
   *                         that you care about being preserved.
   */
  private static void handleControls(@Nullable final Control[] controls,
                                     @NotNull final JSONBuffer jsonBuffer,
                                     @NotNull final List<String> formattedLines)
  {
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
