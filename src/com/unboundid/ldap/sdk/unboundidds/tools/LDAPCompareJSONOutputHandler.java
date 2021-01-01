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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.util.LinkedHashMap;
import java.util.Map;

import com.unboundid.ldap.sdk.CompareRequest;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;



/**
 * This class provides an {@link LDAPCompare} output handler that will format
 * messages as JSON objects.
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
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class LDAPCompareJSONOutputHandler
      extends LDAPCompareOutputHandler
{
  /**
   * The name of the JSON field that holds the assertion value.
   */
  @NotNull private static final String FIELD_NAME_ASSERTION_VALUE =
       "assertion-value";



  /**
   * The name of the JSON field that holds the name of the target attribute.
   */
  @NotNull private static final String FIELD_NAME_ATTRIBUTE = "attribute-name";



  /**
   * The name of the JSON field that holds the diagnostic message from the
   * response.
   */
  @NotNull private static final String FIELD_NAME_DIAGNOSTIC_MESSAGE =
       "diagnostic-message";



  /**
   * The name of the JSON field that holds the DN of the target entry.
   */
  @NotNull private static final String FIELD_NAME_DN = "entry-dn";



  /**
   * The name of the JSON field that holds the matched DN from the response.
   */
  @NotNull private static final String FIELD_NAME_MATCHED_DN = "matched-dn";



  /**
   * The name of the JSON field that holds the referral URLs from the response.
   */
  @NotNull private static final String FIELD_NAME_REFERRAL_URLS =
       "referral-urls";



  /**
   * The name of the JSON field that holds the name of the result code.
   */
  @NotNull private static final String FIELD_NAME_RESULT_CODE_NAME =
       "result-code-name";



  /**
   * The name of the JSON field that holds the integer value of the result code.
   */
  @NotNull private static final String FIELD_NAME_RESULT_CODE_VALUE =
       "result-code-value";



  /**
   * Creates a new instance of this output handler.
   */
  LDAPCompareJSONOutputHandler()
  {
    // No implementation required.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  String formatResult(@NotNull final CompareRequest request,
                      @NotNull final LDAPResult result)
  {
    final Map<String,JSONValue> fields = new LinkedHashMap<>();
    fields.put(FIELD_NAME_DN, new JSONString(request.getDN()));
    fields.put(FIELD_NAME_ATTRIBUTE,
         new JSONString(request.getAttributeName()));
    fields.put(FIELD_NAME_ASSERTION_VALUE,
         new JSONString(request.getAssertionValue()));
    fields.put(FIELD_NAME_RESULT_CODE_VALUE,
         new JSONNumber(result.getResultCode().intValue()));
    fields.put(FIELD_NAME_RESULT_CODE_NAME,
         new JSONString(result.getResultCode().getName()));

    if (result.getDiagnosticMessage() != null)
    {
      fields.put(FIELD_NAME_DIAGNOSTIC_MESSAGE,
           new JSONString(result.getDiagnosticMessage()));
    }

    if (result.getMatchedDN() != null)
    {
      fields.put(FIELD_NAME_MATCHED_DN,
           new JSONString(result.getMatchedDN()));
    }

    if (result.getReferralURLs().length > 0)
    {
      final JSONValue[] referralURLValues =
           new JSONValue[result.getReferralURLs().length];
      for (int i=0; i < referralURLValues.length; i++)
      {
        referralURLValues[i] = new JSONString(result.getReferralURLs()[i]);
      }

      fields.put(FIELD_NAME_REFERRAL_URLS,
           new JSONArray(referralURLValues));
    }

    return new JSONObject(fields).toSingleLineString();
  }
}
