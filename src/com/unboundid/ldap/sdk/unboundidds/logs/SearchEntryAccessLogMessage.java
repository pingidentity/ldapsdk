/*
 * Copyright 2009-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2025 Ping Identity Corporation
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
 * Copyright (C) 2009-2025 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs;



import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.StringTokenizer;

import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about a log
 * message that may appear in the Directory Server access log about a search
 * result entry returned to a client.
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
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SearchEntryAccessLogMessage
       extends SearchRequestAccessLogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6423635071693560277L;



  // The names of the attributes included in the entry that was returned.
  @Nullable private final List<String> attributesReturned;

  // The list of response control OIDs for the operation.
  @NotNull private final List<String> responseControlOIDs;

  // The DN of the entry returned.
  @Nullable private final String dn;



  /**
   * Creates a new search result entry access log message from the provided
   * message string.
   *
   * @param  s  The string to be parsed as a search result entry access log
   *            message.
   *
   * @throws  LogException  If the provided string cannot be parsed as a valid
   *                        log message.
   */
  public SearchEntryAccessLogMessage(@NotNull final String s)
         throws LogException
  {
    this(new LogMessage(s));
  }



  /**
   * Creates a new search result entry access log message from the provided log
   * message.
   *
   * @param  m  The log message to be parsed as a search entry access log
   *            message.
   */
  public SearchEntryAccessLogMessage(@NotNull final LogMessage m)
  {
    super(m);

    dn = getNamedValue("dn");

    final String controlStr = getNamedValue("responseControls");
    if (controlStr == null)
    {
      responseControlOIDs = Collections.emptyList();
    }
    else
    {
      final LinkedList<String> controlList = new LinkedList<>();
      final StringTokenizer t = new StringTokenizer(controlStr, ",");
      while (t.hasMoreTokens())
      {
        controlList.add(t.nextToken());
      }
      responseControlOIDs = Collections.unmodifiableList(controlList);
    }

    final String attrs = getNamedValue("attrsReturned");
    if (attrs == null)
    {
      attributesReturned = null;
    }
    else
    {
      final ArrayList<String> l = new ArrayList<>(10);
      final StringTokenizer tokenizer = new StringTokenizer(attrs, ",");
      while (tokenizer.hasMoreTokens())
      {
        l.add(tokenizer.nextToken());
      }

      attributesReturned = Collections.unmodifiableList(l);
    }
  }



  /**
   * Retrieves the DN of the entry returned to the client.
   *
   * @return  The DN of the entry returned to the client, or {@code null} if it
   *          is not included in the log message.
   */
  @Nullable()
  public String getDN()
  {
    return dn;
  }



  /**
   * Retrieves the names of the attributes included in the entry that was
   * returned.
   *
   * @return  The names of the attributes included in the entry that was
   *          returned, or {@code null} if it is not included in the log
   *          message.
   */
  @Nullable()
  public List<String> getAttributesReturned()
  {
    return attributesReturned;
  }



  /**
   * Retrieves the OIDs of any response controls contained in the log message.
   *
   * @return  The OIDs of any response controls contained in the log message, or
   *          an empty list if it is not included in the log message.
   */
  @NotNull()
  public List<String> getResponseControlOIDs()
  {
    return responseControlOIDs;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public AccessLogMessageType getMessageType()
  {
    return AccessLogMessageType.ENTRY;
  }
}
