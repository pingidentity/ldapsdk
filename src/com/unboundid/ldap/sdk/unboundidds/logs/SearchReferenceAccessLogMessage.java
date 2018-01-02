/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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



import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.StringTokenizer;

import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about a log
 * message that may appear in the Directory Server access log about a search
 * result reference returned to a client.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SearchReferenceAccessLogMessage
       extends SearchRequestAccessLogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4413555391780641502L;



  // The list of response control OIDs for the operation.
  private final List<String> responseControlOIDs;

  // The set of referral URLs returned.
  private final List<String> referralURLs;



  /**
   * Creates a new search result reference access log message from the provided
   * message string.
   *
   * @param  s  The string to be parsed as a search result reference access log
   *            message.
   *
   * @throws  LogException  If the provided string cannot be parsed as a valid
   *                        log message.
   */
  public SearchReferenceAccessLogMessage(final String s)
         throws LogException
  {
    this(new LogMessage(s));
  }



  /**
   * Creates a new search result reference access log message from the provided
   * log message.
   *
   * @param  m  The log message to be parsed as a search reference access log
   *            message.
   */
  public SearchReferenceAccessLogMessage(final LogMessage m)
  {
    super(m);

    final String refStr = getNamedValue("referralURLs");
    if ((refStr == null) || (refStr.length() == 0))
    {
      referralURLs = Collections.emptyList();
    }
    else
    {
      final LinkedList<String> refs = new LinkedList<String>();
      int startPos = 0;
      while (true)
      {
        final int commaPos = refStr.indexOf(",ldap", startPos);
        if (commaPos < 0)
        {
          refs.add(refStr.substring(startPos));
          break;
        }
        else
        {
          refs.add(refStr.substring(startPos, commaPos));
          startPos = commaPos+1;
        }
      }
      referralURLs = Collections.unmodifiableList(refs);
    }

    final String controlStr = getNamedValue("responseControls");
    if (controlStr == null)
    {
      responseControlOIDs = Collections.emptyList();
    }
    else
    {
      final LinkedList<String> controlList = new LinkedList<String>();
      final StringTokenizer t = new StringTokenizer(controlStr, ",");
      while (t.hasMoreTokens())
      {
        controlList.add(t.nextToken());
      }
      responseControlOIDs = Collections.unmodifiableList(controlList);
    }
  }



  /**
   * Retrieves the list of referral URLs returned to the client.
   *
   * @return  The list of referral URLs returned to the client, or an empty list
   *          if it is not included in the log message.
   */
  public List<String> getReferralURLs()
  {
    return referralURLs;
  }



  /**
   * Retrieves the OIDs of any response controls contained in the log message.
   *
   * @return  The OIDs of any response controls contained in the log message, or
   *          an empty list if it is not included in the log message.
   */
  public List<String> getResponseControlOIDs()
  {
    return responseControlOIDs;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public AccessLogMessageType getMessageType()
  {
    return AccessLogMessageType.REFERENCE;
  }
}
