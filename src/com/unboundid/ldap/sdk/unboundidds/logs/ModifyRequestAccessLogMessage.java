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



import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.StringTokenizer;

import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about a log
 * message that may appear in the Directory Server access log about a modify
 * request received from a client.
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
@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class ModifyRequestAccessLogMessage
       extends OperationRequestAccessLogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8276481811479971408L;



  // The list of attributes to be modified.
  private final List<String> attributeNames;

  // The DN of the entry to modify.
  private final String dn;



  /**
   * Creates a new modify request access log message from the provided message
   * string.
   *
   * @param  s  The string to be parsed as a modify request access log message.
   *
   * @throws  LogException  If the provided string cannot be parsed as a valid
   *                        log message.
   */
  public ModifyRequestAccessLogMessage(final String s)
         throws LogException
  {
    this(new LogMessage(s));
  }



  /**
   * Creates a new modify request access log message from the provided log
   * message.
   *
   * @param  m  The log message to be parsed as a modify request access log
   *            message.
   */
  public ModifyRequestAccessLogMessage(final LogMessage m)
  {
    super(m);

    dn = getNamedValue("dn");

    final String attrs = getNamedValue("attrs");
    if (attrs == null)
    {
      attributeNames = null;
    }
    else
    {
      final ArrayList<String> l = new ArrayList<String>(10);
      final StringTokenizer tokenizer = new StringTokenizer(attrs, ",");
      while (tokenizer.hasMoreTokens())
      {
        l.add(tokenizer.nextToken());
      }

      attributeNames = Collections.unmodifiableList(l);
    }
  }



  /**
   * Retrieves the DN of the entry to modify.
   *
   * @return  The DN of the entry to modify, or {@code null} if it is not
   *          included in the log message.
   */
  public final String getDN()
  {
    return dn;
  }



  /**
   * Retrieves the names of the attributes to be modified.
   *
   * @return  The names of the attributes to be modified, or {@code null} if
   *          that is not included in the log message.
   */
  public final List<String> getAttributeNames()
  {
    return attributeNames;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public final AccessLogOperationType getOperationType()
  {
    return AccessLogOperationType.MODIFY;
  }
}
