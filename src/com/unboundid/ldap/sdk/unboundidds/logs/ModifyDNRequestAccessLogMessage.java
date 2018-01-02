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



import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about a log
 * message that may appear in the Directory Server access log about a modify DN
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
public class ModifyDNRequestAccessLogMessage
       extends OperationRequestAccessLogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1968625384801993253L;



  // Indicates whether to delete the old RDN value(s).
  private final Boolean deleteOldRDN;

  // The DN of the entry to rename.
  private final String dn;

  // The new RDN to use for the entry.
  private final String newRDN;

  // The new superior DN for the entry.
  private final String newSuperiorDN;



  /**
   * Creates a new modify DN request access log message from the provided
   * message string.
   *
   * @param  s  The string to be parsed as a modify DN request access log
   *            message.
   *
   * @throws  LogException  If the provided string cannot be parsed as a valid
   *                        log message.
   */
  public ModifyDNRequestAccessLogMessage(final String s)
         throws LogException
  {
    this(new LogMessage(s));
  }



  /**
   * Creates a new modify DN request access log message from the provided log
   * message.
   *
   * @param  m  The log message to be parsed as a modify DN request access log
   *            message.
   */
  public ModifyDNRequestAccessLogMessage(final LogMessage m)
  {
    super(m);

    dn            = getNamedValue("dn");
    newRDN        = getNamedValue("newRDN");
    deleteOldRDN  = getNamedValueAsBoolean("deleteOldRDN");
    newSuperiorDN = getNamedValue("newSuperior");
  }



  /**
   * Retrieves the DN of the entry to rename.
   *
   * @return  The DN of the entry to rename, or {@code null} if it is not
   *          included in the log message.
   */
  public final String getDN()
  {
    return dn;
  }



  /**
   * Retrieves the new RDN to use for the entry.
   *
   * @return  The new RDN to use for the entry, or {@code null} if it is not
   *          included in the log message.
   */
  public final String getNewRDN()
  {
    return newRDN;
  }



  /**
   * Indicates whether the old RDN value(s) should be removed from the entry.
   *
   * @return  {@code Boolean.TRUE} if the old RDN value(s) should be removed
   *          from the entry, {@code Boolean.FALSE} if the old RDN value(s)
   *          should be kept in the entry, or {@code null} if it is not included
   *          in the log message.
   */
  public final Boolean deleteOldRDN()
  {
    return deleteOldRDN;
  }



  /**
   * Retrieves the new superior DN to use for the entry.
   *
   * @return  The new superior DN to use for the entry, or {@code null} if it is
   *          not included in the log message.
   */
  public final String getNewSuperiorDN()
  {
    return newSuperiorDN;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public final AccessLogOperationType getOperationType()
  {
    return AccessLogOperationType.MODDN;
  }
}
