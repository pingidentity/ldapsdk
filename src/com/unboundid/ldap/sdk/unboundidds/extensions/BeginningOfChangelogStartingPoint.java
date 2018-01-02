/*
 * Copyright 2010-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Null;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an implementation of a changelog batch starting point
 * which may be used to start a batch of changes at the first change available
 * in the changelogs of all servers in the replication topology.
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
public final class BeginningOfChangelogStartingPoint
       extends ChangelogBatchStartingPoint
{
  /**
   * The BER type to use for the ASN.1 element used to encode this starting
   * point.
   */
  static final byte TYPE = (byte) 0x82;



  /**
   * The pre-encoded representation of this changelog batch starting point.
   */
  private static final ASN1Null ENCODED_ELEMENT = new ASN1Null(TYPE);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 8048301335476843820L;



  /**
   * Creates a new instance of this changelog batch starting point.
   */
  public BeginningOfChangelogStartingPoint()
  {
    // No implementation is required.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ASN1Element encode()
  {
    return ENCODED_ELEMENT;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("BeginningOfChangelogStartingPoint()");
  }
}
