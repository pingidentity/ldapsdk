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
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides an implementation of a changelog batch starting point
 * which may be used to start a batch of changes at a change identified by a
 * replication CSN.  The first change of the batch will be the change with this
 * CSN.
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
public final class ResumeWithCSNStartingPoint
       extends ChangelogBatchStartingPoint
{
  /**
   * The BER type to use for the ASN.1 element used to encode this starting
   * point.
   */
  static final byte TYPE = (byte) 0x81;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5205334877324505765L;



  // The replication CSN which may be used to define the starting point for the
  // changelog batch request.
  private final String csn;



  /**
   * Creates a new instance of this changelog batch starting point using the
   * provided replication CSN.
   *
   * @param  csn  The replication CSN which may be used to define the starting
   *              point for the get changelog batch request.  It must not be
   *              {@code null}.
   */
  public ResumeWithCSNStartingPoint(final String csn)
  {
    Validator.ensureNotNull(csn);

    this.csn = csn;
  }



  /**
   * Retrieves the replication CSN which may be used to define the starting
   * point for the get changelog batch request.
   *
   * @return  The replication CSN which may be used to define the starting point
   *          for the get changelog batch request.
   */
  public String getCSN()
  {
    return csn;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ASN1Element encode()
  {
    return new ASN1OctetString(TYPE, csn);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("ResumeWithCSNStartingPoint(csn='");
    buffer.append(csn);
    buffer.append("')");
  }
}
