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
import com.unboundid.util.Base64;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides an implementation of a changelog batch starting point
 * which may be used to start a batch of changes at a point where a previous
 * batch ended.  The first change of the batch will be the change immediately
 * after the change associated with the provided token.
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
public final class ResumeWithTokenStartingPoint
       extends ChangelogBatchStartingPoint
{
  /**
   * The BER type to use for the ASN.1 element used to encode this starting
   * point.
   */
  static final byte TYPE = (byte) 0x80;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -101217605840282165L;



  // The content of the token to use when resuming a batch.
  private final ASN1OctetString resumeToken;



  /**
   * Creates a new instance of this changelog batch starting point using the
   * provided resume token.
   *
   * @param  resumeToken  The token which may be used to resume changelog access
   *                      at the point where it previously ended.  It must not
   *                      be {@code null}.
   */
  public ResumeWithTokenStartingPoint(final ASN1OctetString resumeToken)
  {
    Validator.ensureNotNull(resumeToken);

    this.resumeToken = resumeToken;
  }



  /**
   * Retrieves the token which may be used to resume changelog access at the
   * point where it previously ended.
   *
   * @return  The token which may be used to resume changelog access at the
   *          point where it previously ended.
   */
  public ASN1OctetString getResumeToken()
  {
    return resumeToken;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ASN1Element encode()
  {
    return new ASN1OctetString(TYPE, resumeToken.getValue());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("ResumeWithTokenStartingPoint(token='");
    Base64.encode(resumeToken.getValue(), buffer);
    buffer.append("')");
  }
}
