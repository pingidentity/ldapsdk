/*
 * Copyright 2010-2015 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015 UnboundID Corp.
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
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class is part of the Commercial Edition of the UnboundID
 *   LDAP SDK for Java.  It is not available for use in applications that
 *   include only the Standard Edition of the LDAP SDK, and is not supported for
 *   use in conjunction with non-UnboundID products.
 * </BLOCKQUOTE>
 * This class provides an implementation of a changelog batch starting point
 * which may be used to start a batch of changes at the end of the changelog.
 * The first change of the batch will be the next change processed on any of the
 * servers in the replication topology.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class EndOfChangelogStartingPoint
       extends ChangelogBatchStartingPoint
{
  /**
   * The BER type to use for the ASN.1 element used to encode this starting
   * point.
   */
  static final byte TYPE = (byte) 0x83;



  /**
   * The pre-encoded representation of this changelog batch starting point.
   */
  private static final ASN1Null ENCODED_ELEMENT = new ASN1Null(TYPE);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3391952489079984126L;



  /**
   * Creates a new instance of this changelog batch starting point.
   */
  public EndOfChangelogStartingPoint()
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
    buffer.append("EndOfChangelogStartingPoint()");
  }
}
