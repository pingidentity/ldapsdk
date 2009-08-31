/*
 * Copyright 2008-2009 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2009 UnboundID Corp.
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
package com.unboundid.ldap.matchingrules;



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an implementation of a matching rule that performs
 * byte-for-byte matching.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class OctetStringMatchingRule
       extends AcceptAllSimpleMatchingRule
{
  /**
   * The singleton instance that will be returned from the {@code getInstance}
   * method.
   */
  private static final OctetStringMatchingRule INSTANCE =
       new OctetStringMatchingRule();



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5655018388491186342L;



  /**
   * Creates a new instance of this octet string matching rule.
   */
  public OctetStringMatchingRule()
  {
    // No implementation is required.
  }



  /**
   * Retrieves a singleton instance of this matching rule.
   *
   * @return  A singleton instance of this matching rule.
   */
  public static OctetStringMatchingRule getInstance()
  {
    return INSTANCE;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ASN1OctetString normalize(final ASN1OctetString value)
  {
    return value;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ASN1OctetString normalizeSubstring(final ASN1OctetString value,
                                            final byte substringType)
  {
    return value;
  }
}
