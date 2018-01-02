/*
 * Copyright 2014-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2014-2018 Ping Identity Corporation
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
package com.unboundid.asn1;



import javax.security.sasl.SaslClient;

import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class serves as a proxy that provides access to selected package-private
 * methods in classes in the {@code com.unboundid.asn1} package so that they may
 * be called by code in other packages within the LDAP SDK.  Neither this class
 * nor the methods it contains may be used outside of the LDAP SDK.
 */
@InternalUseOnly()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class InternalASN1Helper
{
  /**
   * Prevent this class from being instantiated.
   */
  private InternalASN1Helper()
  {
    // No implementation is required.
  }



  /**
   * Sets the SASL client for the provided ASN.1 stream reader.  This method is
   * intended for use as a helper for processing data that has been encoded some
   * form of SASL integrity or confidentiality, and should not be used for other
   * purposes.
   *
   * @param  asn1StreamReader  The ASN.1 stream reader for which to set the
   *                           SASL client.
   * @param  saslClient        The SASL client to set for the ASN.1 stream
   *                           reader.
   */
  @InternalUseOnly()
  public static void setSASLClient(final ASN1StreamReader asn1StreamReader,
                                   final SaslClient saslClient)
  {
    asn1StreamReader.setSASLClient(saslClient);
  }
}
