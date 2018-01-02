/*
 * Copyright 2017-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2017-2018 Ping Identity Corporation
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
package com.unboundid.util.ssl.cert;



import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import com.unboundid.asn1.ASN1BitString;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines a set of reasons for which a CRL distribution point may
 * revoke a certificate.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum CRLDistributionPointRevocationReason
{
  /**
   * Indicates that a CRL distribution point may revoke a certificate for an
   * unspecified reason.
   */
  UNSPECIFIED("unspecified", 0),



  /**
   * Indicates that a CRL distribution point may revoke a certificate if the
   * certificate's private key may have been compromised.
   */
  KEY_COMPROMISE("keyCompromise", 1),



  /**
   * Indicates that a CRL distribution point may revoke a certificate if the
   * certificate issuer's private key may have been compromised.
   */
  CA_COMPROMISE("caCompromise", 2),



  /**
   * Indicates that a CRL distribution point may revoke a certificate if the
   * owner of a certificate is no longer affiliated with its issuer.
   */
  AFFILIATION_CHANGED("affiliationChanged", 3),



  /**
   * Indicates that a CRL distribution point may revoke a certificate if it has
   * been superseded by a newer certificate.
   */
  SUPERSEDED("superseded", 4),



  /**
   * Indicates that a CRL distribution point may revoke a certificate if the
   * certification authority is no longer in operation.
   */
  CESSATION_OF_OPERATION("cessationOfOperation", 5),



  /**
   * Indicates that a CRL distribution point may revoke a certificate if the
   * certificate has been put on hold.
   */
  CERTIFICATE_HOLD("certificateHold", 6),



  /**
   * Indicates that a CRL distribution point may revoke a certificate if one
   * or more of the privileges granted to the certificate have been withdrawn.
   */
  PRIVILEGE_WITHDRAWN("privilegeWithdrawn", 7),



  /**
   * Indicates that a CRL distribution point may revoke a certificate if an
   * associated attribute authority has been compromised.
   */
  AA_COMPROMISE("aaCompromise", 8);



  // The position of this revocation reason value in the bit string.
  private final int bitPosition;

  // A human-readable name for this revocation reason.
  private final String name;



  /**
   * Creates a CRL distribution point revocation reason value with the provided
   * information.
   *
   * @param  name         A human-readable name for this revocation reason.
   * @param  bitPosition  The bit string index of the bit that indicates whether
   *                      this reason applies.
   */
  CRLDistributionPointRevocationReason(final String name,
                                       final int bitPosition)
  {
    this.name = name;
    this.bitPosition = bitPosition;
  }



  /**
   * Retrieves a human-readable name for this CRL distribution point revocation
   * reason.
   *
   * @return  A human-readable name for this CRL distribution point revocation
   *          reason.
   */
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the bit string index of the bit that indicates whether this
   * reason applies.
   *
   * @return  The bit string index of the bit that indicates whether this reason
   *          applies.
   */
  int getBitPosition()
  {
    return bitPosition;
  }



  /**
   * Retrieves a set that contains all of the revocation reasons that are set in
   * the provided bit string.
   *
   * @param  bitString  The bit string to examine.
   *
   * @return  A set that contains all of the revocation reasons that are set in
   *          the provided bit string.
   */
  static Set<CRLDistributionPointRevocationReason>
              getReasonSet(final ASN1BitString bitString)
  {
    final boolean[] bits = bitString.getBits();

    final EnumSet<CRLDistributionPointRevocationReason> s =
         EnumSet.noneOf(CRLDistributionPointRevocationReason.class);
    for (final CRLDistributionPointRevocationReason r : values())
    {
      if ((bits.length > r.bitPosition) && bits[r.bitPosition])
      {
        s.add(r);
      }
    }

    return Collections.unmodifiableSet(s);
  }



  /**
   * Encodes the provided set of reasons to a bit string.
   *
   * @param  type     The DER to use for the bit string.
   * @param  reasons  The set of reasons to encode.
   *
   * @return  The bit string that represents the encoded set of reasons.
   */
  static ASN1BitString toBitString(final byte type,
              final Set<CRLDistributionPointRevocationReason> reasons)
  {
    final CRLDistributionPointRevocationReason[] values = values();
    final boolean[] bits = new boolean[values.length];
    for (final CRLDistributionPointRevocationReason r : values)
    {
      bits[r.bitPosition] = reasons.contains(r);
    }

    return new ASN1BitString(type, bits);
  }
}
