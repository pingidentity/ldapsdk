/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
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
  @NotNull private final String name;



  /**
   * Creates a CRL distribution point revocation reason value with the provided
   * information.
   *
   * @param  name         A human-readable name for this revocation reason.
   * @param  bitPosition  The bit string index of the bit that indicates whether
   *                      this reason applies.
   */
  CRLDistributionPointRevocationReason(@NotNull final String name,
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
  @NotNull()
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
  @NotNull()
  static Set<CRLDistributionPointRevocationReason>
              getReasonSet(@NotNull final ASN1BitString bitString)
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
  @NotNull()
  static ASN1BitString toBitString(final byte type,
              @NotNull final Set<CRLDistributionPointRevocationReason> reasons)
  {
    final CRLDistributionPointRevocationReason[] values = values();
    final boolean[] bits = new boolean[values.length];
    for (final CRLDistributionPointRevocationReason r : values)
    {
      bits[r.bitPosition] = reasons.contains(r);
    }

    return new ASN1BitString(type, bits);
  }



  /**
   * Retrieves the CRL distribution point revocation reason with the specified
   * name.
   *
   * @param  name  The name of the CRL distribution point revocation reason to
   *               retrieve.  It must not be {@code null}.
   *
   * @return  The requested CRL distribution point revocation reason, or
   *          {@code null} if no such reason is defined.
   */
  @Nullable()
  public static CRLDistributionPointRevocationReason
                     forName(@NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "unspecified":
        return UNSPECIFIED;
      case "keycompromise":
      case "key-compromise":
      case "key_compromise":
        return KEY_COMPROMISE;
      case "cacompromise":
      case "ca-compromise":
      case "ca_compromise":
        return CA_COMPROMISE;
      case "affiliationchanged":
      case "affiliation-changed":
      case "affiliation_changed":
        return AFFILIATION_CHANGED;
      case "superseded":
        return SUPERSEDED;
      case "cessationofoperation":
      case "cessation-of-operation":
      case "cessation_of_operation":
        return CESSATION_OF_OPERATION;
      case "certificatehold":
      case "certificate-hold":
      case "certificate_hold":
        return CERTIFICATE_HOLD;
      case "privilegewithdrawn":
      case "privilege-withdrawn":
      case "privilege_withdrawn":
        return PRIVILEGE_WITHDRAWN;
      case "aacompromise":
      case "aa-compromise":
      case "aa_compromise":
        return AA_COMPROMISE;
      default:
        return null;
    }
  }
}
