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



import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.OID;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.ssl.cert.CertMessages.*;



/**
 * This class provides an implementation of the CRL distribution points X.509
 * certificate extension as described in
 * <A HREF="https://www.ietf.org/rfc/rfc5280.txt">RFC 5280</A> section 4.2.1.13.
 * This can be used to provide information about the location of certificate
 * revocation lists (CRLs) that can be examined to check the validity of this
 * certificate.
 * <BR><BR>
 * The OID for this extension is 2.5.29.31 and the value has the following
 * encoding:
 * <PRE>
 *   CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
 *
 *   DistributionPoint ::= SEQUENCE {
 *        distributionPoint       [0]     DistributionPointName OPTIONAL,
 *        reasons                 [1]     ReasonFlags OPTIONAL,
 *        cRLIssuer               [2]     GeneralNames OPTIONAL }
 *
 *   DistributionPointName ::= CHOICE {
 *        fullName                [0]     GeneralNames,
 *        nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
 *
 *   ReasonFlags ::= BIT STRING {
 *        unused                  (0),
 *        keyCompromise           (1),
 *        cACompromise            (2),
 *        affiliationChanged      (3),
 *        superseded              (4),
 *        cessationOfOperation    (5),
 *        certificateHold         (6),
 *        privilegeWithdrawn      (7),
 *        aACompromise            (8) }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class CRLDistributionPointsExtension
       extends X509CertificateExtension
{
  /**
   * The OID (2.5.29.31) for CRL distribution points extensions.
   */
  public static final OID CRL_DISTRIBUTION_POINTS_OID = new OID("2.5.29.31");



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4710958813506834961L;



  // The list of CRL distribution points included in this extension.
  private final List<CRLDistributionPoint> crlDistributionPoints;



  /**
   * Creates a new CRL distribution points extension with the provided
   * information.
   *
   * @param  isCritical             Indicates whether this extension should be
   *                                considered critical.
   * @param  crlDistributionPoints  The distribution points to include in this
   *                                extension.  It must not be {@code null} or
   *                                empty.
   *
   * @throws  CertException  If a problem is encountered while trying to encode
   *                         the value for this extension.
   */
  CRLDistributionPointsExtension(final boolean isCritical,
       final List<CRLDistributionPoint> crlDistributionPoints)
       throws CertException
  {
    super(CRL_DISTRIBUTION_POINTS_OID, isCritical,
         encodeValue(crlDistributionPoints));

    this.crlDistributionPoints = crlDistributionPoints;
  }




  /**
   * Creates a new CRL distribution points extension from the provided generic
   * extension.
   *
   * @param  extension  The extension to decode as a CRL distribution points
   *                    extension.
   *
   * @throws  CertException  If the provided extension cannot be decoded as a
   *                         CRL distribution points extension.
   */
  CRLDistributionPointsExtension(final X509CertificateExtension extension)
       throws CertException
  {
    super(extension);

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(extension.getValue()).elements();
      final ArrayList<CRLDistributionPoint> dps =
           new ArrayList<>(elements.length);
      for (final ASN1Element e : elements)
      {
        dps.add(new CRLDistributionPoint(e));
      }

      crlDistributionPoints = Collections.unmodifiableList(dps);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CRL_DP_EXTENSION_CANNOT_PARSE.get(
                String.valueOf(extension), StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided information into a form for use as the value for this
   * extension.
   *
   * @param  crlDistributionPoints  The distribution points to include in this
   *                                extension.  It must not be {@code null} or
   *                                empty.
   *
   * @return  The encoded value.
   *
   * @throws  CertException  If a problem is encountered while trying to encode
   *                         this extension.
   */
  private static byte[] encodeValue(
               final List<CRLDistributionPoint> crlDistributionPoints)
          throws CertException
  {
    final ArrayList<ASN1Element> elements =
         new ArrayList<>(crlDistributionPoints.size());
    for (final CRLDistributionPoint p : crlDistributionPoints)
    {
      elements.add(p.encode());
    }

    return new ASN1Sequence(elements).encode();
  }



  /**
   * Retrieves the list of CRL distribution points included in this extension.
   *
   * @return  The list of CRL distribution points included in this extension.
   */
  public List<CRLDistributionPoint> getCRLDistributionPoints()
  {
    return crlDistributionPoints;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getExtensionName()
  {
    return INFO_CRL_DP_EXTENSION_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("CRLDistributionPointsExtension(oid='");
    buffer.append(getOID());
    buffer.append("', isCritical=");
    buffer.append(isCritical());
    buffer.append(", distributionPoints={");

    final Iterator<CRLDistributionPoint> iterator =
         crlDistributionPoints.iterator();
    while (iterator.hasNext())
    {
      iterator.next().toString(buffer);
      if (iterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("})");
  }
}
