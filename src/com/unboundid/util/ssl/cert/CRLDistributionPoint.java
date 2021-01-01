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



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.Set;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1ObjectIdentifier;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1Set;
import com.unboundid.asn1.ASN1UTF8String;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.OID;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.ssl.cert.CertMessages.*;



/**
 * This class implements a data structure that provides information about a
 * CRL distribution point for use in conjunction with the
 * {@link CRLDistributionPointsExtension}.  A CRL distribution point has the
 * following ASN.1 encoding:
 * <PRE>
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
public final class CRLDistributionPoint
       implements Serializable
{
  /**
   * The DER type for the distribution point element in the value sequence.
   */
  private static final byte TYPE_DISTRIBUTION_POINT = (byte) 0xA0;



  /**
   * The DER type for the reasons element in the value sequence.
   */
  private static final byte TYPE_REASONS = (byte) 0x81;



  /**
   * The DER type for the CRL issuer element in the value sequence.
   */
  private static final byte TYPE_CRL_ISSUER = (byte) 0xA2;



  /**
   * The DER type for the distribution point name element in the distribution
   * point CHOICE element.
   */
  private static final byte TYPE_FULL_NAME = (byte) 0xA0;



  /**
   * The DER type for the name relative to CRL issuer element in the
   * distribution point CHOICE element.
   */
  private static final byte TYPE_NAME_RELATIVE_TO_CRL_ISSUER = (byte) 0xA1;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8461308509960278714L;



  // The full set of names for the entity that signs the CRL.
  @Nullable private final GeneralNames crlIssuer;

  // The full set of names for this CRL distribution point.
  @Nullable private final GeneralNames fullName;

  // The name of the distribution point relative to the CRL issuer.
  @Nullable private final RDN nameRelativeToCRLIssuer;

  // The set of reasons that the CRL distribution point may revoke a
  // certificate.
  @NotNull private final Set<CRLDistributionPointRevocationReason>
       revocationReasons;



  /**
   * Creates a new CRL distribution point with the provided information.
   *
   * @param  fullName           The full name for the CRL distribution point.
   *                            This may be {@code null} if it should not be
   *                            included.
   * @param  revocationReasons  The set of reasons that the CRL distribution
   *                            point may revoke a certificate.  This may be
   *                            {@code null} if all of the defined reasons
   *                            should be considered valid.
   * @param  crlIssuer          The full name for the entity that signs the CRL.
   */
  CRLDistributionPoint(@Nullable final GeneralNames fullName,
       @Nullable final Set<CRLDistributionPointRevocationReason>
            revocationReasons,
       @Nullable final GeneralNames crlIssuer)
  {
    this.fullName = fullName;
    this.crlIssuer = crlIssuer;

    nameRelativeToCRLIssuer = null;

    if (revocationReasons == null)
    {
      this.revocationReasons = Collections.unmodifiableSet(EnumSet.allOf(
           CRLDistributionPointRevocationReason.class));
    }
    else
    {
      this.revocationReasons = Collections.unmodifiableSet(revocationReasons);
    }
  }



  /**
   * Creates a new CRL distribution point with the provided information.
   *
   * @param  nameRelativeToCRLIssuer  The name of the distribution point
   *                                  relative to that of the CRL issuer.  This
   *                                  may be {@code null} if it should not be
   *                                  included.
   * @param  revocationReasons        The set of reasons that the CRL
   *                                  distribution point may revoke a
   *                                  certificate.  This may be {@code null} if
   *                                  all of the defined reasons should be
   *                                  considered valid.
   * @param  crlIssuer                The full name for the entity that signs
   *                                  the CRL.
   */
  CRLDistributionPoint(@Nullable final RDN nameRelativeToCRLIssuer,
       @Nullable final Set<CRLDistributionPointRevocationReason>
            revocationReasons,
       @Nullable final GeneralNames crlIssuer)
  {
    this.nameRelativeToCRLIssuer = nameRelativeToCRLIssuer;
    this.crlIssuer = crlIssuer;

    fullName = null;

    if (revocationReasons == null)
    {
      this.revocationReasons = Collections.unmodifiableSet(EnumSet.allOf(
           CRLDistributionPointRevocationReason.class));
    }
    else
    {
      this.revocationReasons = Collections.unmodifiableSet(revocationReasons);
    }
  }



  /**
   * Creates a new CLR distribution point object that is decoded from the
   * provided ASN.1 element.
   *
   * @param  element  The element to decode as a CRL distribution point.
   *
   * @throws  CertException  If the provided element cannot be decoded as a CRL
   *                         distribution point.
   */
  CRLDistributionPoint(@NotNull final ASN1Element element)
       throws CertException
  {
    try
    {
      GeneralNames dpFullName = null;
      GeneralNames issuer = null;
      RDN dpRDN = null;
      Set<CRLDistributionPointRevocationReason> reasons =
           EnumSet.allOf(CRLDistributionPointRevocationReason.class);

      for (final ASN1Element e : element.decodeAsSequence().elements())
      {
        switch (e.getType())
        {
          case TYPE_DISTRIBUTION_POINT:
            final ASN1Element innerElement = ASN1Element.decode(e.getValue());
            switch (innerElement.getType())
            {
              case TYPE_FULL_NAME:
                dpFullName = new GeneralNames(innerElement);
                break;

              case TYPE_NAME_RELATIVE_TO_CRL_ISSUER:
                final Schema schema = Schema.getDefaultStandardSchema();
                final ASN1Element[] attributeSetElements =
                     innerElement.decodeAsSet().elements();
                final String[] attributeNames =
                     new String[attributeSetElements.length];
                final byte[][] attributeValues =
                     new byte[attributeSetElements.length][];
                for (int j=0; j < attributeSetElements.length; j++)
                {
                  final ASN1Element[] attributeTypeAndValueElements =
                       attributeSetElements[j].decodeAsSequence().elements();
                  final OID attributeTypeOID = attributeTypeAndValueElements[0].
                       decodeAsObjectIdentifier().getOID();
                  final AttributeTypeDefinition attributeType =
                       schema.getAttributeType(attributeTypeOID.toString());
                  if (attributeType == null)
                  {
                    attributeNames[j] = attributeTypeOID.toString();
                  }
                  else
                  {
                    attributeNames[j] =
                         attributeType.getNameOrOID().toUpperCase();
                  }

                  attributeValues[j] = attributeTypeAndValueElements[1].
                       decodeAsOctetString().getValue();
                }

                dpRDN = new RDN(attributeNames, attributeValues, schema);
                break;

              default:
                throw new CertException(
                     ERR_CRL_DP_UNRECOGNIZED_NAME_ELEMENT_TYPE.get(
                          StaticUtils.toHex(innerElement.getType())));
            }
            break;

          case TYPE_REASONS:
            reasons = CRLDistributionPointRevocationReason.getReasonSet(
                 e.decodeAsBitString());
            break;

          case TYPE_CRL_ISSUER:
            issuer = new GeneralNames(e);
            break;
        }
      }

      fullName = dpFullName;
      nameRelativeToCRLIssuer = dpRDN;
      revocationReasons = Collections.unmodifiableSet(reasons);
      crlIssuer = issuer;
    }
    catch (final CertException e)
    {
      Debug.debugException(e);
      throw e;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CRL_DP_CANNOT_DECODE.get(StaticUtils.getExceptionMessage(e)), e);
    }
  }



  /**
   * Encodes this CRL distribution point to an ASN.1 element.
   *
   * @return  The encoded CRL distribution point.
   *
   * @throws  CertException  If a problem is encountered while encoding this
   *                         CRL distribution point.
   */
  @NotNull()
  ASN1Element encode()
       throws CertException
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(3);

    ASN1Element distributionPointElement = null;
    if (fullName != null)
    {
      distributionPointElement =
           new ASN1Element(TYPE_FULL_NAME, fullName.encode().getValue());
    }
    else if (nameRelativeToCRLIssuer != null)
    {
      final Schema schema;
      try
      {
        schema = Schema.getDefaultStandardSchema();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new CertException(
             ERR_CRL_DP_ENCODE_CANNOT_GET_SCHEMA.get(toString(),
                  String.valueOf(nameRelativeToCRLIssuer),
                  StaticUtils.getExceptionMessage(e)),
             e);
      }

      final String[] names = nameRelativeToCRLIssuer.getAttributeNames();
      final String[] values = nameRelativeToCRLIssuer.getAttributeValues();
      final ArrayList<ASN1Element> rdnElements = new ArrayList<>(names.length);
      for (int i=0; i < names.length; i++)
      {
        final AttributeTypeDefinition at = schema.getAttributeType(names[i]);
        if (at == null)
        {
          throw new CertException(ERR_CRL_DP_ENCODE_UNKNOWN_ATTR_TYPE.get(
               toString(), String.valueOf(nameRelativeToCRLIssuer), names[i]));
        }

        try
        {
          rdnElements.add(new ASN1Sequence(
               new ASN1ObjectIdentifier(at.getOID()),
               new ASN1UTF8String(values[i])));
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new CertException(
               ERR_CRL_DP_ENCODE_ERROR.get(toString(),
                    String.valueOf(nameRelativeToCRLIssuer),
                    StaticUtils.getExceptionMessage(e)),
               e);
        }
      }

      distributionPointElement =
           new ASN1Set(TYPE_NAME_RELATIVE_TO_CRL_ISSUER, rdnElements);
    }

    if (distributionPointElement != null)
    {
      elements.add(new ASN1Element(TYPE_DISTRIBUTION_POINT,
           distributionPointElement.encode()));
    }

    if (! revocationReasons.equals(EnumSet.allOf(
         CRLDistributionPointRevocationReason.class)))
    {
      elements.add(CRLDistributionPointRevocationReason.toBitString(
           TYPE_REASONS, revocationReasons));
    }

    if (crlIssuer != null)
    {
      elements.add(new ASN1Element(TYPE_CRL_ISSUER,
           crlIssuer.encode().getValue()));
    }

    return new ASN1Sequence(elements);
  }



  /**
   * Retrieves the full set of names for this CRL distribution point, if
   * available.
   *
   * @return  The full set of names for this CRL distribution point, or
   *          {@code null} if it was not included in the extension.
   */
  @Nullable()
  public GeneralNames getFullName()
  {
    return fullName;
  }



  /**
   * Retrieves the name relative to the CRL issuer for this CRL distribution
   * point, if available.
   *
   * @return  The name relative to the CRL issuer for this CRL distribution
   *          point, or {@code null} if it was not included in the extension.
   */
  @Nullable()
  public RDN getNameRelativeToCRLIssuer()
  {
    return nameRelativeToCRLIssuer;
  }



  /**
   * Retrieves a set of potential reasons that the CRL distribution point may
   * list a certificate as revoked.
   *
   * @return  A set of potential reasons that the CRL distribution point may
   *          list a certificate as revoked.
   */
  @NotNull()
  public Set<CRLDistributionPointRevocationReason>
              getPotentialRevocationReasons()
  {
    return revocationReasons;
  }



  /**
   * Retrieves the full set of names for the CRL issuer, if available.
   *
   * @return  The full set of names for the CRL issuer, or {@code null} if it
   *          was not included in the extension.
   */
  @Nullable()
  public GeneralNames getCRLIssuer()
  {
    return crlIssuer;
  }



  /**
   * Retrieves a string representation of this CRL distribution point.
   *
   * @return  A string representation of this CRL distribution point.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this CRL distribution point to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("CRLDistributionPoint(");

    if (fullName != null)
    {
      buffer.append("fullName=");
      fullName.toString(buffer);
      buffer.append(", ");
    }
    else if (nameRelativeToCRLIssuer != null)
    {
      buffer.append("nameRelativeToCRLIssuer='");
      nameRelativeToCRLIssuer.toString(buffer);
      buffer.append("', ");
    }

    buffer.append("potentialRevocationReasons={");

    final Iterator<CRLDistributionPointRevocationReason> reasonIterator =
         revocationReasons.iterator();
    while (reasonIterator.hasNext())
    {
      buffer.append('\'');
      buffer.append(reasonIterator.next().getName());
      buffer.append('\'');

      if (reasonIterator.hasNext())
      {
        buffer.append(',');
      }
    }

    if (crlIssuer != null)
    {
      buffer.append(", crlIssuer=");
      crlIssuer.toString(buffer);
    }

    buffer.append('}');
  }
}
