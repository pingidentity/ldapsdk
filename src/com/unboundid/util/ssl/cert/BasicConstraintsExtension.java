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



import java.util.ArrayList;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Constants;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1Sequence;
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
 * This class provides an implementation of the basic constraints X.509
 * certificate extension as described in
 * <A HREF="https://www.ietf.org/rfc/rfc5280.txt">RFC 5280</A> section 4.2.1.9.
 * This can be used to indicate whether a certificate is a certification
 * authority (CA), and the maximum depth of certification paths that include
 * this certificate.
 * <BR><BR>
 * The OID for this extension is 2.5.29.19 and the value has the following
 * encoding:
 * <PRE>
 *   BasicConstraints ::= SEQUENCE {
 *        cA                      BOOLEAN DEFAULT FALSE,
 *        pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class BasicConstraintsExtension
       extends X509CertificateExtension
{
  /**
   * The OID (2.5.29.19) for basic constraints extensions.
   */
  @NotNull public static final OID BASIC_CONSTRAINTS_OID = new OID("2.5.29.19");



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7597324354728536247L;



  // Indicates whether the certificate is a certification authority.
  private final boolean isCA;

  // The path length constraint for paths that include the certificate.
  @Nullable private final Integer pathLengthConstraint;



  /**
   * Creates a new basic constraints extension from the provided information.
   *
   * @param  isCritical            Indicates whether this extension should be
   *                               considered critical.
   * @param  isCA                  Indicates whether the associated certificate
   *                               is a certification authority.
   * @param  pathLengthConstraint  The path length constraint for paths that
   *                               include the certificate.  This may be
   *                               {@code null} if it should not be included in
   *                               the extension.
   */
  BasicConstraintsExtension(final boolean isCritical, final boolean isCA,
                            @Nullable final Integer pathLengthConstraint)
  {
    super(BASIC_CONSTRAINTS_OID, isCritical,
         encodeValue(isCA, pathLengthConstraint));

    this.isCA = isCA;
    this.pathLengthConstraint = pathLengthConstraint;
  }



  /**
   * Creates a new basic constraints extension from the provided generic
   * extension.
   *
   * @param  extension  The extension to decode as a basic constraints
   *                    extension.
   *
   * @throws  CertException  If the provided extension cannot be decoded as a
   *                         basic constraints extension.
   */
  BasicConstraintsExtension(@NotNull final X509CertificateExtension extension)
       throws CertException
  {
    super(extension);

    try
    {
      boolean ca = false;
      Integer lengthConstraint = null;
      for (final ASN1Element e :
           ASN1Sequence.decodeAsSequence(extension.getValue()).elements())
      {
        switch (e.getType())
        {
          case ASN1Constants.UNIVERSAL_BOOLEAN_TYPE:
            ca = e.decodeAsBoolean().booleanValue();
            break;
          case ASN1Constants.UNIVERSAL_INTEGER_TYPE:
            lengthConstraint = e.decodeAsInteger().intValue();
            break;
        }
      }

      isCA = ca;
      pathLengthConstraint = lengthConstraint;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_BASIC_CONSTRAINTS_EXTENSION_CANNOT_PARSE.get(
                String.valueOf(extension), StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided information into a value for this extension.
   *
   * @param  isCA                  Indicates whether the associated certificate
   *                               is a certification authority.
   * @param  pathLengthConstraint  The path length constraint for paths that
   *                               include the certificate.  This may be
   *                               {@code null} if it should not be included in
   *                               the extension.
   *
   * @return  The encoded extension value.
   */
  @NotNull()
  private static byte[] encodeValue(final boolean isCA,
                             @Nullable final Integer pathLengthConstraint)
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(2);
    if (isCA)
    {
      elements.add(new ASN1Boolean(isCA));
    }

    if (pathLengthConstraint != null)
    {
      elements.add(new ASN1Integer(pathLengthConstraint));
    }

    return new ASN1Sequence(elements).encode();
  }


  /**
   * Indicates whether the associated certificate is a certification authority
   * (that is, can be used to sign other certificates).
   *
   * @return  {@code true} if the associated certificate is a certification
   *          authority, or {@code false} if not.
   */
  public boolean isCA()
  {
    return isCA;
  }



  /**
   * Retrieves the path length constraint for the associated certificate, if
   * defined.  If {@link #isCA()} returns {@code true} and this method returns
   * a non-{@code null} value, then any certificate chain that includes the
   * associated certificate should not be trusted if the chain contains more
   * than this number of certificates.
   *
   * @return  The path length constraint for the associated certificate, or
   *          {@code null} if no path length constraint is defined.
   */
  @Nullable()
  public Integer getPathLengthConstraint()
  {
    return pathLengthConstraint;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtensionName()
  {
    return INFO_BASIC_CONSTRAINTS_EXTENSION_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("BasicConstraintsExtension(oid='");
    buffer.append(getOID());
    buffer.append("', isCritical=");
    buffer.append(isCritical());
    buffer.append(", isCA=");
    buffer.append(isCA);

    if (pathLengthConstraint != null)
    {
      buffer.append(", pathLengthConstraint=");
      buffer.append(pathLengthConstraint);
    }

    buffer.append(')');
  }
}
