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
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1ObjectIdentifier;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.OID;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.ssl.cert.CertMessages.*;



/**
 * This class provides an implementation of the extended key usage X.509
 * certificate extension as described in
 * <A HREF="https://www.ietf.org/rfc/rfc5280.txt">RFC 5280</A> section 4.2.1.12.
 * This can be used to provide an extensible list of OIDs that identify ways
 * that a certificate is intended to be used.
 * <BR><BR>
 * The OID for this extension is 2.5.29.37 and the value has the following
 * encoding:
 * <PRE>
 *   ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
 *
 *   KeyPurposeId ::= OBJECT IDENTIFIER
 * </PRE>
 *
 * @see  ExtendedKeyUsageID
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ExtendedKeyUsageExtension
       extends X509CertificateExtension
{
  /**
   * The OID (2.5.29.37) for extended key usage extensions.
   */
  @NotNull public static final OID EXTENDED_KEY_USAGE_OID =
       new OID("2.5.29.37");



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8208115548961483723L;



  // The set of key purpose IDs included in this extension.
  @NotNull private final Set<OID> keyPurposeIDs;



  /**
   * Creates a new extended key usage extension with the provided set of key
   * purpose IDs.
   *
   * @param  isCritical     Indicates whether this extension should be
   *                        considered critical.
   * @param  keyPurposeIDs  The set of key purpose IDs included in this
   *                        extension.  It must not be {@code null}.
   *
   * @throws  CertException  If a problem is encountered while encoding the
   *                         value for this extension.
   */
  ExtendedKeyUsageExtension(final boolean isCritical,
                            @NotNull final List<OID> keyPurposeIDs)
       throws CertException
  {
    super(EXTENDED_KEY_USAGE_OID, isCritical, encodeValue(keyPurposeIDs));

    this.keyPurposeIDs =
         Collections.unmodifiableSet(new LinkedHashSet<>(keyPurposeIDs));
  }



  /**
   * Creates a new extended key usage extension from the provided generic
   * extension.
   *
   * @param  extension  The extension to decode as an extended key usage
   *                    extension.
   *
   * @throws  CertException  If the provided extension cannot be decoded as an
   *                         extended key usage extension.
   */
  ExtendedKeyUsageExtension(@NotNull final X509CertificateExtension extension)
       throws CertException
  {
    super(extension);

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(extension.getValue()).elements();
      final LinkedHashSet<OID> ids =
           new LinkedHashSet<>(StaticUtils.computeMapCapacity(elements.length));
      for (final ASN1Element e : elements)
      {
        ids.add(e.decodeAsObjectIdentifier().getOID());
      }

      keyPurposeIDs = Collections.unmodifiableSet(ids);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_EXTENDED_KEY_USAGE_EXTENSION_CANNOT_PARSE.get(
                String.valueOf(extension), StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided information for use as the value of this extension.
   *
   * @param  keyPurposeIDs  The set of key purpose IDs included in this
   *                        extension.  It must not be {@code null}.
   *
   * @return  The encoded value for this extension.
   *
   * @throws  CertException  If a problem is encountered while encoding the
   *                         value.
   */
  @NotNull()
  private static byte[] encodeValue(@NotNull final List<OID> keyPurposeIDs)
          throws CertException
  {
    try
    {
      final ArrayList<ASN1Element> elements =
           new ArrayList<>(keyPurposeIDs.size());
      for (final OID oid : keyPurposeIDs)
      {
        elements.add(new ASN1ObjectIdentifier(oid));
      }

      return new ASN1Sequence(elements).encode();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_EXTENDED_KEY_USAGE_EXTENSION_CANNOT_ENCODE.get(
                String.valueOf(keyPurposeIDs),
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the OIDs of the key purpose values contained in this extension.
   * Some, all, or none of the OIDs contained in this extension may correspond
   * to values in the {@link ExtendedKeyUsageID} enumeration.
   *
   * @return  The OIDs of the key purpose values contained in this extension.
   */
  @NotNull()
  public Set<OID> getKeyPurposeIDs()
  {
    return keyPurposeIDs;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtensionName()
  {
    return INFO_EXTENDED_KEY_USAGE_EXTENSION_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ExtendedKeyUsageExtension(oid='");
    buffer.append(getOID());
    buffer.append("', isCritical=");
    buffer.append(isCritical());
    buffer.append(", keyPurposeIDs={");

    final Iterator<OID> oidIterator = keyPurposeIDs.iterator();
    while (oidIterator.hasNext())
    {
      buffer.append('\'');
      buffer.append(ExtendedKeyUsageID.getNameOrOID(oidIterator.next()));
      buffer.append('\'');

      if (oidIterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("})");
  }
}
