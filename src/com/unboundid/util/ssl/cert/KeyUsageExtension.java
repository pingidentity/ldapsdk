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



import com.unboundid.asn1.ASN1BitString;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.OID;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.ssl.cert.CertMessages.*;



/**
 * This class provides an implementation of the key usage X.509 certificate
 * extension as described in
 * <A HREF="https://www.ietf.org/rfc/rfc5280.txt">RFC 5280</A> section 4.2.1.3.
 * This can be used to determine how the certificate's key is intended to be
 * used.
 * <BR><BR>
 * The OID for this extension is 2.5.29.15 and the value has the following
 * encoding:
 * <PRE>
 *   KeyUsage ::= BIT STRING {
 *        digitalSignature        (0),
 *        nonRepudiation          (1), -- recent editions of X.509 have
 *                             -- renamed this bit to contentCommitment
 *        keyEncipherment         (2),
 *        dataEncipherment        (3),
 *        keyAgreement            (4),
 *        keyCertSign             (5),
 *        cRLSign                 (6),
 *        encipherOnly            (7),
 *        decipherOnly            (8) }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class KeyUsageExtension
       extends X509CertificateExtension
{
  /**
   * The OID (2.5.29.15) for key usage extensions.
   */
  @NotNull public static final OID KEY_USAGE_OID = new OID("2.5.29.15");



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5453303403925657600L;



  // Indicates whether the crlSign bit is set.
  private final boolean crlSign;

  // Indicates whether the dataEncipherment bit is set.
  private final boolean dataEncipherment;

  // Indicates whether the decipherOnly bit is set.
  private final boolean decipherOnly;

  // Indicates whether the digitalSignature bit is set.
  private final boolean digitalSignature;

  // Indicates whether the encipherOnly bit is set.
  private final boolean encipherOnly;

  // Indicates whether the keyAgreement bit is set.
  private final boolean keyAgreement;

  // Indicates whether the keyCertSign bit is set.
  private final boolean keyCertSign;

  // Indicates whether the keyEncipherment bit is set.
  private final boolean keyEncipherment;

  // Indicates whether the nonRepudiation bit is set.
  private final boolean nonRepudiation;



  /**
   * Creates a new key usage extension with the provided information.
   *
   * @param  isCritical        Indicates whether this extension should be
   *                           considered critical.
   * @param  digitalSignature  Indicates whether the digitalSignature bit should
   *                           be set.
   * @param  nonRepudiation    Indicates whether the nonRepudiation bit should
   *                           be set.
   * @param  keyEncipherment   Indicates whether the keyEncipherment bit should
   *                           be set.
   * @param  dataEncipherment  Indicates whether the dataEncipherment bit should
   *                           be set.
   * @param  keyAgreement      Indicates whether the keyAgreement bit should be
   *                           set.
   * @param  keyCertSign       Indicates whether the keyCertSign bit should be
   *                           set.
   * @param  crlSign           Indicates whether the crlSign bit should be set.
   * @param  encipherOnly      Indicates whether the encipherOnly bit should be
   *                           set.
   * @param  decipherOnly      Indicates whether the decipherOnly bit should be
   *                           set.
   */
  KeyUsageExtension(final boolean isCritical, final boolean digitalSignature,
                    final boolean nonRepudiation, final boolean keyEncipherment,
                    final boolean dataEncipherment, final boolean keyAgreement,
                    final boolean keyCertSign, final boolean crlSign,
                    final boolean encipherOnly, final boolean decipherOnly)
  {
    super(KEY_USAGE_OID, isCritical,
         new ASN1BitString(digitalSignature, nonRepudiation, keyEncipherment,
              dataEncipherment, keyAgreement, keyCertSign, crlSign,
              encipherOnly, decipherOnly).encode());

    this.digitalSignature = digitalSignature;
    this.nonRepudiation = nonRepudiation;
    this.keyEncipherment = keyEncipherment;
    this.dataEncipherment = dataEncipherment;
    this.keyAgreement = keyAgreement;
    this.keyCertSign = keyCertSign;
    this.crlSign = crlSign;
    this.encipherOnly = encipherOnly;
    this.decipherOnly = decipherOnly;
  }



  /**
   * Creates a new key usage extension from the provided generic extension.
   *
   * @param  extension  The extension to decode as a key usage extension.
   *
   * @throws  CertException  If the provided extension cannot be decoded as a
   *                         key usage extension.
   */
  KeyUsageExtension(@NotNull final X509CertificateExtension extension)
       throws CertException
  {
    super(extension);

    try
    {
      final ASN1BitString valueBitString =
           ASN1BitString.decodeAsBitString(extension.getValue());
      final boolean[] bits = valueBitString.getBits();

      digitalSignature = ((bits.length > 0) && bits[0]);
      nonRepudiation = ((bits.length > 1) && bits[1]);
      keyEncipherment = ((bits.length > 2) && bits[2]);
      dataEncipherment = ((bits.length > 3) && bits[3]);
      keyAgreement = ((bits.length > 4) && bits[4]);
      keyCertSign = ((bits.length > 5) && bits[5]);
      crlSign = ((bits.length > 6) && bits[6]);
      encipherOnly = ((bits.length > 7) && bits[7]);
      decipherOnly = ((bits.length > 8) && bits[8]);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_KEY_USAGE_EXTENSION_CANNOT_PARSE.get(
                String.valueOf(extension), StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Indicates whether the digital signature bit is set.  If {@code true}, then
   * the key may be used for verifying digital signatures (other than signatures
   * on certificates or CRLs, as those usages are covered by the
   * {@link #isKeyCertSignBitSet()} and {@link #isCRLSignBitSet()} methods,
   * respectively).
   *
   * @return  {@code true} if the digital signature bit is set, or {@code false}
   *          if not.
   */
  public boolean isDigitalSignatureBitSet()
  {
    return digitalSignature;
  }



  /**
   * Indicates whether the non-repudiation bit is set.  If {@code true}, then
   * the key may be used to prevent someone from denying the authenticity of a
   * digital signature generated with the key.
   *
   * @return  {@code true} if the non-repudiation bit is set, or {@code false}
   *          if not.
   */
  public boolean isNonRepudiationBitSet()
  {
    return nonRepudiation;
  }



  /**
   * Indicates whether the key encipherment bit is set.  If {@code true}, then
   * the public key may be used for encrypting other private keys or secret keys
   * (for example, to protect the keys while they are being transported).
   *
   * @return  {@code true} if the key encipherment bit is set, or {@code false}
   *          if not.
   */
  public boolean isKeyEnciphermentBitSet()
  {
    return keyEncipherment;
  }



  /**
   * Indicates whether the data encipherment bit is set.  If {@code true}, then
   * the public key may be used for encrypting arbitrary data without the need
   * for a symmetric cipher.
   *
   * @return  {@code true} if the data encipherment bit is set, or {@code false}
   *          if not.
   */
  public boolean isDataEnciphermentBitSet()
  {
    return dataEncipherment;
  }



  /**
   * Indicates whether the key agreement bit is set.  If {@code true}, then
   * the public key may be used for key agreement processing.
   *
   * @return  {@code true} if the key agreement bit is set, or {@code false} if
   *          not.
   */
  public boolean isKeyAgreementBitSet()
  {
    return keyAgreement;
  }



  /**
   * Indicates whether the key cert sign bit is set.  If {@code true}, then the
   * public key may be used for verifying certificate signatures.
   *
   * @return  {@code true} if the CRL sign bit is set, or {@code false} if not.
   */
  public boolean isKeyCertSignBitSet()
  {
    return keyCertSign;
  }



  /**
   * Indicates whether the CRL sign bit is set.  If {@code true}, then the
   * public key may be used for verifying certificate revocation list (CRL)
   * signatures.
   *
   * @return  {@code true} if the CRL sign bit is set, or {@code false} if not.
   */
  public boolean isCRLSignBitSet()
  {
    return crlSign;
  }



  /**
   * Indicates whether the encipher only bit is set.  If {@code true}, and if
   * the {@link #isKeyAgreementBitSet()} is also {@code true}, then the public
   * key may be used only for enciphering data when performing key agreement.
   *
   * @return  {@code true} if the encipher only bit is set, or {@code false} if
   *          not.
   */
  public boolean isEncipherOnlyBitSet()
  {
    return encipherOnly;
  }



  /**
   * Indicates whether the decipher only bit is set.  If {@code true}, and if
   * the {@link #isKeyAgreementBitSet()} is also {@code true}, then the public
   * key may be used only for deciphering data when performing key agreement.
   *
   * @return  {@code true} if the decipher only bit is set, or {@code false} if
   *          not.
   */
  public boolean isDecipherOnlyBitSet()
  {
    return decipherOnly;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtensionName()
  {
    return INFO_KEY_USAGE_EXTENSION_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("KeyUsageExtension(oid='");
    buffer.append(getOID());
    buffer.append("', isCritical=");
    buffer.append(isCritical());
    buffer.append(", digitalSignature=");
    buffer.append(digitalSignature);
    buffer.append(", nonRepudiation=");
    buffer.append(nonRepudiation);
    buffer.append(", keyEncipherment=");
    buffer.append(keyEncipherment);
    buffer.append(", dataEncipherment=");
    buffer.append(dataEncipherment);
    buffer.append(", keyAgreement=");
    buffer.append(keyAgreement);
    buffer.append(", keyCertSign=");
    buffer.append(keyCertSign);
    buffer.append(", clrSign=");
    buffer.append(crlSign);
    buffer.append(", encipherOnly=");
    buffer.append(encipherOnly);
    buffer.append(", decipherOnly=");
    buffer.append(decipherOnly);
    buffer.append(')');
  }
}
