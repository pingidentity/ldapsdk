/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.protocol;



import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1StreamReaderSequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ModifyDNRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.protocol.ProtocolMessages.*;



/**
 * This class provides an implementation of an LDAP modify DN request protocol
 * op.
 */
@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ModifyDNRequestProtocolOp
       implements ProtocolOp
{
  /**
   * The BER type for the newSuperior element.
   */
  public static final byte TYPE_NEW_SUPERIOR = (byte) 0x80;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7514385089303489375L;



  // The deleteOldRDN flag for this modify DN request.
  private final boolean deleteOldRDN;

  // The entry DN for this modify DN request.
  @NotNull private final String dn;

  // The new RDN for this modify DN request.
  @NotNull private final String newRDN;

  // The new superior DN for this modify DN request.
  @Nullable private final String newSuperiorDN;



  /**
   * Creates a new modify DN request protocol op with the provided information.
   *
   * @param  dn             The entry DN for this modify DN request.
   * @param  newRDN         The new RDN for this modify DN request.
   * @param  deleteOldRDN   Indicates whether to delete the old RDN values.
   * @param  newSuperiorDN  The new superior DN for this modify DN request, or
   *                        {@code null} if there is none.
   */
  public ModifyDNRequestProtocolOp(@NotNull final String dn,
                                   @NotNull final String newRDN,
                                   final boolean deleteOldRDN,
                                   @Nullable final String newSuperiorDN)
  {
    this.dn            = dn;
    this.newRDN        = newRDN;
    this.deleteOldRDN  = deleteOldRDN;
    this.newSuperiorDN = newSuperiorDN;
  }



  /**
   * Creates a new modify DN request protocol op from the provided modify DN
   * request object.
   *
   * @param  request  The modify DN request object to use to create this
   *                  protocol op.
   */
  public ModifyDNRequestProtocolOp(@NotNull final ModifyDNRequest request)
  {
    dn            = request.getDN();
    newRDN        = request.getNewRDN();
    deleteOldRDN  = request.deleteOldRDN();
    newSuperiorDN = request.getNewSuperiorDN();
  }



  /**
   * Creates a new modify DN request protocol op read from the provided ASN.1
   * stream reader.
   *
   * @param  reader  The ASN.1 stream reader from which to read the modify DN
   *                 request protocol op.
   *
   * @throws  LDAPException  If a problem occurs while reading or parsing the
   *                         modify DN request.
   */
  ModifyDNRequestProtocolOp(@NotNull final ASN1StreamReader reader)
       throws LDAPException
  {
    try
    {
      final ASN1StreamReaderSequence opSequence = reader.beginSequence();

      dn           = reader.readString();
      newRDN       = reader.readString();
      deleteOldRDN = reader.readBoolean();

      if (opSequence.hasMoreElements())
      {
        newSuperiorDN = reader.readString();
      }
      else
      {
        newSuperiorDN = null;
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MODIFY_DN_REQUEST_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the target entry DN for this modify DN request.
   *
   * @return  The target entry DN for this modify DN request.
   */
  @NotNull()
  public String getDN()
  {
    return dn;
  }



  /**
   * Retrieves the new RDN for this modify DN request.
   *
   * @return  The new RDN for this modify DN request.
   */
  @NotNull()
  public String getNewRDN()
  {
    return newRDN;
  }



  /**
   * Indicates whether to delete the old RDN values from the target entry.
   *
   * @return  {@code true} if the old RDN values should be removed from the
   *          entry, or {@code false} if not.
   */
  public boolean deleteOldRDN()
  {
    return deleteOldRDN;
  }



  /**
   * Retrieves the new superior DN for this modify DN request, if any.
   *
   * @return  The new superior DN for this modify DN request, or {@code null} if
   *          there is none.
   */
  @Nullable()
  public String getNewSuperiorDN()
  {
    return newSuperiorDN;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ASN1Element encodeProtocolOp()
  {
    if (newSuperiorDN == null)
    {
      return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST,
           new ASN1OctetString(dn),
           new ASN1OctetString(newRDN),
           new ASN1Boolean(deleteOldRDN));
    }
    else
    {
      return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST,
           new ASN1OctetString(dn),
           new ASN1OctetString(newRDN),
           new ASN1Boolean(deleteOldRDN),
           new ASN1OctetString(TYPE_NEW_SUPERIOR, newSuperiorDN));
    }
  }



  /**
   * Decodes the provided ASN.1 element as a modify DN request protocol op.
   *
   * @param  element  The ASN.1 element to be decoded.
   *
   * @return  The decoded modify DN request protocol op.
   *
   * @throws  LDAPException  If the provided ASN.1 element cannot be decoded as
   *                         a modify DN request protocol op.
   */
  @NotNull()
  public static ModifyDNRequestProtocolOp decodeProtocolOp(
                     @NotNull final ASN1Element element)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(element).elements();
      final String dn =
           ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();
      final String newRDN =
           ASN1OctetString.decodeAsOctetString(elements[1]).stringValue();
      final boolean deleteOldRDN =
           ASN1Boolean.decodeAsBoolean(elements[2]).booleanValue();

      final String newSuperiorDN;
      if (elements.length > 3)
      {
        newSuperiorDN =
             ASN1OctetString.decodeAsOctetString(elements[3]).stringValue();
      }
      else
      {
        newSuperiorDN = null;
      }

      return new ModifyDNRequestProtocolOp(dn, newRDN, deleteOldRDN,
           newSuperiorDN);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MODIFY_DN_REQUEST_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void writeTo(@NotNull final ASN1Buffer buffer)
  {
    final ASN1BufferSequence opSequence =
         buffer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST);
    buffer.addOctetString(dn);
    buffer.addOctetString(newRDN);
    buffer.addBoolean(deleteOldRDN);

    if (newSuperiorDN != null)
    {
      buffer.addOctetString(TYPE_NEW_SUPERIOR, newSuperiorDN);
    }
    opSequence.end();
  }



  /**
   * Creates a modify DN request from this protocol op.
   *
   * @param  controls  The set of controls to include in the modify DN request.
   *                   It may be empty or {@code null} if no controls should be
   *                   included.
   *
   * @return  The modify DN request that was created.
   */
  @NotNull()
  public ModifyDNRequest toModifyDNRequest(@Nullable final Control... controls)
  {
    return new ModifyDNRequest(dn, newRDN, deleteOldRDN, newSuperiorDN,
         controls);
  }



  /**
   * Retrieves a string representation of this protocol op.
   *
   * @return  A string representation of this protocol op.
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
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ModifyDNRequestProtocolOp(dn='");
    buffer.append(dn);
    buffer.append("', newRDN='");
    buffer.append(newRDN);
    buffer.append("', deleteOldRDN=");
    buffer.append(deleteOldRDN);

    if (newSuperiorDN != null)
    {
      buffer.append(", newSuperiorDN='");
      buffer.append(newSuperiorDN);
      buffer.append('\'');
    }

    buffer.append(')');
  }
}
