/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2018 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1StreamReaderSequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.protocol.ProtocolMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.Validator.*;



/**
 * This class provides an implementation of an LDAP modify request protocol op.
 */
@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ModifyRequestProtocolOp
       implements ProtocolOp
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6294739625253826184L;



  // The list of modifications for this modify request.
  private final List<Modification> modifications;

  // The entry DN for this modify request.
  private final String dn;



  /**
   * Creates a new modify request protocol op with the provided information.
   *
   * @param  dn             The entry DN for this modify request.
   * @param  modifications  The list of modifications to include in this modify
   *                        request.
   */
  public ModifyRequestProtocolOp(final String dn,
                                 final List<Modification> modifications)
  {
    this.dn            = dn;
    this.modifications = Collections.unmodifiableList(modifications);
  }



  /**
   * Creates a new modify request protocol op from the provided modify request
   * object.
   *
   * @param  request  The modify request object to use to create this protocol
   *                  op.
   */
  public ModifyRequestProtocolOp(final ModifyRequest request)
  {
    dn            = request.getDN();
    modifications = request.getModifications();
  }



  /**
   * Creates a new modify request protocol op read from the provided ASN.1
   * stream reader.
   *
   * @param  reader  The ASN.1 stream reader from which to read the modify
   *                 request protocol op.
   *
   * @throws  LDAPException  If a problem occurs while reading or parsing the
   *                         modify request.
   */
  ModifyRequestProtocolOp(final ASN1StreamReader reader)
       throws LDAPException
  {
    try
    {
      reader.beginSequence();
      dn = reader.readString();
      ensureNotNull(dn);

      final ArrayList<Modification> mods = new ArrayList<Modification>(5);
      final ASN1StreamReaderSequence modSequence = reader.beginSequence();
      while (modSequence.hasMoreElements())
      {
        mods.add(Modification.readFrom(reader));
      }

      modifications = Collections.unmodifiableList(mods);
    }
    catch (final LDAPException le)
    {
      debugException(le);
      throw le;
    }
    catch (final Exception e)
    {
      debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MODIFY_REQUEST_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }



  /**
   * Retrieves the target entry DN for this modify request.
   *
   * @return  The target entry DN for this modify request.
   */
  public String getDN()
  {
    return dn;
  }



  /**
   * Retrieves the list of modifications for this modify request.
   *
   * @return  The list of modifications for this modify request.
   */
  public List<Modification> getModifications()
  {
    return modifications;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ASN1Element encodeProtocolOp()
  {
    final ArrayList<ASN1Element> modElements =
         new ArrayList<ASN1Element>(modifications.size());
    for (final Modification m : modifications)
    {
      modElements.add(m.encode());
    }

    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST,
         new ASN1OctetString(dn),
         new ASN1Sequence(modElements));
  }



  /**
   * Decodes the provided ASN.1 element as a modify request protocol op.
   *
   * @param  element  The ASN.1 element to be decoded.
   *
   * @return  The decoded modify request protocol op.
   *
   * @throws  LDAPException  If the provided ASN.1 element cannot be decoded as
   *                         a modify request protocol op.
   */
  public static ModifyRequestProtocolOp decodeProtocolOp(
                                             final ASN1Element element)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(element).elements();
      final String dn =
           ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();

      final ASN1Element[] modElements =
           ASN1Sequence.decodeAsSequence(elements[1]).elements();
      final ArrayList<Modification> mods =
           new ArrayList<Modification>(modElements.length);
      for (final ASN1Element e : modElements)
      {
        mods.add(Modification.decode(ASN1Sequence.decodeAsSequence(e)));
      }

      return new ModifyRequestProtocolOp(dn, mods);
    }
    catch (final Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MODIFY_REQUEST_CANNOT_DECODE.get(getExceptionMessage(e)),
           e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void writeTo(final ASN1Buffer writer)
  {
    final ASN1BufferSequence opSequence =
         writer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST);
    writer.addOctetString(dn);

    final ASN1BufferSequence modSequence = writer.beginSequence();
    for (final Modification m : modifications)
    {
      m.writeTo(writer);
    }
    modSequence.end();
    opSequence.end();
  }



  /**
   * Creates a modify request from this protocol op.
   *
   * @param  controls  The set of controls to include in the modify request.
   *                   It may be empty or {@code null} if no controls should be
   *                   included.
   *
   * @return  The modify request that was created.
   */
  public ModifyRequest toModifyRequest(final Control... controls)
  {
    return new ModifyRequest(dn, modifications, controls);
  }



  /**
   * Retrieves a string representation of this protocol op.
   *
   * @return  A string representation of this protocol op.
   */
  @Override()
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
  public void toString(final StringBuilder buffer)
  {
    buffer.append("ModifyRequestProtocolOp(dn='");
    buffer.append(dn);
    buffer.append("', mods={");

    final Iterator<Modification> iterator = modifications.iterator();
    while (iterator.hasNext())
    {
      iterator.next().toString(buffer);
      if (iterator.hasNext())
      {
        buffer.append(',');
      }
    }

    buffer.append("})");
  }
}
