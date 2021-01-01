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



import java.io.InterruptedIOException;
import java.io.IOException;
import java.io.Serializable;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1StreamReaderSequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.InternalSDKHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.schema.Schema;
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
 * This class provides a data structure that may be used to represent LDAP
 * protocol messages.  Each LDAP message contains a message ID, a protocol op,
 * and an optional set of controls.
 */
@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPMessage
       implements Serializable
{
  /**
   * The BER type to use for the bind request protocol op.
   */
  public static final byte PROTOCOL_OP_TYPE_BIND_REQUEST = 0x60;



  /**
   * The BER type to use for the bind response protocol op.
   */
  public static final byte PROTOCOL_OP_TYPE_BIND_RESPONSE = 0x61;



  /**
   * The BER type to use for the unbind request protocol op.
   */
  public static final byte PROTOCOL_OP_TYPE_UNBIND_REQUEST = 0x42;



  /**
   * The BER type to use for the search request protocol op.
   */
  public static final byte PROTOCOL_OP_TYPE_SEARCH_REQUEST = 0x63;



  /**
   * The BER type to use for the search result entry protocol op.
   */
  public static final byte PROTOCOL_OP_TYPE_SEARCH_RESULT_ENTRY = 0x64;



  /**
   * The BER type to use for the search result reference protocol op.
   */
  public static final byte PROTOCOL_OP_TYPE_SEARCH_RESULT_REFERENCE = 0x73;



  /**
   * The BER type to use for the search result done protocol op.
   */
  public static final byte PROTOCOL_OP_TYPE_SEARCH_RESULT_DONE = 0x65;



  /**
   * The BER type to use for the modify request protocol op.
   */
  public static final byte PROTOCOL_OP_TYPE_MODIFY_REQUEST = 0x66;



  /**
   * The BER type to use for the modify response protocol op.
   */
  public static final byte PROTOCOL_OP_TYPE_MODIFY_RESPONSE = 0x67;



  /**
   * The BER type to use for the add request protocol op.
   */
  public static final byte PROTOCOL_OP_TYPE_ADD_REQUEST = 0x68;



  /**
   * The BER type to use for the add response protocol op.
   */
  public static final byte PROTOCOL_OP_TYPE_ADD_RESPONSE = 0x69;



  /**
   * The BER type to use for the delete request protocol op.
   */
  public static final byte PROTOCOL_OP_TYPE_DELETE_REQUEST = 0x4A;



  /**
   * The BER type to use for the delete response protocol op.
   */
  public static final byte PROTOCOL_OP_TYPE_DELETE_RESPONSE = 0x6B;



  /**
   * The BER type to use for the modify DN request protocol op.
   */
  public static final byte PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST = 0x6C;



  /**
   * The BER type to use for the modify DN response protocol op.
   */
  public static final byte PROTOCOL_OP_TYPE_MODIFY_DN_RESPONSE = 0x6D;



  /**
   * The BER type to use for the compare request protocol op.
   */
  public static final byte PROTOCOL_OP_TYPE_COMPARE_REQUEST = 0x6E;



  /**
   * The BER type to use for the compare response protocol op.
   */
  public static final byte PROTOCOL_OP_TYPE_COMPARE_RESPONSE = 0x6F;



  /**
   * The BER type to use for the abandon request protocol op.
   */
  public static final byte PROTOCOL_OP_TYPE_ABANDON_REQUEST = 0x50;



  /**
   * The BER type to use for the extended request protocol op.
   */
  public static final byte PROTOCOL_OP_TYPE_EXTENDED_REQUEST = 0x77;



  /**
   * The BER type to use for the extended response protocol op.
   */
  public static final byte PROTOCOL_OP_TYPE_EXTENDED_RESPONSE = 0x78;



  /**
   * The BER type to use for the intermediate response protocol op.
   */
  public static final byte PROTOCOL_OP_TYPE_INTERMEDIATE_RESPONSE = 0x79;



  /**
   * The BER type to use for the set of controls.
   */
  public static final byte MESSAGE_TYPE_CONTROLS = (byte) 0xA0;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 909272448857832592L;



  // The message ID for this LDAP message.
  private final int messageID;

  // The protocol op for this LDAP message.
  @NotNull private final ProtocolOp protocolOp;

  // The set of controls for this LDAP message.
  @NotNull private final List<Control> controls;



  /**
   * Creates a new LDAP message with the provided information.
   *
   * @param  messageID   The message ID for this LDAP message.
   * @param  protocolOp  The protocol op for this LDAP message.  It must not be
   *                     {@code null}.
   * @param  controls    The set of controls for this LDAP message.  It may be
   *                     {@code null} or empty if no controls are required.
   */
  public LDAPMessage(final int messageID, @NotNull final ProtocolOp protocolOp,
                     @Nullable final Control... controls)
  {
    this.messageID  = messageID;
    this.protocolOp = protocolOp;

    if (controls == null)
    {
      this.controls = Collections.emptyList();
    }
    else
    {
      this.controls = Collections.unmodifiableList(Arrays.asList(controls));
    }
  }



  /**
   * Creates a new LDAP message with the provided information.
   *
   * @param  messageID   The message ID for this LDAP message.
   * @param  protocolOp  The protocol op for this LDAP message.  It must not be
   *                     {@code null}.
   * @param  controls    The set of controls for this LDAP message.  It may be
   *                     {@code null} or empty if no controls are required.
   */
  public LDAPMessage(final int messageID, @NotNull final ProtocolOp protocolOp,
                     @Nullable final List<Control> controls)
  {
    this.messageID  = messageID;
    this.protocolOp = protocolOp;

    if (controls == null)
    {
      this.controls = Collections.emptyList();
    }
    else
    {
      this.controls = Collections.unmodifiableList(controls);
    }
  }



  /**
   * Retrieves the message ID for this LDAP message.
   *
   * @return  The message ID for this LDAP message.
   */
  public int getMessageID()
  {
    return messageID;
  }



  /**
   * Retrieves the protocol op for this LDAP message.
   *
   * @return  The protocol op for this LDAP message.
   */
  @NotNull()
  public ProtocolOp getProtocolOp()
  {
    return protocolOp;
  }



  /**
   * Retrieves the BER type for the protocol op contained in this LDAP message.
   *
   * @return  The BER type for the protocol op contained in this LDAP message.
   */
  public byte getProtocolOpType()
  {
    return protocolOp.getProtocolOpType();
  }



  /**
   * Retrieves the abandon request protocol op from this LDAP message.  This may
   * only be used if this LDAP message was obtained using the {@link #readFrom}
   * method.
   *
   * @return  The abandon request protocol op from this LDAP message.
   *
   * @throws  ClassCastException  If the protocol op for this LDAP message is
   *                              not an abandon request protocol op.
   */
  @NotNull()
  public AbandonRequestProtocolOp getAbandonRequestProtocolOp()
         throws ClassCastException
  {
    return (AbandonRequestProtocolOp) protocolOp;
  }



  /**
   * Retrieves the add request protocol op from this LDAP message.  This may
   * only be used if this LDAP message was obtained using the {@link #readFrom}
   * method.
   *
   * @return  The add request protocol op from this LDAP message.
   *
   * @throws  ClassCastException  If the protocol op for this LDAP message is
   *                              not an add request protocol op.
   */
  @NotNull()
  public AddRequestProtocolOp getAddRequestProtocolOp()
         throws ClassCastException
  {
    return (AddRequestProtocolOp) protocolOp;
  }



  /**
   * Retrieves the add response protocol op from this LDAP message.  This may
   * only be used if this LDAP message was obtained using the {@link #readFrom}
   * method.
   *
   * @return  The add response protocol op from this LDAP message.
   *
   * @throws  ClassCastException  If the protocol op for this LDAP message is
   *                              not an add response protocol op.
   */
  @NotNull()
  public AddResponseProtocolOp getAddResponseProtocolOp()
         throws ClassCastException
  {
    return (AddResponseProtocolOp) protocolOp;
  }



  /**
   * Retrieves the bind request protocol op from this LDAP message.  This may
   * only be used if this LDAP message was obtained using the {@link #readFrom}
   * method.
   *
   * @return  The bind request protocol op from this LDAP message.
   *
   * @throws  ClassCastException  If the protocol op for this LDAP message is
   *                              not a bind request protocol op.
   */
  @NotNull()
  public BindRequestProtocolOp getBindRequestProtocolOp()
         throws ClassCastException
  {
    return (BindRequestProtocolOp) protocolOp;
  }



  /**
   * Retrieves the bind response protocol op from this LDAP message.  This may
   * only be used if this LDAP message was obtained using the {@link #readFrom}
   * method.
   *
   * @return  The bind response protocol op from this LDAP message.
   *
   * @throws  ClassCastException  If the protocol op for this LDAP message is
   *                              not a bind response protocol op.
   */
  @NotNull()
  public BindResponseProtocolOp getBindResponseProtocolOp()
         throws ClassCastException
  {
    return (BindResponseProtocolOp) protocolOp;
  }



  /**
   * Retrieves the compare request protocol op from this LDAP message.  This may
   * only be used if this LDAP message was obtained using the {@link #readFrom}
   * method.
   *
   * @return  The compare request protocol op from this LDAP message.
   *
   * @throws  ClassCastException  If the protocol op for this LDAP message is
   *                              not a compare request protocol op.
   */
  @NotNull()
  public CompareRequestProtocolOp getCompareRequestProtocolOp()
         throws ClassCastException
  {
    return (CompareRequestProtocolOp) protocolOp;
  }



  /**
   * Retrieves the compare response protocol op from this LDAP message.  This
   * may only be used if this LDAP message was obtained using the
   * {@link #readFrom} method.
   *
   * @return  The compare response protocol op from this LDAP message.
   *
   * @throws  ClassCastException  If the protocol op for this LDAP message is
   *                              not a compare response protocol op.
   */
  @NotNull()
  public CompareResponseProtocolOp getCompareResponseProtocolOp()
         throws ClassCastException
  {
    return (CompareResponseProtocolOp) protocolOp;
  }



  /**
   * Retrieves the delete request protocol op from this LDAP message.  This may
   * only be used if this LDAP message was obtained using the {@link #readFrom}
   * method.
   *
   * @return  The delete request protocol op from this LDAP message.
   *
   * @throws  ClassCastException  If the protocol op for this LDAP message is
   *                              not a delete request protocol op.
   */
  @NotNull()
  public DeleteRequestProtocolOp getDeleteRequestProtocolOp()
         throws ClassCastException
  {
    return (DeleteRequestProtocolOp) protocolOp;
  }



  /**
   * Retrieves the delete response protocol op from this LDAP message.  This may
   * only be used if this LDAP message was obtained using the {@link #readFrom}
   * method.
   *
   * @return  The delete response protocol op from this LDAP message.
   *
   * @throws  ClassCastException  If the protocol op for this LDAP message is
   *                              not a delete response protocol op.
   */
  @NotNull()
  public DeleteResponseProtocolOp getDeleteResponseProtocolOp()
         throws ClassCastException
  {
    return (DeleteResponseProtocolOp) protocolOp;
  }



  /**
   * Retrieves the extended request protocol op from this LDAP message.  This
   * may only be used if this LDAP message was obtained using the
   * {@link #readFrom} method.
   *
   * @return  The extended request protocol op from this LDAP message.
   *
   * @throws  ClassCastException  If the protocol op for this LDAP message is
   *                              not an extended request protocol op.
   */
  @NotNull()
  public ExtendedRequestProtocolOp getExtendedRequestProtocolOp()
         throws ClassCastException
  {
    return (ExtendedRequestProtocolOp) protocolOp;
  }



  /**
   * Retrieves the extended response protocol op from this LDAP message.  This
   * may only be used if this LDAP message was obtained using the
   * {@link #readFrom} method.
   *
   * @return  The extended response protocol op from this LDAP message.
   *
   * @throws  ClassCastException  If the protocol op for this LDAP message is
   *                              not an extended response protocol op.
   */
  @NotNull()
  public ExtendedResponseProtocolOp getExtendedResponseProtocolOp()
         throws ClassCastException
  {
    return (ExtendedResponseProtocolOp) protocolOp;
  }



  /**
   * Retrieves the modify request protocol op from this LDAP message.  This may
   * only be used if this LDAP message was obtained using the {@link #readFrom}
   * method.
   *
   * @return  The modify request protocol op from this LDAP message.
   *
   * @throws  ClassCastException  If the protocol op for this LDAP message is
   *                              not a modify request protocol op.
   */
  @NotNull()
  public ModifyRequestProtocolOp getModifyRequestProtocolOp()
         throws ClassCastException
  {
    return (ModifyRequestProtocolOp) protocolOp;
  }



  /**
   * Retrieves the modify response protocol op from this LDAP message.  This may
   * only be used if this LDAP message was obtained using the {@link #readFrom}
   * method.
   *
   * @return  The modify response protocol op from this LDAP message.
   *
   * @throws  ClassCastException  If the protocol op for this LDAP message is
   *                              not a modify response protocol op.
   */
  @NotNull()
  public ModifyResponseProtocolOp getModifyResponseProtocolOp()
         throws ClassCastException
  {
    return (ModifyResponseProtocolOp) protocolOp;
  }



  /**
   * Retrieves the modify DN request protocol op from this LDAP message.  This
   * may only be used if this LDAP message was obtained using the
   * {@link #readFrom} method.
   *
   * @return  The modify DN request protocol op from this LDAP message.
   *
   * @throws  ClassCastException  If the protocol op for this LDAP message is
   *                              not a modify DN request protocol op.
   */
  @NotNull()
  public ModifyDNRequestProtocolOp getModifyDNRequestProtocolOp()
         throws ClassCastException
  {
    return (ModifyDNRequestProtocolOp) protocolOp;
  }



  /**
   * Retrieves the modify DN response protocol op from this LDAP message.  This
   * may only be used if this LDAP message was obtained using the
   * {@link #readFrom} method.
   *
   * @return  The modify DN response protocol op from this LDAP message.
   *
   * @throws  ClassCastException  If the protocol op for this LDAP message is
   *                              not a modify DN response protocol op.
   */
  @NotNull()
  public ModifyDNResponseProtocolOp getModifyDNResponseProtocolOp()
         throws ClassCastException
  {
    return (ModifyDNResponseProtocolOp) protocolOp;
  }



  /**
   * Retrieves the search request protocol op from this LDAP message.  This
   * may only be used if this LDAP message was obtained using the
   * {@link #readFrom} method.
   *
   * @return  The search request protocol op from this LDAP message.
   *
   * @throws  ClassCastException  If the protocol op for this LDAP message is
   *                              not a search request protocol op.
   */
  @NotNull()
  public SearchRequestProtocolOp getSearchRequestProtocolOp()
         throws ClassCastException
  {
    return (SearchRequestProtocolOp) protocolOp;
  }



  /**
   * Retrieves the search result entry protocol op from this LDAP message.  This
   * may only be used if this LDAP message was obtained using the
   * {@link #readFrom} method.
   *
   * @return  The search result entry protocol op from this LDAP message.
   *
   * @throws  ClassCastException  If the protocol op for this LDAP message is
   *                              not a search result entry protocol op.
   */
  @NotNull()
  public SearchResultEntryProtocolOp getSearchResultEntryProtocolOp()
         throws ClassCastException
  {
    return (SearchResultEntryProtocolOp) protocolOp;
  }



  /**
   * Retrieves the search result reference protocol op from this LDAP message.
   * This may only be used if this LDAP message was obtained using the
   * {@link #readFrom} method.
   *
   * @return  The search result reference protocol op from this LDAP message.
   *
   * @throws  ClassCastException  If the protocol op for this LDAP message is
   *                              not a search result reference protocol op.
   */
  @NotNull()
  public SearchResultReferenceProtocolOp getSearchResultReferenceProtocolOp()
         throws ClassCastException
  {
    return (SearchResultReferenceProtocolOp) protocolOp;
  }



  /**
   * Retrieves the search result done protocol op from this LDAP message.  This
   * may only be used if this LDAP message was obtained using the
   * {@link #readFrom} method.
   *
   * @return  The search result done protocol op from this LDAP message.
   *
   * @throws  ClassCastException  If the protocol op for this LDAP message is
   *                              not a search result done protocol op.
   */
  @NotNull()
  public SearchResultDoneProtocolOp getSearchResultDoneProtocolOp()
         throws ClassCastException
  {
    return (SearchResultDoneProtocolOp) protocolOp;
  }



  /**
   * Retrieves the unbind request protocol op from this LDAP message.  This may
   * only be used if this LDAP message was obtained using the {@link #readFrom}
   * method.
   *
   * @return  The unbind request protocol op from this LDAP message.
   *
   * @throws  ClassCastException  If the protocol op for this LDAP message is
   *                              not an unbind request protocol op.
   */
  @NotNull()
  public UnbindRequestProtocolOp getUnbindRequestProtocolOp()
         throws ClassCastException
  {
    return (UnbindRequestProtocolOp) protocolOp;
  }



  /**
   * Retrieves the intermediate response protocol op from this LDAP message.
   * This may only be used if this LDAP message was obtained using the
   * {@link #readFrom} method.
   *
   * @return  The intermediate response protocol op from this LDAP message.
   *
   * @throws  ClassCastException  If the protocol op for this LDAP message is
   *                              not an intermediate response protocol op.
   */
  @NotNull()
  public IntermediateResponseProtocolOp getIntermediateResponseProtocolOp()
         throws ClassCastException
  {
    return (IntermediateResponseProtocolOp) protocolOp;
  }



  /**
   * Retrieves the set of controls for this LDAP message.
   *
   * @return  The set of controls for this LDAP message.
   */
  @NotNull()
  public List<Control> getControls()
  {
    return controls;
  }



  /**
   * Encodes this LDAP message to an ASN.1 element.
   *
   * @return  The ASN.1 element containing the encoded representation of this
   *          LDAP message.
   */
  @NotNull()
  public ASN1Element encode()
  {
    if (controls.isEmpty())
    {
      return new ASN1Sequence(
           new ASN1Integer(messageID),
           protocolOp.encodeProtocolOp());
    }
    else
    {
      final Control[] controlArray = new Control[controls.size()];
      controls.toArray(controlArray);

      return new ASN1Sequence(
           new ASN1Integer(messageID),
           protocolOp.encodeProtocolOp(),
           Control.encodeControls(controlArray));
    }
  }



  /**
   * Decodes the provided ASN.1 element as an LDAP message.
   *
   * @param  element  The ASN.1 element to be decoded.
   *
   * @return  The LDAP message decoded from the provided ASN.1 element.
   *
   * @throws  LDAPException  If the provided ASN.1 element cannot be decoded as
   *                         a valid LDAP message.
   */
  @NotNull()
  public static LDAPMessage decode(@NotNull final ASN1Element element)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(element).elements();
      if ((elements.length < 2) || (elements.length > 3))
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_MESSAGE_DECODE_VALUE_SEQUENCE_INVALID_ELEMENT_COUNT.get(
                  elements.length));
      }

      final int messageID = ASN1Integer.decodeAsInteger(elements[0]).intValue();

      final ProtocolOp protocolOp;
      switch (elements[1].getType())
      {
        case PROTOCOL_OP_TYPE_ABANDON_REQUEST:
          protocolOp = AbandonRequestProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_ADD_REQUEST:
          protocolOp = AddRequestProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_ADD_RESPONSE:
          protocolOp = AddResponseProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_BIND_REQUEST:
          protocolOp = BindRequestProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_BIND_RESPONSE:
          protocolOp = BindResponseProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_COMPARE_REQUEST:
          protocolOp = CompareRequestProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_COMPARE_RESPONSE:
          protocolOp = CompareResponseProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_DELETE_REQUEST:
          protocolOp = DeleteRequestProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_DELETE_RESPONSE:
          protocolOp = DeleteResponseProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_EXTENDED_REQUEST:
          protocolOp = ExtendedRequestProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_EXTENDED_RESPONSE:
          protocolOp = ExtendedResponseProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_INTERMEDIATE_RESPONSE:
          protocolOp =
               IntermediateResponseProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_MODIFY_REQUEST:
          protocolOp = ModifyRequestProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_MODIFY_RESPONSE:
          protocolOp = ModifyResponseProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST:
          protocolOp = ModifyDNRequestProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_MODIFY_DN_RESPONSE:
          protocolOp = ModifyDNResponseProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_SEARCH_REQUEST:
          protocolOp = SearchRequestProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_SEARCH_RESULT_DONE:
          protocolOp = SearchResultDoneProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_SEARCH_RESULT_ENTRY:
          protocolOp =
               SearchResultEntryProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_SEARCH_RESULT_REFERENCE:
          protocolOp =
               SearchResultReferenceProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_UNBIND_REQUEST:
          protocolOp = UnbindRequestProtocolOp.decodeProtocolOp(elements[1]);
          break;
        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_MESSAGE_DECODE_INVALID_PROTOCOL_OP_TYPE.get(
                    StaticUtils.toHex(elements[1].getType())));
      }

      final Control[] controls;
      if (elements.length == 3)
      {
        controls =
             Control.decodeControls(ASN1Sequence.decodeAsSequence(elements[2]));
      }
      else
      {
        controls = null;
      }

      return new LDAPMessage(messageID, protocolOp, controls);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw le;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MESSAGE_DECODE_ERROR.get(StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Writes an encoded representation of this LDAP message to the provided ASN.1
   * buffer.
   *
   * @param  buffer  The ASN.1 buffer to which the encoded representation should
   *                 be written.
   */
  public void writeTo(@NotNull final ASN1Buffer buffer)
  {
    final ASN1BufferSequence messageSequence = buffer.beginSequence();
    buffer.addInteger(messageID);
    protocolOp.writeTo(buffer);

    if (! controls.isEmpty())
    {
      final ASN1BufferSequence controlsSequence =
           buffer.beginSequence(MESSAGE_TYPE_CONTROLS);
      for (final Control c : controls)
      {
        c.writeTo(buffer);
      }
      controlsSequence.end();
    }
    messageSequence.end();
  }



  /**
   * Reads an LDAP message from the provided ASN.1 stream reader.
   *
   * @param  reader               The ASN.1 stream reader from which the LDAP
   *                              message should be read.
   * @param  ignoreSocketTimeout  Indicates whether to ignore socket timeout
   *                              exceptions caught during processing.  This
   *                              should be {@code true} when the associated
   *                              connection is operating in asynchronous mode,
   *                              and {@code false} when operating in
   *                              synchronous mode.  In either case, exceptions
   *                              will not be ignored for the first read, since
   *                              that will be handled by the connection reader.
   *
   * @return  The decoded LDAP message, or {@code null} if the end of the input
   *          stream has been reached.
   *
   * @throws  LDAPException  If an error occurs while attempting to read or
   *                         decode the LDAP message.
   */
  @Nullable()
  public static LDAPMessage readFrom(@NotNull final ASN1StreamReader reader,
                                     final boolean ignoreSocketTimeout)
         throws LDAPException
  {
    final ASN1StreamReaderSequence messageSequence;
    try
    {
      reader.setIgnoreSocketTimeout(false, ignoreSocketTimeout);
      messageSequence = reader.beginSequence();
      if (messageSequence == null)
      {
        return null;
      }
    }
    catch (final IOException ioe)
    {
      if (! ((ioe instanceof SocketTimeoutException) ||
             (ioe instanceof InterruptedIOException)))
      {
        Debug.debugException(ioe);
      }

      throw new LDAPException(ResultCode.SERVER_DOWN,
           ERR_MESSAGE_IO_ERROR.get(StaticUtils.getExceptionMessage(ioe)), ioe);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MESSAGE_CANNOT_DECODE.get(StaticUtils.getExceptionMessage(e)),
           e);
    }

    try
    {

      reader.setIgnoreSocketTimeout(ignoreSocketTimeout, ignoreSocketTimeout);
      final int messageID = reader.readInteger();

      final ProtocolOp protocolOp;
      final byte protocolOpType = (byte) reader.peek();
      switch (protocolOpType)
      {
        case PROTOCOL_OP_TYPE_BIND_REQUEST:
          protocolOp = new BindRequestProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_BIND_RESPONSE:
          protocolOp = new BindResponseProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_UNBIND_REQUEST:
          protocolOp = new UnbindRequestProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_SEARCH_REQUEST:
          protocolOp = new SearchRequestProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_SEARCH_RESULT_ENTRY:
          protocolOp = new SearchResultEntryProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_SEARCH_RESULT_REFERENCE:
          protocolOp = new SearchResultReferenceProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_SEARCH_RESULT_DONE:
          protocolOp = new SearchResultDoneProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_MODIFY_REQUEST:
          protocolOp = new ModifyRequestProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_MODIFY_RESPONSE:
          protocolOp = new ModifyResponseProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_ADD_REQUEST:
          protocolOp = new AddRequestProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_ADD_RESPONSE:
          protocolOp = new AddResponseProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_DELETE_REQUEST:
          protocolOp = new DeleteRequestProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_DELETE_RESPONSE:
          protocolOp = new DeleteResponseProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST:
          protocolOp = new ModifyDNRequestProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_MODIFY_DN_RESPONSE:
          protocolOp = new ModifyDNResponseProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_COMPARE_REQUEST:
          protocolOp = new CompareRequestProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_COMPARE_RESPONSE:
          protocolOp = new CompareResponseProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_ABANDON_REQUEST:
          protocolOp = new AbandonRequestProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_EXTENDED_REQUEST:
          protocolOp = new ExtendedRequestProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_EXTENDED_RESPONSE:
          protocolOp = new ExtendedResponseProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_INTERMEDIATE_RESPONSE:
          protocolOp = new IntermediateResponseProtocolOp(reader);
          break;
        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_MESSAGE_INVALID_PROTOCOL_OP_TYPE.get(
                    StaticUtils.toHex(protocolOpType)));
      }

      final ArrayList<Control> controls = new ArrayList<>(5);
      if (messageSequence.hasMoreElements())
      {
        final ASN1StreamReaderSequence controlSequence = reader.beginSequence();
        while (controlSequence.hasMoreElements())
        {
          controls.add(Control.readFrom(reader));
        }
      }

      return new LDAPMessage(messageID, protocolOp, controls);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw le;
    }
    catch (final IOException ioe)
    {
      Debug.debugException(ioe);

      if ((ioe instanceof SocketTimeoutException) ||
          (ioe instanceof InterruptedIOException))
      {
        // We don't want to provide this exception as the cause because we want
        // to ensure that a failure in the middle of the response causes the
        // connection to be terminated.
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_MESSAGE_CANNOT_DECODE.get(StaticUtils.
                  getExceptionMessage(ioe)));
      }
      else
      {
        throw new LDAPException(ResultCode.SERVER_DOWN,
             ERR_MESSAGE_IO_ERROR.get(StaticUtils.getExceptionMessage(ioe)),
             ioe);
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MESSAGE_CANNOT_DECODE.get(StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Reads {@link LDAPResponse} object from the provided ASN.1 stream reader.
   *
   * @param  reader               The ASN.1 stream reader from which the LDAP
   *                              message should be read.
   * @param  ignoreSocketTimeout  Indicates whether to ignore socket timeout
   *                              exceptions caught during processing.  This
   *                              should be {@code true} when the associated
   *                              connection is operating in asynchronous mode,
   *                              and {@code false} when operating in
   *                              synchronous mode.  In either case, exceptions
   *                              will not be ignored for the first read, since
   *                              that will be handled by the connection reader.
   *
   * @return  The decoded LDAP message, or {@code null} if the end of the input
   *          stream has been reached.
   *
   * @throws  LDAPException  If an error occurs while attempting to read or
   *                         decode the LDAP message.
   */
  @Nullable()
  public static LDAPResponse readLDAPResponseFrom(
                                  @NotNull final ASN1StreamReader reader,
                                  final boolean ignoreSocketTimeout)
         throws LDAPException
  {
    return readLDAPResponseFrom(reader, ignoreSocketTimeout, null);
  }



  /**
   * Reads {@link LDAPResponse} object from the provided ASN.1 stream reader.
   *
   * @param  reader               The ASN.1 stream reader from which the LDAP
   *                              message should be read.
   * @param  ignoreSocketTimeout  Indicates whether to ignore socket timeout
   *                              exceptions caught during processing.  This
   *                              should be {@code true} when the associated
   *                              connection is operating in asynchronous mode,
   *                              and {@code false} when operating in
   *                              synchronous mode.  In either case, exceptions
   *                              will not be ignored for the first read, since
   *                              that will be handled by the connection reader.
   * @param  schema               The schema to use to select the appropriate
   *                              matching rule for attributes included in the
   *                              response.
   *
   * @return  The decoded LDAP message, or {@code null} if the end of the input
   *          stream has been reached.
   *
   * @throws  LDAPException  If an error occurs while attempting to read or
   *                         decode the LDAP message.
   */
  @Nullable()
  public static LDAPResponse readLDAPResponseFrom(
                                  @NotNull final ASN1StreamReader reader,
                                  final boolean ignoreSocketTimeout,
                                  @Nullable final Schema schema)
         throws LDAPException
  {
    final ASN1StreamReaderSequence messageSequence;
    try
    {
      reader.setIgnoreSocketTimeout(false, ignoreSocketTimeout);
      messageSequence = reader.beginSequence();
      if (messageSequence == null)
      {
        return null;
      }
    }
    catch (final IOException ioe)
    {
      if (! ((ioe instanceof SocketTimeoutException) ||
             (ioe instanceof InterruptedIOException)))
      {
        Debug.debugException(ioe);
      }

      throw new LDAPException(ResultCode.SERVER_DOWN,
           ERR_MESSAGE_IO_ERROR.get(StaticUtils.getExceptionMessage(ioe)), ioe);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MESSAGE_CANNOT_DECODE.get(StaticUtils.getExceptionMessage(e)),
           e);
    }

    try
    {
      reader.setIgnoreSocketTimeout(ignoreSocketTimeout, ignoreSocketTimeout);
      final int messageID = reader.readInteger();

      final byte protocolOpType = (byte) reader.peek();
      switch (protocolOpType)
      {
        case PROTOCOL_OP_TYPE_ADD_RESPONSE:
        case PROTOCOL_OP_TYPE_DELETE_RESPONSE:
        case PROTOCOL_OP_TYPE_MODIFY_RESPONSE:
        case PROTOCOL_OP_TYPE_MODIFY_DN_RESPONSE:
          return InternalSDKHelper.readLDAPResultFrom(messageID,
                      messageSequence, reader);

        case PROTOCOL_OP_TYPE_BIND_RESPONSE:
          return InternalSDKHelper.readBindResultFrom(messageID,
                      messageSequence, reader);

        case PROTOCOL_OP_TYPE_COMPARE_RESPONSE:
          return InternalSDKHelper.readCompareResultFrom(messageID,
                      messageSequence, reader);

        case PROTOCOL_OP_TYPE_EXTENDED_RESPONSE:
          return InternalSDKHelper.readExtendedResultFrom(messageID,
                      messageSequence, reader);

        case PROTOCOL_OP_TYPE_SEARCH_RESULT_ENTRY:
          return InternalSDKHelper.readSearchResultEntryFrom(messageID,
                      messageSequence, reader, schema);

        case PROTOCOL_OP_TYPE_SEARCH_RESULT_REFERENCE:
          return InternalSDKHelper.readSearchResultReferenceFrom(messageID,
                      messageSequence, reader);

        case PROTOCOL_OP_TYPE_SEARCH_RESULT_DONE:
          return InternalSDKHelper.readSearchResultFrom(messageID,
                      messageSequence, reader);

        case PROTOCOL_OP_TYPE_INTERMEDIATE_RESPONSE:
          return InternalSDKHelper.readIntermediateResponseFrom(messageID,
                      messageSequence, reader);

        case PROTOCOL_OP_TYPE_ABANDON_REQUEST:
        case PROTOCOL_OP_TYPE_ADD_REQUEST:
        case PROTOCOL_OP_TYPE_BIND_REQUEST:
        case PROTOCOL_OP_TYPE_COMPARE_REQUEST:
        case PROTOCOL_OP_TYPE_DELETE_REQUEST:
        case PROTOCOL_OP_TYPE_EXTENDED_REQUEST:
        case PROTOCOL_OP_TYPE_MODIFY_REQUEST:
        case PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST:
        case PROTOCOL_OP_TYPE_SEARCH_REQUEST:
        case PROTOCOL_OP_TYPE_UNBIND_REQUEST:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_MESSAGE_PROTOCOL_OP_TYPE_NOT_RESPONSE.get(
                    StaticUtils.toHex(protocolOpType)));

        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_MESSAGE_INVALID_PROTOCOL_OP_TYPE.get(
                    StaticUtils.toHex(protocolOpType)));
      }
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw le;
    }
    catch (final IOException ioe)
    {
      Debug.debugException(ioe);

      if ((ioe instanceof SocketTimeoutException) ||
          (ioe instanceof InterruptedIOException))
      {
        // We don't want to provide this exception as the cause because we want
        // to ensure that a failure in the middle of the response causes the
        // connection to be terminated.
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_MESSAGE_CANNOT_DECODE.get(
                  StaticUtils.getExceptionMessage(ioe)));
      }
      else
      {
        throw new LDAPException(ResultCode.SERVER_DOWN,
             ERR_MESSAGE_IO_ERROR.get(StaticUtils.getExceptionMessage(ioe)),
             ioe);
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MESSAGE_CANNOT_DECODE.get(StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves a string representation of this LDAP message.
   *
   * @return  A string representation of this LDAP message.
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
   * Appends a string representation of this LDAP message to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("LDAPMessage(msgID=");
    buffer.append(messageID);
    buffer.append(", protocolOp=");
    protocolOp.toString(buffer);

    if (! controls.isEmpty())
    {
      buffer.append(", controls={");
      final Iterator<Control> iterator = controls.iterator();
      while (iterator.hasNext())
      {
        iterator.next().toString(buffer);
        if (iterator.hasNext())
        {
          buffer.append(',');
        }
      }
      buffer.append('}');
    }

    buffer.append(')');
  }
}
