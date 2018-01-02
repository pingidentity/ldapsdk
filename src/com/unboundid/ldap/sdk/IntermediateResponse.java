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
package com.unboundid.ldap.sdk;



import java.io.Serializable;
import java.util.ArrayList;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1StreamReaderSequence;
import com.unboundid.ldap.protocol.LDAPResponse;
import com.unboundid.util.Extensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.LDAPMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides a data structure for holding information about an LDAP
 * intermediate response, which provides the ability for the directory server to
 * return multiple messages in response to operations that would not otherwise
 * support it.  Intermediate response messages will only be returned by the
 * server if the client does something to explicitly indicate that it is able
 * to accept them (e.g., by requesting an extended operation that may return
 * intermediate response messages, or by including a control in a request that
 * may cause the request to return intermediate response messages).
 * Intermediate response messages may include one or both of the following:
 * <UL>
 *   <LI>Response OID -- An optional OID that can be used to identify the type
 *       of intermediate response.</LI>
 *   <LI>Value -- An optional element that provides the encoded value for this
 *       intermediate response.  If a value is provided, then the encoding for
 *       the value depends on the type of intermediate response.</LI>
 * </UL>
 * When requesting an operation which may return intermediate response messages,
 * an {@link IntermediateResponseListener} must be provided for the associated
 * request.  If an intermediate response message is returned for a request that
 * does not have a registered {@code IntermediateResponseListener}, then it will
 * be silently discarded.
 */
@Extensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class IntermediateResponse
       implements Serializable, LDAPResponse
{
  /**
   * The BER type for the intermediate response OID element.
   */
  protected static final byte TYPE_INTERMEDIATE_RESPONSE_OID = (byte) 0x80;



  /**
   * The BER type for the intermediate response value element.
   */
  protected static final byte TYPE_INTERMEDIATE_RESPONSE_VALUE = (byte) 0x81;



  /**
   * An empty set of controls that will be used if no controls are provided.
   */
  private static final Control[] NO_CONTROLS = new Control[0];



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 218434694212935869L;



  // The encoded value for this intermediate response, if available.
  private final ASN1OctetString value;

  // The set of controls for this intermediate response.
  private final Control[] controls;

  // The message ID for this intermediate response.
  private final int messageID;

  // The OID for this extended request.
  private final String oid;



  /**
   * Creates a new intermediate response with the provided information.
   *
   * @param  oid    The OID for this intermediate response.  It may be
   *                {@code null} if there is no OID.
   * @param  value  The value for this intermediate response.  It may be
   *                {@code null} if there is no value.
   */
  public IntermediateResponse(final String oid, final ASN1OctetString value)
  {
    this(-1, oid, value, NO_CONTROLS);
  }



  /**
   * Creates a new intermediate response with the provided information.
   *
   * @param  messageID  The message ID for the LDAP message containing this
   *                    intermediate response.
   * @param  oid        The OID for this intermediate response.  It may be
   *                    {@code null} if there is no OID.
   * @param  value      The value for this intermediate response.  It may be
   *                    {@code null} if there is no value.
   */
  public IntermediateResponse(final int messageID, final String oid,
                              final ASN1OctetString value)
  {
    this(messageID, oid, value, NO_CONTROLS);
  }



  /**
   * Creates a new intermediate response with the provided information.
   *
   * @param  oid       The OID for this intermediate response.  It may be
   *                   {@code null} if there is no OID.
   * @param  value     The value for this intermediate response.  It may be
   *                   {@code null} if there is no value.
   * @param  controls  The set of controls for this intermediate response.
   */
  public IntermediateResponse(final String oid, final ASN1OctetString value,
                              final Control[] controls)
  {
    this(-1, oid, value, controls);
  }



  /**
   * Creates a new intermediate response with the provided information.
   *
   * @param  messageID  The message ID for the LDAP message containing this
   *                    intermediate response.
   * @param  oid        The OID for this intermediate response.  It may be
   *                    {@code null} if there is no OID.
   * @param  value      The value for this intermediate response.  It may be
   *                    {@code null} if there is no value.
   * @param  controls   The set of controls for this intermediate response.
   */
  public IntermediateResponse(final int messageID, final String oid,
                              final ASN1OctetString value,
                              final Control[] controls)
  {
    this.messageID = messageID;
    this.oid       = oid;
    this.value     = value;

    if (controls == null)
    {
      this.controls = NO_CONTROLS;
    }
    else
    {
      this.controls = controls;
    }
  }



  /**
   * Creates a new intermediate response with the information from the provided
   * intermediate response.
   *
   * @param  intermediateResponse  The intermediate response that should be used
   *                               to create this new intermediate response.
   */
  protected IntermediateResponse(
                 final IntermediateResponse intermediateResponse)
  {
    messageID = intermediateResponse.messageID;
    oid       = intermediateResponse.oid;
    value     = intermediateResponse.value;
    controls  = intermediateResponse.controls;
  }



  /**
   * Creates a new intermediate response object with the provided message ID and
   * with the protocol op and controls read from the given ASN.1 stream reader.
   *
   * @param  messageID        The LDAP message ID for the LDAP message that is
   *                          associated with this intermediate response.
   * @param  messageSequence  The ASN.1 stream reader sequence used in the
   *                          course of reading the LDAP message elements.
   * @param  reader           The ASN.1 stream reader from which to read the
   *                          protocol op and controls.
   *
   * @return  The decoded intermediate response.
   *
   * @throws  LDAPException  If a problem occurs while reading or decoding data
   *                         from the ASN.1 stream reader.
   */
  static IntermediateResponse readFrom(final int messageID,
              final ASN1StreamReaderSequence messageSequence,
              final ASN1StreamReader reader)
         throws LDAPException
  {
    try
    {
      String oid = null;
      ASN1OctetString value = null;

      final ASN1StreamReaderSequence opSequence = reader.beginSequence();
      while (opSequence.hasMoreElements())
      {
        final byte type = (byte) reader.peek();
        switch (type)
        {
          case TYPE_INTERMEDIATE_RESPONSE_OID:
            oid = reader.readString();
            break;
          case TYPE_INTERMEDIATE_RESPONSE_VALUE:
            value = new ASN1OctetString(type, reader.readBytes());
            break;
          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_INTERMEDIATE_RESPONSE_INVALID_ELEMENT.get(toHex(type)));
        }
      }

      final Control[] controls;
      if (messageSequence.hasMoreElements())
      {
        final ArrayList<Control> controlList = new ArrayList<Control>(1);
        final ASN1StreamReaderSequence controlSequence = reader.beginSequence();
        while (controlSequence.hasMoreElements())
        {
          controlList.add(Control.readFrom(reader));
        }

        controls = new Control[controlList.size()];
        controlList.toArray(controls);
      }
      else
      {
        controls = NO_CONTROLS;
      }

      return new IntermediateResponse(messageID, oid, value, controls);
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
           ERR_INTERMEDIATE_RESPONSE_CANNOT_DECODE.get(getExceptionMessage(e)),
           e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int getMessageID()
  {
    return messageID;
  }



  /**
   * Retrieves the OID for this intermediate response, if any.
   *
   * @return  The OID for this intermediate response, or {@code null} if there
   *          is no OID for this response.
   */
  public final String getOID()
  {
    return oid;
  }



  /**
   * Retrieves the encoded value for this intermediate response, if any.
   *
   * @return  The encoded value for this intermediate response, or {@code null}
   *          if there is no value for this response.
   */
  public final ASN1OctetString getValue()
  {
    return value;
  }



  /**
   * Retrieves the set of controls returned with this intermediate response.
   * Individual response controls of a specific type may be retrieved and
   * decoded using the {@code get} method in the response control class.
   *
   * @return  The set of controls returned with this intermediate response.
   */
  public final Control[] getControls()
  {
    return controls;
  }



  /**
   * Retrieves the control with the specified OID.  If there is more than one
   * control with the given OID, then the first will be returned.
   *
   * @param  oid  The OID of the control to retrieve.
   *
   * @return  The control with the requested OID, or {@code null} if there is no
   *          such control for this intermediate response.
   */
  public final Control getControl(final String oid)
  {
    for (final Control c : controls)
    {
      if (c.getOID().equals(oid))
      {
        return c;
      }
    }

    return null;
  }



  /**
   * Retrieves the user-friendly name for the intermediate response, if
   * available.  If no user-friendly name has been defined, but a response OID
   * is available, then that will be returned.  If neither a user-friendly name
   * nor a response OID are available, then {@code null} will be returned.
   *
   * @return  The user-friendly name for this intermediate response, the
   *          response OID if a user-friendly name is not available but a
   *          response OID is, or {@code null} if neither a user-friendly name
   *          nor a response OID are available.
   */
  public String getIntermediateResponseName()
  {
    // By default, we will return the OID (which may be null).  Subclasses
    // should override this to provide the user-friendly name.
    return oid;
  }



  /**
   * Retrieves a human-readable string representation for the contents of the
   * value for this intermediate response, if appropriate.  If one is provided,
   * then it should be a relatively compact single-line representation of the
   * most important elements of the value.
   *
   * @return  A human-readable string representation for the contents of the
   *          value for this intermediate response, or {@code null} if there is
   *          no value or no string representation is available.
   */
  public String valueToString()
  {
    return null;
  }



  /**
   * Retrieves a string representation of this intermediate response.
   *
   * @return  A string representation of this intermediate response.
   */
  @Override()
  public final String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this intermediate response to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("IntermediateResponse(");

    boolean added = false;

    if (messageID >= 0)
    {
      buffer.append("messageID=");
      buffer.append(messageID);
      added = true;
    }

    if (oid != null)
    {
      if (added)
      {
        buffer.append(", ");
      }

      buffer.append("oid='");
      buffer.append(oid);
      buffer.append('\'');
      added = true;
    }

    if (controls.length > 0)
    {
      if (added)
      {
        buffer.append(", ");
      }

      buffer.append("controls={");
      for (int i=0; i < controls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(controls[i]);
      }
      buffer.append('}');
    }

    buffer.append(')');
  }
}
