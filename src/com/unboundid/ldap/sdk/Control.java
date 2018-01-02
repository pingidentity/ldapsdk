/*
 * Copyright 2007-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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
import java.util.concurrent.ConcurrentHashMap;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Exception;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1StreamReaderSequence;
import com.unboundid.util.Extensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.asn1.ASN1Constants.*;
import static com.unboundid.ldap.sdk.LDAPMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.Validator.*;



/**
 * This class provides a data structure that represents an LDAP control.  A
 * control is an element that may be attached to an LDAP request or response
 * to provide additional information about the processing that should be (or has
 * been) performed.  This class may be overridden to provide additional
 * processing for specific types of controls.
 * <BR><BR>
 * A control includes the following elements:
 * <UL>
 *   <LI>An object identifier (OID), which identifies the type of control.</LI>
 *   <LI>A criticality flag, which indicates whether the control should be
 *       considered critical to the processing of the operation.  If a control
 *       is marked critical but the server either does not support that control
 *       or it is not appropriate for the associated request, then the server
 *       will reject the request.  If a control is not marked critical and the
 *       server either does not support it or it is not appropriate for the
 *       associated request, then the server will simply ignore that
 *       control and process the request as if it were not present.</LI>
 *   <LI>An optional value, which provides additional information for the
 *       control.  Some controls do not take values, and the value encoding for
 *       controls which do take values varies based on the type of control.</LI>
 * </UL>
 * Controls may be included in a request from the client to the server, as well
 * as responses from the server to the client (including intermediate response,
 * search result entry, and search result references, in addition to the final
 * response message for an operation).  When using request controls, they may be
 * included in the request object at the time it is created, or may be added
 * after the fact for {@link UpdatableLDAPRequest} objects.  When using
 * response controls, each response control class includes a {@code get} method
 * that can be used to extract the appropriate control from an appropriate
 * result (e.g.,  {@link LDAPResult}, {@link SearchResultEntry}, or
 * {@link SearchResultReference}).
 */
@Extensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class Control
       implements Serializable
{
  /**
   * The BER type to use for the encoded set of controls in an LDAP message.
   */
  private static final byte CONTROLS_TYPE = (byte) 0xA0;



  // The registered set of decodeable controls, mapped from their OID to the
  // class implementing the DecodeableControl interface that should be used to
  // decode controls with that OID.
  private static final ConcurrentHashMap<String,DecodeableControl>
       decodeableControlMap = new ConcurrentHashMap<String,DecodeableControl>();



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4440956109070220054L;



  // The encoded value for this control, if there is one.
  private final ASN1OctetString value;

  // Indicates whether this control should be considered critical.
  private final boolean isCritical;

  // The OID for this control
  private final String oid;



  static
  {
    com.unboundid.ldap.sdk.controls.ControlHelper.
         registerDefaultResponseControls();
    com.unboundid.ldap.sdk.experimental.ControlHelper.
         registerDefaultResponseControls();
    com.unboundid.ldap.sdk.unboundidds.controls.ControlHelper.
         registerDefaultResponseControls();
  }



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.  All
   * {@code DecodeableControl} objects must provide a default constructor that
   * can be used to create an instance suitable for invoking the
   * {@code decodeControl} method.
   */
  protected Control()
  {
    oid        = null;
    isCritical = true;
    value      = null;
  }



  /**
   * Creates a new control whose fields are initialized from the contents of the
   * provided control.
   *
   * @param  control  The control whose information should be used to create
   *                  this new control.
   */
  protected Control(final Control control)
  {
    oid        = control.oid;
    isCritical = control.isCritical;
    value      = control.value;
  }



  /**
   * Creates a new control with the provided OID.  It will not be critical, and
   * it will not have a value.
   *
   * @param  oid  The OID for this control.  It must not be {@code null}.
   */
  public Control(final String oid)
  {
    ensureNotNull(oid);

    this.oid   = oid;
    isCritical = false;
    value      = null;
  }



  /**
   * Creates a new control with the provided OID and criticality.  It will not
   * have a value.
   *
   * @param  oid         The OID for this control.  It must not be {@code null}.
   * @param  isCritical  Indicates whether this control should be considered
   *                     critical.
   */
  public Control(final String oid, final boolean isCritical)
  {
    ensureNotNull(oid);

    this.oid        = oid;
    this.isCritical = isCritical;
    value           = null;
  }



  /**
   * Creates a new control with the provided information.
   *
   * @param  oid         The OID for this control.  It must not be {@code null}.
   * @param  isCritical  Indicates whether this control should be considered
   *                     critical.
   * @param  value       The value for this control.  It may be {@code null} if
   *                     there is no value.
   */
  public Control(final String oid, final boolean isCritical,
                 final ASN1OctetString value)
  {
    ensureNotNull(oid);

    this.oid        = oid;
    this.isCritical = isCritical;
    this.value      = value;
  }



  /**
   * Retrieves the OID for this control.
   *
   * @return  The OID for this control.
   */
  public final String getOID()
  {
    return oid;
  }



  /**
   * Indicates whether this control should be considered critical.
   *
   * @return  {@code true} if this control should be considered critical, or
   *          {@code false} if not.
   */
  public final boolean isCritical()
  {
    return isCritical;
  }



  /**
   * Indicates whether this control has a value.
   *
   * @return  {@code true} if this control has a value, or {@code false} if not.
   */
  public final boolean hasValue()
  {
    return (value != null);
  }



  /**
   * Retrieves the encoded value for this control.
   *
   * @return  The encoded value for this control, or {@code null} if there is no
   *          value.
   */
  public final ASN1OctetString getValue()
  {
    return value;
  }



  /**
   * Writes an ASN.1-encoded representation of this control to the provided
   * ASN.1 stream writer.
   *
   * @param  writer  The ASN.1 stream writer to which the encoded representation
   *                 should be written.
   */
  public final void writeTo(final ASN1Buffer writer)
  {
    final ASN1BufferSequence controlSequence = writer.beginSequence();
    writer.addOctetString(oid);

    if (isCritical)
    {
      writer.addBoolean(true);
    }

    if (value != null)
    {
      writer.addOctetString(value.getValue());
    }

    controlSequence.end();
  }



  /**
   * Encodes this control to an ASN.1 sequence suitable for use in an LDAP
   * message.
   *
   * @return  The encoded representation of this control.
   */
  public final ASN1Sequence encode()
  {
    final ArrayList<ASN1Element> elementList = new ArrayList<ASN1Element>(3);
    elementList.add(new ASN1OctetString(oid));

    if (isCritical)
    {
      elementList.add(new ASN1Boolean(isCritical));
    }

    if (value != null)
    {
      elementList.add(new ASN1OctetString(value.getValue()));
    }

    return new ASN1Sequence(elementList);
  }



  /**
   * Reads an LDAP control from the provided ASN.1 stream reader.
   *
   * @param  reader  The ASN.1 stream reader from which to read the control.
   *
   * @return  The decoded control.
   *
   * @throws  LDAPException  If a problem occurs while attempting to read or
   *                         parse the control.
   */
  public static Control readFrom(final ASN1StreamReader reader)
         throws LDAPException
  {
    try
    {
      final ASN1StreamReaderSequence controlSequence = reader.beginSequence();
      final String oid = reader.readString();

      boolean isCritical = false;
      ASN1OctetString value = null;
      while (controlSequence.hasMoreElements())
      {
        final byte type = (byte) reader.peek();
        switch (type)
        {
          case UNIVERSAL_BOOLEAN_TYPE:
            isCritical = reader.readBoolean();
            break;
          case UNIVERSAL_OCTET_STRING_TYPE:
            value = new ASN1OctetString(reader.readBytes());
            break;
          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                                    ERR_CONTROL_INVALID_TYPE.get(toHex(type)));
        }
      }

      return decode(oid, isCritical, value);
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
           ERR_CONTROL_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }



  /**
   * Decodes the provided ASN.1 sequence as an LDAP control.
   *
   * @param  controlSequence  The ASN.1 sequence to be decoded.
   *
   * @return  The decoded control.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode the
   *                         provided ASN.1 sequence as an LDAP control.
   */
  public static Control decode(final ASN1Sequence controlSequence)
         throws LDAPException
  {
    final ASN1Element[] elements = controlSequence.elements();

    if ((elements.length < 1) || (elements.length > 3))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_CONTROL_DECODE_INVALID_ELEMENT_COUNT.get(
                                   elements.length));
    }

    final String oid =
         ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();

    boolean isCritical = false;
    ASN1OctetString value = null;
    if (elements.length == 2)
    {
      switch (elements[1].getType())
      {
        case UNIVERSAL_BOOLEAN_TYPE:
          try
          {
            isCritical =
                 ASN1Boolean.decodeAsBoolean(elements[1]).booleanValue();
          }
          catch (final ASN1Exception ae)
          {
            debugException(ae);
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_CONTROL_DECODE_CRITICALITY.get(getExceptionMessage(ae)),
                 ae);
          }
          break;

        case UNIVERSAL_OCTET_STRING_TYPE:
          value = ASN1OctetString.decodeAsOctetString(elements[1]);
          break;

        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_CONTROL_INVALID_TYPE.get(
                                       toHex(elements[1].getType())));
      }
    }
    else if (elements.length == 3)
    {
      try
      {
        isCritical = ASN1Boolean.decodeAsBoolean(elements[1]).booleanValue();
      }
      catch (final ASN1Exception ae)
      {
        debugException(ae);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_CONTROL_DECODE_CRITICALITY.get(getExceptionMessage(ae)), ae);
      }

      value = ASN1OctetString.decodeAsOctetString(elements[2]);
    }

    return decode(oid, isCritical, value);
  }



  /**
   * Attempts to create the most appropriate control instance from the provided
   * information.  If a {@link DecodeableControl} instance has been registered
   * for the specified OID, then this method will attempt to use that instance
   * to construct a control.  If that fails, or if no appropriate
   * {@code DecodeableControl} is registered, then a generic control will be
   * returned.
   *
   * @param  oid         The OID for the control.  It must not be {@code null}.
   * @param  isCritical  Indicates whether the control should be considered
   *                     critical.
   * @param  value       The value for the control.  It may be {@code null} if
   *                     there is no value.
   *
   * @return  The decoded control.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode the
   *                         provided ASN.1 sequence as an LDAP control.
   */
  public static Control decode(final String oid, final boolean isCritical,
                               final ASN1OctetString value)
         throws LDAPException
  {
     final DecodeableControl decodeableControl = decodeableControlMap.get(oid);
     if (decodeableControl == null)
     {
       return new Control(oid, isCritical, value);
     }
     else
     {
       try
       {
         return decodeableControl.decodeControl(oid, isCritical, value);
       }
       catch (final Exception e)
       {
         debugException(e);
         return new Control(oid, isCritical, value);
       }
     }
  }



  /**
   * Encodes the provided set of controls to an ASN.1 sequence suitable for
   * inclusion in an LDAP message.
   *
   * @param  controls  The set of controls to be encoded.
   *
   * @return  An ASN.1 sequence containing the encoded set of controls.
   */
  public static ASN1Sequence encodeControls(final Control[] controls)
  {
    final ASN1Sequence[] controlElements = new ASN1Sequence[controls.length];
    for (int i=0; i < controls.length; i++)
    {
      controlElements[i] = controls[i].encode();
    }

    return new ASN1Sequence(CONTROLS_TYPE, controlElements);
  }



  /**
   * Decodes the contents of the provided sequence as a set of controls.
   *
   * @param  controlSequence  The ASN.1 sequence containing the encoded set of
   *                          controls.
   *
   * @return  The decoded set of controls.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode any
   *                         of the controls.
   */
  public static Control[] decodeControls(final ASN1Sequence controlSequence)
         throws LDAPException
  {
    final ASN1Element[] controlElements = controlSequence.elements();
    final Control[] controls = new Control[controlElements.length];

    for (int i=0; i < controlElements.length; i++)
    {
      try
      {
        controls[i] = decode(ASN1Sequence.decodeAsSequence(controlElements[i]));
      }
      catch (final ASN1Exception ae)
      {
        debugException(ae);
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_CONTROLS_DECODE_ELEMENT_NOT_SEQUENCE.get(
                                     getExceptionMessage(ae)),
                                ae);
      }
    }

    return controls;
  }



  /**
   * Registers the provided class to be used in an attempt to decode controls
   * with the specified OID.
   *
   * @param  oid              The response control OID for which the provided
   *                          class will be registered.
   * @param  controlInstance  The control instance that should be used to decode
   *                          controls with the provided OID.
   */
  public static void registerDecodeableControl(final String oid,
                          final DecodeableControl controlInstance)
  {
    decodeableControlMap.put(oid, controlInstance);
  }



  /**
   * Deregisters the decodeable control class associated with the provided OID.
   *
   * @param  oid  The response control OID for which to deregister the
   *              decodeable control class.
   */
  public static void deregisterDecodeableControl(final String oid)
  {
    decodeableControlMap.remove(oid);
  }



  /**
   * Retrieves a hash code for this control.
   *
   * @return  A hash code for this control.
   */
  @Override()
  public final int hashCode()
  {
    int hashCode = oid.hashCode();

    if (isCritical)
    {
      hashCode++;
    }

    if (value != null)
    {
      hashCode += value.hashCode();
    }

    return hashCode;
  }



  /**
   * Indicates whether the provided object may be considered equal to this
   * control.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object may be considered equal to
   *          this control, or {@code false} if not.
   */
  @Override()
  public final boolean equals(final Object o)
  {
    if (o == null)
    {
      return false;
    }

    if (o == this)
    {
      return true;
    }

    if (! (o instanceof Control))
    {
      return false;
    }

    final Control c = (Control) o;
    if (! oid.equals(c.oid))
    {
      return false;
    }

    if (isCritical != c.isCritical)
    {
      return false;
    }

    if (value == null)
    {
      if (c.value != null)
      {
        return false;
      }
    }
    else
    {
      if (c.value == null)
      {
        return false;
      }

      if (! value.equals(c.value))
      {
        return false;
      }
    }


    return true;
  }



  /**
   * Retrieves the user-friendly name for this control, if available.  If no
   * user-friendly name has been defined, then the OID will be returned.
   *
   * @return  The user-friendly name for this control, or the OID if no
   *          user-friendly name is available.
   */
  public String getControlName()
  {
    // By default, we will return the OID.  Subclasses should override this to
    // provide the user-friendly name.
    return oid;
  }



  /**
   * Retrieves a string representation of this LDAP control.
   *
   * @return  A string representation of this LDAP control.
   */
  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this LDAP control to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which to append the string representation of
   *                 this buffer.
   */
  public void toString(final StringBuilder buffer)
  {
    buffer.append("Control(oid=");
    buffer.append(oid);
    buffer.append(", isCritical=");
    buffer.append(isCritical);
    buffer.append(", value=");

    if (value == null)
    {
      buffer.append("{null}");
    }
    else
    {
      buffer.append("{byte[");
      buffer.append(value.getValue().length);
      buffer.append("]}");
    }

    buffer.append(')');
  }
}
