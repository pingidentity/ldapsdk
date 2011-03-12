/*
 * Copyright 2009-2011 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2011 UnboundID Corp.
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



import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1StreamReaderSequence;
import com.unboundid.ldap.sdk.LDAPException;
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
 * This class provides an implementation of an LDAP bind request protocol op.
 */
@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class BindRequestProtocolOp
       implements ProtocolOp
{
  /**
   * The credentials type for simple bind requests.
   */
  public static final byte CRED_TYPE_SIMPLE = (byte) 0x80;



  /**
   * The credentials type for SASL bind requests.
   */
  public static final byte CRED_TYPE_SASL = (byte) 0xA3;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6661208657485444954L;



  // The credentials to use for SASL authentication.
  private final ASN1OctetString saslCredentials;

  // The password to use for simple authentication.
  private final ASN1OctetString simplePassword;

  // The credentials type for this bind request.
  private final byte credentialsType;

  // The protocol version for this bind request.
  private final int version;

  // The bind DN to use for this bind request.
  private final String bindDN;

  // The name of the SASL mechanism.
  private final String saslMechanism;



  /**
   * Creates a new bind request protocol op for a simple bind.
   *
   * @param  bindDN    The DN for this bind request.
   * @param  password  The password for this bind request.
   */
  public BindRequestProtocolOp(final String bindDN, final String password)
  {
    if (bindDN == null)
    {
      this.bindDN = "";
    }
    else
    {
      this.bindDN = bindDN;
    }

    if (password == null)
    {
      simplePassword = new ASN1OctetString(CRED_TYPE_SIMPLE);
    }
    else
    {
      simplePassword = new ASN1OctetString(CRED_TYPE_SIMPLE, password);
    }

    version         = 3;
    credentialsType = CRED_TYPE_SIMPLE;
    saslMechanism   = null;
    saslCredentials = null;
  }



  /**
   * Creates a new bind request protocol op for a simple bind.
   *
   * @param  bindDN    The DN for this bind request.
   * @param  password  The password for this bind request.
   */
  public BindRequestProtocolOp(final String bindDN, final byte[] password)
  {
    if (bindDN == null)
    {
      this.bindDN = "";
    }
    else
    {
      this.bindDN = bindDN;
    }

    if (password == null)
    {
      simplePassword = new ASN1OctetString(CRED_TYPE_SIMPLE);
    }
    else
    {
      simplePassword = new ASN1OctetString(CRED_TYPE_SIMPLE, password);
    }

    version         = 3;
    credentialsType = CRED_TYPE_SIMPLE;
    saslMechanism   = null;
    saslCredentials = null;
  }



  /**
   * Creates a new bind request protocol op for a SASL bind.
   *
   * @param  bindDN           The DN for this bind request.
   * @param  saslMechanism    The name of the SASL mechanism for this bind
   *                          request.  It must not be {@code null}.
   * @param  saslCredentials  The SASL credentials for this bind request, if
   *                          any.
   */
  public BindRequestProtocolOp(final String bindDN, final String saslMechanism,
                               final ASN1OctetString saslCredentials)
  {
    this.saslMechanism   = saslMechanism;
    this.saslCredentials = saslCredentials;

    if (bindDN == null)
    {
      this.bindDN = "";
    }
    else
    {
      this.bindDN = bindDN;
    }

    version         = 3;
    credentialsType = CRED_TYPE_SASL;
    simplePassword  = null;
  }



  /**
   * Creates a new bind request protocol op read from the provided ASN.1 stream
   * reader.
   *
   * @param  reader  The ASN.1 stream reader from which to read the bind request
   *                 protocol op.
   *
   * @throws  LDAPException  If a problem occurs while reading or parsing the
   *                         bind request.
   */
  BindRequestProtocolOp(final ASN1StreamReader reader)
       throws LDAPException
  {
    try
    {
      reader.beginSequence();
      version         = reader.readInteger();
      bindDN          = reader.readString();
      credentialsType = (byte) reader.peek();

      ensureNotNull(bindDN);

      switch (credentialsType)
      {
        case CRED_TYPE_SIMPLE:
          simplePassword =
               new ASN1OctetString(credentialsType, reader.readBytes());
          saslMechanism   = null;
          saslCredentials = null;
          ensureNotNull(bindDN);
          break;

        case CRED_TYPE_SASL:
          final ASN1StreamReaderSequence saslSequence = reader.beginSequence();
          saslMechanism = reader.readString();
          ensureNotNull(saslMechanism);
          if (saslSequence.hasMoreElements())
          {
            saslCredentials = new ASN1OctetString(reader.readBytes());
          }
          else
          {
            saslCredentials = null;
          }
          simplePassword = null;
          break;

        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_BIND_REQUEST_INVALID_CRED_TYPE.get(toHex(credentialsType)));
      }
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw le;
    }
    catch (Exception e)
    {
      debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_BIND_REQUEST_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }



  /**
   * Retrieves the protocol version for this bind request.
   *
   * @return  The protocol version for this bind request.
   */
  public int getVersion()
  {
    return version;
  }



  /**
   * Retrieves the bind DN for this bind request.
   *
   * @return  The bind DN for this bind request, or an empty string if none was
   *          provided.
   */
  public String getBindDN()
  {
    return bindDN;
  }



  /**
   * Retrieves the credentials type for this bind request.  It will either be
   * {@link #CRED_TYPE_SIMPLE} or {@link #CRED_TYPE_SASL}.
   *
   * @return  The credentials type for this bind request.
   */
  public byte getCredentialsType()
  {
    return credentialsType;
  }



  /**
   * Retrieves the password to use for simple authentication.
   *
   * @return  The password to use for simple authentication, or {@code null} if
   *          SASL authentication will be used.
   */
  public ASN1OctetString getSimplePassword()
  {
    return simplePassword;
  }



  /**
   * Retrieves the name of the SASL mechanism for this bind request.
   *
   * @return  The name of the SASL mechanism for this bind request, or
   *          {@code null} if simple authentication will be used.
   */
  public String getSASLMechanism()
  {
    return saslMechanism;
  }



  /**
   * Retrieves the credentials to use for SASL authentication, if any.
   *
   * @return  The credentials to use for SASL authentication, or {@code null} if
   *          there are no SASL credentials or if simple authentication will be
   *          used.
   */
  public ASN1OctetString getSASLCredentials()
  {
    return saslCredentials;
  }



  /**
   * {@inheritDoc}
   */
  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST;
  }



  /**
   * {@inheritDoc}
   */
  public void writeTo(final ASN1Buffer buffer)
  {
    final ASN1BufferSequence opSequence =
         buffer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST);
    buffer.addInteger(version);
    buffer.addOctetString(bindDN);

    if (credentialsType == CRED_TYPE_SIMPLE)
    {
      buffer.addElement(simplePassword);
    }
    else
    {
      final ASN1BufferSequence saslSequence =
           buffer.beginSequence(CRED_TYPE_SASL);
      buffer.addOctetString(saslMechanism);
      if (saslCredentials != null)
      {
        buffer.addElement(saslCredentials);
      }
      saslSequence.end();
    }
    opSequence.end();
    buffer.setZeroBufferOnClear();
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
  public void toString(final StringBuilder buffer)
  {
    buffer.append("BindRequestProtocolOp(version=");
    buffer.append(version);
    buffer.append(", bindDN='");
    buffer.append(bindDN);
    buffer.append("', type=");

    if (credentialsType == CRED_TYPE_SIMPLE)
    {
      buffer.append("simple");
    }
    else
    {
      buffer.append("SASL, mechanism=");
      buffer.append(saslMechanism);
    }

    buffer.append(')');
  }
}
