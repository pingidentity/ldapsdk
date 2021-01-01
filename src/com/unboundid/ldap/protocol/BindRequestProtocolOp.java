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



import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1StreamReaderSequence;
import com.unboundid.ldap.sdk.BindRequest;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.GenericSASLBindRequest;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.Debug;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.protocol.ProtocolMessages.*;



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
  @Nullable private final ASN1OctetString saslCredentials;

  // The password to use for simple authentication.
  @Nullable private final ASN1OctetString simplePassword;

  // The credentials type for this bind request.
  private final byte credentialsType;

  // The protocol version for this bind request.
  private final int version;

  // The bind DN to use for this bind request.
  @NotNull private final String bindDN;

  // The name of the SASL mechanism.
  @Nullable private final String saslMechanism;



  /**
   * Creates a new bind request protocol op for a simple bind.
   *
   * @param  bindDN    The DN for this bind request.
   * @param  password  The password for this bind request.
   */
  public BindRequestProtocolOp(@Nullable final String bindDN,
                               @Nullable final String password)
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
  public BindRequestProtocolOp(@Nullable final String bindDN,
                               @Nullable final byte[] password)
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
  public BindRequestProtocolOp(@Nullable final String bindDN,
                               @NotNull final String saslMechanism,
                               @Nullable final ASN1OctetString saslCredentials)
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
   * Creates a new bind request protocol op from the provided bind request
   * object.
   *
   * @param  request  The simple bind request to use to create this protocol op.
   *                  It must have been created with a static password rather
   *                  than using a password provider.
   *
   * @throws  LDAPSDKUsageException  If the provided simple bind request is
   *                                 configured to use a password provider
   *                                 rather than a static password.
   */
  public BindRequestProtocolOp(@NotNull final SimpleBindRequest request)
         throws LDAPSDKUsageException
  {
    version         = 3;
    credentialsType = CRED_TYPE_SIMPLE;
    bindDN          = request.getBindDN();
    simplePassword  = request.getPassword();
    saslMechanism   = null;
    saslCredentials = null;

    if (simplePassword == null)
    {
      throw new LDAPSDKUsageException(
           ERR_BIND_REQUEST_CANNOT_CREATE_WITH_PASSWORD_PROVIDER.get());
    }
  }



  /**
   * Creates a new bind request protocol op from the provided bind request
   * object.
   *
   * @param  request  The generic SASL bind request to use to create this
   *                  protocol op.
   */
  public BindRequestProtocolOp(@NotNull final GenericSASLBindRequest request)
  {
    version         = 3;
    credentialsType = CRED_TYPE_SASL;
    bindDN          = request.getBindDN();
    simplePassword  = null;
    saslMechanism   = request.getSASLMechanismName();
    saslCredentials = request.getCredentials();
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
  BindRequestProtocolOp(@NotNull final ASN1StreamReader reader)
       throws LDAPException
  {
    try
    {
      reader.beginSequence();
      version         = reader.readInteger();
      bindDN          = reader.readString();
      credentialsType = (byte) reader.peek();

      Validator.ensureNotNull(bindDN);

      switch (credentialsType)
      {
        case CRED_TYPE_SIMPLE:
          simplePassword =
               new ASN1OctetString(credentialsType, reader.readBytes());
          saslMechanism   = null;
          saslCredentials = null;
          Validator.ensureNotNull(bindDN);
          break;

        case CRED_TYPE_SASL:
          final ASN1StreamReaderSequence saslSequence = reader.beginSequence();
          saslMechanism = reader.readString();
          Validator.ensureNotNull(saslMechanism);
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
               ERR_BIND_REQUEST_INVALID_CRED_TYPE.get(
                    StaticUtils.toHex(credentialsType)));
      }
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
           ERR_BIND_REQUEST_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Creates a new bind request protocol op with the provided information.
   *
   * @param  version          The protocol version.
   * @param  bindDN           The bind DN.  It must not be {@code null} (but may
   *                          be empty).
   * @param  credentialsType  The type of credentials supplied.
   * @param  simplePassword   The password for simple authentication, if
   *                          appropriate.
   * @param  saslMechanism    The name of the SASL mechanism, if appropriate.
   * @param  saslCredentials  The SASL credentials, if appropriate.
   */
  private BindRequestProtocolOp(final int version, @NotNull final String bindDN,
                                final byte credentialsType,
                                @Nullable final ASN1OctetString simplePassword,
                                @Nullable final String saslMechanism,
                                @Nullable final ASN1OctetString saslCredentials)
  {
    this.version         = version;
    this.bindDN          = bindDN;
    this.credentialsType = credentialsType;
    this.simplePassword  = simplePassword;
    this.saslMechanism   = saslMechanism;
    this.saslCredentials = saslCredentials;
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
  @NotNull()
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
  @Nullable()
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
  @Nullable()
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
  @Nullable()
  public ASN1OctetString getSASLCredentials()
  {
    return saslCredentials;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ASN1Element encodeProtocolOp()
  {
    final ASN1Element credentials;
    if (credentialsType == CRED_TYPE_SIMPLE)
    {
      credentials = simplePassword;
    }
    else
    {
      if (saslCredentials == null)
      {
        credentials = new ASN1Sequence(CRED_TYPE_SASL,
             new ASN1OctetString(saslMechanism));
      }
      else
      {
        credentials = new ASN1Sequence(CRED_TYPE_SASL,
             new ASN1OctetString(saslMechanism),
             saslCredentials);
      }
    }

    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST,
         new ASN1Integer(version),
         new ASN1OctetString(bindDN),
         credentials);
  }



  /**
   * Decodes the provided ASN.1 element as a bind request protocol op.
   *
   * @param  element  The ASN.1 element to be decoded.
   *
   * @return  The decoded bind request protocol op.
   *
   * @throws  LDAPException  If the provided ASN.1 element cannot be decoded as
   *                         a bind request protocol op.
   */
  @NotNull()
  public static BindRequestProtocolOp decodeProtocolOp(
                                           @NotNull final ASN1Element element)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(element).elements();
      final int version = ASN1Integer.decodeAsInteger(elements[0]).intValue();
      final String bindDN =
           ASN1OctetString.decodeAsOctetString(elements[1]).stringValue();

      final ASN1OctetString saslCredentials;
      final ASN1OctetString simplePassword;
      final String saslMechanism;
      switch (elements[2].getType())
      {
        case CRED_TYPE_SIMPLE:
          simplePassword  = ASN1OctetString.decodeAsOctetString(elements[2]);
          saslMechanism   = null;
          saslCredentials = null;
          break;

        case CRED_TYPE_SASL:
          final ASN1Element[] saslElements =
               ASN1Sequence.decodeAsSequence(elements[2]).elements();
          saslMechanism = ASN1OctetString.decodeAsOctetString(saslElements[0]).
               stringValue();
          if (saslElements.length == 1)
          {
            saslCredentials = null;
          }
          else
          {
            saslCredentials =
                 ASN1OctetString.decodeAsOctetString(saslElements[1]);
          }

          simplePassword = null;
          break;

        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_BIND_REQUEST_INVALID_CRED_TYPE.get(
                    StaticUtils.toHex(elements[2].getType())));
      }

      return new BindRequestProtocolOp(version, bindDN, elements[2].getType(),
           simplePassword, saslMechanism, saslCredentials);
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
           ERR_BIND_REQUEST_CANNOT_DECODE.get(
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
   * Creates a new bind request object from this bind request protocol op.
   *
   * @param  controls  The set of controls to include in the bind request.  It
   *                   may be empty or {@code null} if no controls should be
   *                   included.
   *
   * @return  The bind request that was created.
   */
  @NotNull()
  public BindRequest toBindRequest(@Nullable final Control... controls)
  {
    if (credentialsType == CRED_TYPE_SIMPLE)
    {
      return new SimpleBindRequest(bindDN, simplePassword.getValue(),
           controls);
    }
    else
    {
      return new GenericSASLBindRequest(bindDN, saslMechanism,
           saslCredentials, controls);
    }
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
