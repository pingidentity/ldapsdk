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



import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1StreamReaderSequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.protocol.ProtocolMessages.*;



/**
 * This class provides an implementation of a generic response protocol op.
 * It must be subclassed by classes providing implementations for each
 * operation type.
 */
@InternalUseOnly()
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public abstract class GenericResponseProtocolOp
       implements ProtocolOp
{
  /**
   * The BER type for the referral URLs elements.
   */
  public static final byte TYPE_REFERRALS = (byte) 0xA3;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 3837308973105414874L;



  // The BER type for this response.
  private final byte type;

  // The result code for this response.
  private final int resultCode;

  // The referral URLs for this response.
  @NotNull private final List<String> referralURLs;

  // The diagnostic message for this response.
  @Nullable private final String diagnosticMessage;

  // The matched DN for this response.Static
  @Nullable private final String matchedDN;



  /**
   * Creates a new instance of this response with the provided information.
   *
   * @param  type               The BER type for this response.
   * @param  resultCode         The result code for this response.
   * @param  matchedDN          The matched DN for this result, if available.
   * @param  diagnosticMessage  The diagnostic message for this response, if
   *                            available.
   * @param  referralURLs       The list of referral URLs for this response, if
   *                            available.
   */
  protected GenericResponseProtocolOp(final byte type, final int resultCode,
                                      @Nullable final String matchedDN,
                                      @Nullable final String diagnosticMessage,
                                      @Nullable final List<String> referralURLs)
  {
    this.type              = type;
    this.resultCode        = resultCode;
    this.matchedDN         = matchedDN;
    this.diagnosticMessage = diagnosticMessage;

    if (referralURLs == null)
    {
      this.referralURLs = Collections.emptyList();
    }
    else
    {
      this.referralURLs = Collections.unmodifiableList(referralURLs);
    }
  }



  /**
   * Creates a new response read from the provided ASN.1 stream reader.
   *
   * @param  reader  The ASN.1 stream reader from which to read the response.
   *
   * @throws  LDAPException  If a problem occurs while reading or parsing the
   *                         response.
   */
  protected GenericResponseProtocolOp(@NotNull final ASN1StreamReader reader)
            throws LDAPException
  {
    try
    {
      type = (byte) reader.peek();
      final ASN1StreamReaderSequence opSequence = reader.beginSequence();
      resultCode = reader.readEnumerated();

      String s = reader.readString();
      Validator.ensureNotNull(s);
      if (s.isEmpty())
      {
        matchedDN = null;
      }
      else
      {
        matchedDN = s;
      }

      s = reader.readString();
      Validator.ensureNotNull(s);
      if (s.isEmpty())
      {
        diagnosticMessage = null;
      }
      else
      {
        diagnosticMessage = s;
      }

      if (opSequence.hasMoreElements())
      {
        final ArrayList<String> refs = new ArrayList<>(1);
        final ASN1StreamReaderSequence refSequence = reader.beginSequence();
        while (refSequence.hasMoreElements())
        {
          refs.add(reader.readString());
        }
        referralURLs = Collections.unmodifiableList(refs);
      }
      else
      {
        referralURLs = Collections.emptyList();
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_RESPONSE_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)), e);
    }
  }



  /**
   * Retrieves the result code for this response.
   *
   * @return  The result code for this response.
   */
  public final int getResultCode()
  {
    return resultCode;
  }



  /**
   * Retrieves the matched DN for this response, if any.
   *
   * @return  The matched DN for this response, or {@code null} if there is
   *          no matched DN.
   */
  @Nullable()
  public final String getMatchedDN()
  {
    return matchedDN;
  }



  /**
   * Retrieves the diagnostic message for this response, if any.
   *
   * @return  The diagnostic message for this response, or {@code null} if there
   *          is no diagnostic message.
   */
  @Nullable()
  public final String getDiagnosticMessage()
  {
    return diagnosticMessage;
  }



  /**
   * Retrieves the list of referral URLs for this response.
   *
   * @return  The list of referral URLs for this response, or an empty list
   *          if there are no referral URLs.
   */
  @NotNull()
  public final List<String> getReferralURLs()
  {
    return referralURLs;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public byte getProtocolOpType()
  {
    return type;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public final void writeTo(@NotNull final ASN1Buffer buffer)
  {
    final ASN1BufferSequence opSequence = buffer.beginSequence(type);
    buffer.addEnumerated(resultCode);
    buffer.addOctetString(matchedDN);
    buffer.addOctetString(diagnosticMessage);

    if (! referralURLs.isEmpty())
    {
      final ASN1BufferSequence refSequence =
           buffer.beginSequence(TYPE_REFERRALS);
      for (final String s : referralURLs)
      {
        buffer.addOctetString(s);
      }
      refSequence.end();
    }
    opSequence.end();
  }



  /**
   * Creates a new LDAP result object from this response protocol op.
   *
   * @param  controls  The set of controls to include in the LDAP result.  It
   *                   may be empty or {@code null} if no controls should be
   *                   included.
   *
   * @return  The LDAP result that was created.
   */
  @NotNull()
  public LDAPResult toLDAPResult(@Nullable final Control... controls)
  {
    final String[] refs;
    if (referralURLs.isEmpty())
    {
      refs = StaticUtils.NO_STRINGS;
    }
    else
    {
      refs = new String[referralURLs.size()];
      referralURLs.toArray(refs);
    }

    return new LDAPResult(-1, ResultCode.valueOf(resultCode), diagnosticMessage,
         matchedDN, refs, controls);
  }



  /**
   * Retrieves a string representation of this protocol op.
   *
   * @return  A string representation of this protocol op.
   */
  @Override()
  @NotNull()
  public final String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public final void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ResponseProtocolOp(type=");
    StaticUtils.toHex(type, buffer);
    buffer.append(", resultCode=");
    buffer.append(resultCode);

    if (matchedDN != null)
    {
      buffer.append(", matchedDN='");
      buffer.append(matchedDN);
      buffer.append('\'');
    }

    if (diagnosticMessage != null)
    {
      buffer.append(", diagnosticMessage='");
      buffer.append(diagnosticMessage);
      buffer.append('\'');
    }

    if (! referralURLs.isEmpty())
    {
      buffer.append(", referralURLs={");

      final Iterator<String> iterator = referralURLs.iterator();
      while (iterator.hasNext())
      {
        buffer.append('\'');
        buffer.append(iterator.next());
        buffer.append('\'');
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
