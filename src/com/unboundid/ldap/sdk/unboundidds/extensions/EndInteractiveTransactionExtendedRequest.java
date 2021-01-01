/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of the end interactive transaction
 * extended request.  It may be used to either commit or abort a transaction
 * that was created using the start interactive transaction request.  See the
 * documentation in the {@link StartInteractiveTransactionExtendedRequest} for
 * an example of processing an interactive transaction.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 *
 * @deprecated  The use of interactive transactions is strongly discouraged
 *              because it can create conditions which are prone to deadlocks
 *              between operations that may significantly affect performance and
 *              will result in the cancellation of one or both operations.
 */
@Deprecated()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class EndInteractiveTransactionExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.4) for the end interactive transaction
   * extended request.
   */
  @NotNull public static final String END_INTERACTIVE_TRANSACTION_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.6.4";



  /**
   * The BER type for the {@code txnID} element of the request.
   */
  private static final byte TYPE_TXN_ID = (byte) 0x80;



  /**
   * The BER type for the {@code commit} element of the request.
   */
  private static final byte TYPE_COMMIT = (byte) 0x81;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7404929482337917353L;



  // The transaction ID for the associated transaction.
  @NotNull private final ASN1OctetString transactionID;

  // Indicates whether to commit or abort the associated transaction.
  private final boolean commit;



  /**
   * Creates a new end interactive transaction extended request with the
   * provided information.
   *
   * @param  transactionID  The transaction ID for the transaction to commit or
   *                        abort.  It must not be {@code null}.
   * @param  commit         {@code true} if the transaction should be committed,
   *                        or {@code false} if the transaction should be
   *                        aborted.
   */
  public EndInteractiveTransactionExtendedRequest(
              @NotNull final ASN1OctetString transactionID,
              final boolean commit)
  {
    this(transactionID, commit, null);
  }



  /**
   * Creates a new end interactive transaction extended request with the
   * provided information.
   *
   * @param  transactionID  The transaction ID for the transaction to commit or
   *                        abort.  It must not be {@code null}.
   * @param  commit         {@code true} if the transaction should be committed,
   *                        or {@code false} if the transaction should be
   *                        aborted.
   * @param  controls       The set of controls to include in the request.
   */
  public EndInteractiveTransactionExtendedRequest(
              @NotNull final ASN1OctetString transactionID,
              final boolean commit,
              @Nullable final Control[] controls)
  {
    super(END_INTERACTIVE_TRANSACTION_REQUEST_OID,
          encodeValue(transactionID, commit),
          controls);

    this.transactionID = transactionID;
    this.commit        = commit;
  }



  /**
   * Creates a new end interactive transaction extended request from the
   * provided generic extended request.
   *
   * @param  extendedRequest  The generic extended request to use to create this
   *                          end interactive transaction extended request.
   *
   * @throws  LDAPException  If a problem occurs while decoding the request.
   */
  public EndInteractiveTransactionExtendedRequest(
              @NotNull final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    super(extendedRequest);

    final ASN1OctetString value = extendedRequest.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_END_INT_TXN_REQUEST_NO_VALUE.get());
    }

    ASN1OctetString txnID = null;
    boolean shouldCommit = true;
    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(valueElement).elements();

      for (final ASN1Element e : elements)
      {
        if (e.getType() == TYPE_TXN_ID)
        {
          txnID = ASN1OctetString.decodeAsOctetString(e);
        }
        else if (e.getType() == TYPE_COMMIT)
        {
          shouldCommit = ASN1Boolean.decodeAsBoolean(e).booleanValue();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_END_INT_TXN_REQUEST_INVALID_TYPE.get(
                    StaticUtils.toHex(e.getType())));
        }
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
                              ERR_END_INT_TXN_REQUEST_CANNOT_DECODE.get(e), e);
    }

    if (txnID == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_END_INT_TXN_REQUEST_NO_TXN_ID.get());
    }

    transactionID = txnID;
    commit        = shouldCommit;
  }



  /**
   * Generates the value to include in this extended request.
   *
   * @param  transactionID  The transaction ID for the transaction to commit or
   *                        abort.  It must not be {@code null}.
   * @param  commit         {@code true} if the transaction should be committed,
   *                        or {@code false} if the transaction should be
   *                        aborted.
   *
   * @return  The ASN.1 octet string containing the encoded request value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
               @NotNull final ASN1OctetString transactionID,
               final boolean commit)
  {
    Validator.ensureNotNull(transactionID);

    final ASN1Element[] valueElements;
    if (commit)
    {
      valueElements = new ASN1Element[]
      {
        new ASN1OctetString(TYPE_TXN_ID, transactionID.getValue())
      };
    }
    else
    {
      valueElements = new ASN1Element[]
      {
        new ASN1OctetString(TYPE_TXN_ID, transactionID.getValue()),
        new ASN1Boolean(TYPE_COMMIT, commit)
      };
    }

    return new ASN1OctetString(new ASN1Sequence(valueElements).encode());
  }



  /**
   * Retrieves the transaction ID for the transaction to commit or abort.
   *
   * @return  The transaction ID for the transaction to commit or abort.
   */
  @NotNull()
  public ASN1OctetString getTransactionID()
  {
    return transactionID;
  }



  /**
   * Indicates whether the transaction should be committed or aborted.
   *
   * @return  {@code true} if the transaction should be committed, or
   *          {@code false} if it should be aborted.
   */
  public boolean commit()
  {
    return commit;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public EndInteractiveTransactionExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public EndInteractiveTransactionExtendedRequest duplicate(
              @Nullable final Control[] controls)
  {
    final EndInteractiveTransactionExtendedRequest r =
         new EndInteractiveTransactionExtendedRequest(transactionID, commit,
              controls);
    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return r;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedRequestName()
  {
    return INFO_EXTENDED_REQUEST_NAME_END_INTERACTIVE_TXN.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("EndInteractiveTransactionExtendedRequest(transactionID='");
    buffer.append(transactionID.stringValue());
    buffer.append("', commit=");
    buffer.append(commit);

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
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
