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



import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  The use of interactive transactions is strongly discouraged
 *   because it can create conditions which are prone to deadlocks between
 *   operations that may significantly affect performance and will result in the
 *   cancellation of one or both operations.  It is strongly recommended that
 *   standard LDAP transactions (which may be started using a
 *   {@link com.unboundid.ldap.sdk.extensions.StartTransactionExtendedRequest})
 *   or a {@link MultiUpdateExtendedRequest} be used instead.  Although they
 *   cannot include arbitrary read operations, LDAP transactions and
 *   multi-update operations may be used in conjunction with the
 *   {@link com.unboundid.ldap.sdk.controls.AssertionRequestControl},
 *   {@link com.unboundid.ldap.sdk.controls.PreReadRequestControl}, and
 *   {@link com.unboundid.ldap.sdk.controls.PostReadRequestControl} to
 *   incorporate some read capability into a transaction, and in conjunction
 *   with the {@link com.unboundid.ldap.sdk.ModificationType#INCREMENT}
 *   modification type to increment integer values without the need to know the
 *   precise value before or after the operation (although the pre-read and/or
 *   post-read controls may be used to determine that).
 * </BLOCKQUOTE>
 * This class provides an implementation of the start interactive transaction
 * extended request.  It may be used to begin a transaction that allows multiple
 * operations to be processed as a single atomic unit.  Interactive transactions
 * may include read operations, in which case it is guaranteed that no
 * operations outside of the transaction will be allowed to access the
 * associated entries until the transaction has been committed or aborted.  The
 * {@link StartInteractiveTransactionExtendedResult} that is returned will
 * include a a transaction ID, which should be included in each operation that
 * is part of the transaction using the
 * {@code InteractiveTransactionSpecificationRequestControl}.  After all
 * requests for the transaction have been submitted to the server, the
 * {@link EndInteractiveTransactionExtendedRequest} should be used to
 * commit that transaction, or it may also be used to abort the transaction if
 * it is decided that it is no longer needed.
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
 * <BR>
 * The start transaction extended request may include an element which indicates
 * the base DN below which all operations will be attempted.  This may be used
 * to allow the Directory Server to tailor the transaction to the appropriate
 * backend.
 * <BR><BR>
 * Whenever the client sends a start interactive transaction request to the
 * server, the {@link StartInteractiveTransactionExtendedResult} that is
 * returned will include a transaction ID that may be used to identify the
 * transaction for all operations which are to be performed as part of the
 * transaction.  This transaction ID should be included in a
 * {@code InteractiveTransactionSpecificationRequestControl} attached to each
 * request that is to be processed as part of the transaction.  When the
 * transaction has completed, the
 * {@link EndInteractiveTransactionExtendedRequest} may be used to commit it,
 * and it may also be used at any time to abort the transaction if it is no
 * longer needed.
 * <H2>Example</H2>
 * The following example demonstrates the process for creating an interactive
 * transaction, processing multiple requests as part of that transaction, and
 * then commits the transaction.
 * <PRE>
 * // Start the interactive transaction and get the transaction ID.
 * StartInteractiveTransactionExtendedRequest startTxnRequest =
 *      new StartInteractiveTransactionExtendedRequest("dc=example,dc=com");
 * StartInteractiveTransactionExtendedResult startTxnResult =
 *      (StartInteractiveTransactionExtendedResult)
 *      connection.processExtendedOperation(startTxnRequest);
 * if (startTxnResult.getResultCode() != ResultCode.SUCCESS)
 * {
 *   throw new LDAPException(startTxnResult);
 * }
 * ASN1OctetString txnID = startTxnResult.getTransactionID();
 *
 * // At this point, we have a valid transaction.  We want to ensure that the
 * // transaction is aborted if any failure occurs, so do that in a
 * // try-finally block.
 * boolean txnFailed = true;
 * try
 * {
 *   // Perform a search to find all users in the "Sales" department.
 *   SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
 *        SearchScope.SUB, Filter.createEqualityFilter("ou", "Sales"));
 *   searchRequest.addControl(
 *        new InteractiveTransactionSpecificationRequestControl(txnID, true,
 *             true));
 *
 *   SearchResult searchResult = connection.search(searchRequest);
 *   if (searchResult.getResultCode() != ResultCode.SUCCESS)
 *   {
 *     throw new LDAPException(searchResult);
 *   }
 *
 *   // Iterate through all of the users and assign a new fax number to each
 *   // of them.
 *   for (SearchResultEntry e : searchResult.getSearchEntries())
 *   {
 *     ModifyRequest modifyRequest = new ModifyRequest(e.getDN(),
 *          new Modification(ModificationType.REPLACE,
 *               "facsimileTelephoneNumber", "+1 123 456 7890"));
 *     modifyRequest.addControl(
 *          new InteractiveTransactionSpecificationRequestControl(txnID, true,
 *
 *               true));
 *     connection.modify(modifyRequest);
 *   }
 *
 *   // Commit the transaction.
 *   ExtendedResult endTxnResult = connection.processExtendedOperation(
 *        new EndInteractiveTransactionExtendedRequest(txnID, true));
 *   if (endTxnResult.getResultCode() == ResultCode.SUCCESS)
 *   {
 *     txnFailed = false;
 *   }
 * }
 * finally
 * {
 *   if (txnFailed)
 *   {
 *     connection.processExtendedOperation(
 *          new EndInteractiveTransactionExtendedRequest(txnID, false));
 *   }
 * }
 * </PRE>
 *
 * @deprecated  The use of interactive transactions is strongly discouraged
 *              because it can create conditions which are prone to deadlocks
 *              between operations that may significantly affect performance and
 *              will result in the cancellation of one or both operations.
 */
@Deprecated()
@SuppressWarnings("deprecation")
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class StartInteractiveTransactionExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.3) for the start interactive transaction
   * extended request.
   */
  @NotNull public static final String
       START_INTERACTIVE_TRANSACTION_REQUEST_OID =
            "1.3.6.1.4.1.30221.2.6.3";



  /**
   * The BER type for the {@code baseDN} element of the request.
   */
  private static final byte TYPE_BASE_DN = (byte) 0x80;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4475028061132753546L;



  // The base DN for this request, if specified.
  @Nullable private final String baseDN;



  /**
   * Creates a new start interactive transaction extended request with no base
   * DN.
   */
  public StartInteractiveTransactionExtendedRequest()
  {
    super(START_INTERACTIVE_TRANSACTION_REQUEST_OID);

    baseDN = null;
  }



  /**
   * Creates a new start interactive transaction extended request.
   *
   * @param  baseDN  The base DN to use for the request.  It may be {@code null}
   *                 if no base DN should be provided.
   */
  public StartInteractiveTransactionExtendedRequest(
              @Nullable final String baseDN)
  {
    super(START_INTERACTIVE_TRANSACTION_REQUEST_OID, encodeValue(baseDN));

    this.baseDN = baseDN;
  }



  /**
   * Creates a new start interactive transaction extended request.
   *
   * @param  baseDN    The base DN to use for the request.  It may be
   *                   {@code null} if no base DN should be provided.
   * @param  controls  The set of controls to include in the request.
   */
  public StartInteractiveTransactionExtendedRequest(
              @Nullable final String baseDN,
              @Nullable final Control[] controls)
  {
    super(START_INTERACTIVE_TRANSACTION_REQUEST_OID, encodeValue(baseDN),
          controls);

    this.baseDN = baseDN;
  }



  /**
   * Creates a new start interactive transaction extended request from the
   * provided generic extended request.
   *
   * @param  extendedRequest  The generic extended request to use to create this
   *                          start interactive transaction extended request.
   *
   * @throws  LDAPException  If a problem occurs while decoding the request.
   */
  public StartInteractiveTransactionExtendedRequest(
              @NotNull final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    super(extendedRequest);

    if (! extendedRequest.hasValue())
    {
      baseDN = null;
      return;
    }

    String baseDNStr = null;
    try
    {
      final ASN1Element valueElement =
           ASN1Element.decode(extendedRequest.getValue().getValue());
      final ASN1Sequence valueSequence =
           ASN1Sequence.decodeAsSequence(valueElement);
      for (final ASN1Element e : valueSequence.elements())
      {
        if (e.getType() == TYPE_BASE_DN)
        {
          baseDNStr = ASN1OctetString.decodeAsOctetString(e).stringValue();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_START_INT_TXN_REQUEST_INVALID_ELEMENT.get(
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
           ERR_START_INT_TXN_REQUEST_VALUE_NOT_SEQUENCE.get(e.getMessage()), e);
    }

    baseDN = baseDNStr;
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the value of this extended request.
   *
   * @param  baseDN  The base DN to use for the request.  It may be {@code null}
   *                 if no base DN should be provided.
   *
   * @return  The ASN.1 octet string containing the encoded value, or
   *          {@code null} if no value should be used.
   */
  @Nullable()
  private static ASN1OctetString encodeValue(@Nullable final String baseDN)
  {
    if (baseDN == null)
    {
      return null;
    }

    final ASN1Element[] elements =
    {
      new ASN1OctetString(TYPE_BASE_DN, baseDN)
    };

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the base DN for this start interactive transaction extended
   * request, if available.
   *
   * @return  The base DN for this start interactive transaction extended
   *          request, or {@code null} if none was provided.
   */
  @Nullable()
  public String getBaseDN()
  {
    return baseDN;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public StartInteractiveTransactionExtendedResult process(
              @NotNull final LDAPConnection connection, final int depth)
         throws LDAPException
  {
    final ExtendedResult extendedResponse = super.process(connection, depth);
    return new StartInteractiveTransactionExtendedResult(extendedResponse);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public StartInteractiveTransactionExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public StartInteractiveTransactionExtendedRequest duplicate(
              @Nullable final Control[] controls)
  {
    final StartInteractiveTransactionExtendedRequest r =
         new StartInteractiveTransactionExtendedRequest(baseDN, controls);
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
    return INFO_EXTENDED_REQUEST_NAME_START_INTERACTIVE_TXN.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("StartInteractiveTransactionExtendedRequest(");

    if (baseDN != null)
    {
      buffer.append("baseDN='");
      buffer.append(baseDN);
      buffer.append('\'');
    }

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      if (baseDN != null)
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
