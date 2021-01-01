/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.experimental;



import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.experimental.ExperimentalMessages.*;



/**
 * This class serves as the base class for entries that hold information about
 * operations processed by an LDAP server, much like LDAP-accessible access log
 * messages.  The format for the entries used in this implementation is
 * described in draft-chu-ldap-logschema-00.
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public abstract class DraftChuLDAPLogSchema00Entry
       extends ReadOnlyEntry
{
  /**
   * The name of the attribute used to hold the DN of the authorization identity
   * for the operation.
   */
  @NotNull public static final String ATTR_AUTHORIZATION_IDENTITY_DN =
       "reqAuthzID";



  /**
   * The name of the attribute used to hold the diagnostic message the server
   * included in the response to the client.
   */
  @NotNull public static final String ATTR_DIAGNOSTIC_MESSAGE = "reqMessage";



  /**
   * The name of the attribute used to hold the type of operation that was
   * processed.  For extended operation, the value will be
   * "extended" followed by the OID of the extended request (e.g.,
   * "extended1.3.6.1.4.1.1466.20037" to indicate the StartTLS extended
   * request).  For all other operation types, this will be simply the name of
   * the operation:  abandon, add, bind, compare, delete, modify, modrdn,
   * search, or unbind.
   */
  @NotNull public static final String ATTR_OPERATION_TYPE = "reqType";



  /**
   * The name of the attribute used to hold the time the server completed
   * processing the operation.  Values will be in generalized time format, but
   * may be of a very high precision to ensure that each log entry has a
   * unique end time.
   */
  @NotNull public static final String ATTR_PROCESSING_END_TIME = "reqEnd";



  /**
   * The name of the attribute used to hold the time the server started
   * processing the operation.  Values will be in generalized time format, but
   * may be of a very high precision to ensure that each log entry has a
   * unique start time.
   */
  @NotNull public static final String ATTR_PROCESSING_START_TIME = "reqStart";



  /**
   * The name of the attribute used to hold a referral URL the server included
   * in the response to the client.
   */
  @NotNull public static final String ATTR_REFERRAL_URL = "reqReferral";



  /**
   * The name of the attribute used to hold information about a request control
   * included in the request received from the client.
   */
  @NotNull public static final String ATTR_REQUEST_CONTROL = "reqControls";



  /**
   * The name of the attribute used to hold information about a response control
   * included in the result returned to the client.
   */
  @NotNull public static final String ATTR_RESPONSE_CONTROL = "reqRespControls";



  /**
   * The name of the attribute used to hold the integer value of the result code
   * the server included in the response to the client.
   */
  @NotNull public static final String ATTR_RESULT_CODE = "reqResult";



  /**
   * The name of the attribute used to hold a session identifier for a sequence
   * of operations received on the same connection.
   */
  @NotNull public static final String ATTR_SESSION_ID = "reqSession";



  /**
   * The name of the attribute used to hold the DN of the entry targeted by the
   * operation.  For a search operation, this will be the search base DN.
   */
  @NotNull public static final String ATTR_TARGET_ENTRY_DN = "reqDN";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7279669732772403236L;



  // The parsed processing end time for the operation.
  @Nullable private final Date processingEndTimeDate;

  // The parsed processing start time for the operation.
  @NotNull private final Date processingStartTimeDate;

  // A list of controls included in the request from the client.
  @NotNull private final List<Control> requestControls;

  // A list of controls included in the request from the client.
  @NotNull private final List<Control> responseControls;

  // A list of referral URLs returned to the client.
  @NotNull private final List<String> referralURLs;

  // The operation type for the log entry.
  @NotNull private final OperationType operationType;

  // The result code returned to the client.
  @Nullable private final ResultCode resultCode;

  // The DN of the account used as the authorization identity for the operation.
  @Nullable private final String authorizationIdentityDN;

  // The diagnostic message returned to the client.
  @Nullable private final String diagnosticMessage;

  // The string representation of the processing end time for the operation.
  @Nullable private final String processingEndTimeString;

  // The string representation of the processing start time for the operation.
  @NotNull private final String processingStartTimeString;

  // The session ID for the sequence of operations received on the same
  // connection.
  @NotNull private final String sessionID;

  // The DN of the entry targeted by the client.
  @Nullable private final String targetEntryDN;



  /**
   * Creates a new instance of this access log entry from the provided entry.
   *
   * @param  entry          The entry used to create this access log entry.
   * @param  operationType  The associated operation type.
   *
   * @throws  LDAPException  If the provided entry cannot be decoded as a valid
   *                         access log entry as per the specification contained
   *                         in draft-chu-ldap-logschema-00.
   */
  DraftChuLDAPLogSchema00Entry(@NotNull final Entry entry,
                               @NotNull final OperationType operationType)
       throws LDAPException
  {
    super(entry);

    this.operationType = operationType;


    // Get the processing start time.
    processingStartTimeString =
         entry.getAttributeValue(ATTR_PROCESSING_START_TIME);
    if (processingStartTimeString == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_LOGSCHEMA_DECODE_MISSING_REQUIRED_ATTR.get(entry.getDN(),
                ATTR_PROCESSING_START_TIME));
    }
    else
    {
      try
      {
        processingStartTimeDate =
             StaticUtils.decodeGeneralizedTime(processingStartTimeString);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_LOGSCHEMA_DECODE_CANNOT_DECODE_TIME.get(entry.getDN(),
                  ATTR_PROCESSING_START_TIME, processingStartTimeString),
             e);
      }
    }


    // Get the processing end time.
    processingEndTimeString =
         entry.getAttributeValue(ATTR_PROCESSING_END_TIME);
    if (processingEndTimeString == null)
    {
      processingEndTimeDate = null;
    }
    else
    {
      try
      {
        processingEndTimeDate =
             StaticUtils.decodeGeneralizedTime(processingEndTimeString);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_LOGSCHEMA_DECODE_CANNOT_DECODE_TIME.get(entry.getDN(),
                  ATTR_PROCESSING_END_TIME, processingEndTimeString),
             e);
      }
    }


    // Get the session ID.
    sessionID = entry.getAttributeValue(ATTR_SESSION_ID);
    if (sessionID == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_LOGSCHEMA_DECODE_MISSING_REQUIRED_ATTR.get(entry.getDN(),
                ATTR_SESSION_ID));
    }


    // Get the target DN.  It can only be null for abandon, extended, and unbind
    // operation types.
    targetEntryDN = entry.getAttributeValue(ATTR_TARGET_ENTRY_DN);
    if (targetEntryDN == null)
    {
      if (! ((operationType == OperationType.ABANDON) ||
             (operationType == OperationType.EXTENDED) ||
             (operationType == OperationType.UNBIND)))
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_LOGSCHEMA_DECODE_MISSING_REQUIRED_ATTR.get(entry.getDN(),
                  ATTR_TARGET_ENTRY_DN));
      }
    }


    // Get the authorization identity.
    authorizationIdentityDN =
         entry.getAttributeValue(ATTR_AUTHORIZATION_IDENTITY_DN);


    // Get the set of request controls, if any.
    requestControls = decodeControls(entry, ATTR_REQUEST_CONTROL);


    // Get the set of response controls, if any.
    responseControls = decodeControls(entry, ATTR_RESPONSE_CONTROL);


    // Get the result code, if any.
    final String resultCodeString = entry.getAttributeValue(ATTR_RESULT_CODE);
    if (resultCodeString == null)
    {
      resultCode = null;
    }
    else
    {
      try
      {
        resultCode = ResultCode.valueOf(Integer.parseInt(resultCodeString));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_LOGSCHEMA_DECODE_RESULT_CODE_ERROR.get(entry.getDN(),
                  resultCodeString, ATTR_RESULT_CODE),
             e);
      }
    }


    // Get the diagnostic message, if any.
    diagnosticMessage = entry.getAttributeValue(ATTR_DIAGNOSTIC_MESSAGE);


    // Get the referral URLs, if any.
    final String[] referralArray = entry.getAttributeValues(ATTR_REFERRAL_URL);
    if (referralArray == null)
    {
      referralURLs = Collections.emptyList();
    }
    else
    {
      referralURLs =
           Collections.unmodifiableList(StaticUtils.toList(referralArray));
    }
  }



  /**
   * Decodes a set of controls contained in the specified attribute of the
   * provided entry.
   *
   * @param  entry          The entry containing the controls to decode.
   * @param  attributeName  The name of the attribute expected to hold the set
   *                        of controls to decode.
   *
   * @return  The decoded controls, or an empty list if the provided entry did
   *          not include any controls in the specified attribute.
   *
   * @throws  LDAPException  If a problem is encountered while trying to decode
   *                         the controls.
   */
  @NotNull()
  private static List<Control> decodeControls(@NotNull final Entry entry,
                                    @NotNull final String attributeName)
          throws LDAPException
  {
    final byte[][] values = entry.getAttributeValueByteArrays(attributeName);
    if ((values == null) || (values.length == 0))
    {
      return Collections.emptyList();
    }

    final ArrayList<Control> controls = new ArrayList<>(values.length);
    for (final byte[] controlBytes : values)
    {
      try
      {
        controls.add(Control.decode(ASN1Sequence.decodeAsSequence(
             controlBytes)));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_LOGSCHEMA_DECODE_CONTROL_ERROR.get(entry.getDN(),
                  attributeName, StaticUtils.getExceptionMessage(e)),
             e);
      }
    }

    return Collections.unmodifiableList(controls);
  }



  /**
   * Retrieves the type of operation represented by this access log entry.
   *
   * @return  The type of operation represented by this access log entry.
   */
  @NotNull()
  public final OperationType getOperationType()
  {
    return operationType;
  }



  /**
   * Retrieves the DN of the entry targeted by by the operation represented by
   * this access log entry, if available.  Some types of operations, like
   * abandon and extended operations, will not have a target entry DN.  For a
   * search operation, this will be the base DN for the search request.  For a
   * modify DN operation, this will be the DN of the entry before any processing
   * was performed.
   *
   * @return  The DN of the entry targeted by the operation represented by this
   *          access log entry, or {@code null} if no DN is available.
   */
  @Nullable()
  public final String getTargetEntryDN()
  {
    return targetEntryDN;
  }



  /**
   * Retrieves the string representation of the time that the server started
   * processing the operation represented by this access log entry.  Note that
   * the string representation of this start time may have a different precision
   * than the parsed start time returned by the
   * {@link #getProcessingStartTimeDate()} method.
   *
   * @return  The string representation of the time that the server started
   *          processing the operation represented by this access log entry.
   */
  @NotNull()
  public final String getProcessingStartTimeString()
  {
    return processingStartTimeString;
  }



  /**
   * Retrieves a parsed representation of the time that the server started
   * processing the operation represented by this access log entry.  Note that
   * this parsed representation may have a different precision than the start
   * time string returned by the {@link #getProcessingStartTimeString()} method.
   *
   * @return  A parsed representation of the time that the server started
   *          processing the operation represented by this access log entry.
   */
  @NotNull()
  public final Date getProcessingStartTimeDate()
  {
    return processingStartTimeDate;
  }



  /**
   * Retrieves the string representation of the time that the server completed
   * processing the operation represented by this access log entry, if
   * available.  Note that the string representation of this end time may have a
   * different precision than the parsed end time returned by the
   * {@link #getProcessingEndTimeDate()} method.
   *
   * @return  The string representation of the time that the server completed
   *          processing the operation represented by this access log entry, or
   *          {@code null} if no end time is available.
   */
  @Nullable()
  public final String getProcessingEndTimeString()
  {
    return processingEndTimeString;
  }



  /**
   * Retrieves a parsed representation of the time that the server completed
   * processing the operation represented by this access log entry, if
   * available.  Note that this parsed representation may have a different
   * precision than the end time string returned by the
   * {@link #getProcessingEndTimeString()} method.
   *
   * @return  A parsed representation of the time that the server completed
   *          processing the operation represented by this access log entry.
   */
  @Nullable()
  public final Date getProcessingEndTimeDate()
  {
    return processingEndTimeDate;
  }



  /**
   * Retrieves the session identifier that the server assigned to the operation
   * represented by this access log entry and can be used to correlate that
   * operation with other operations requested on the same client connection.
   * The server will assign a unique session identifier to each client
   * connection, and all requests received on that connection will share the
   * same session ID.
   *
   * @return  The session identifier that the server assigned to the operation
   *          represented by this access log entry.
   */
  @NotNull()
  public final String getSessionID()
  {
    return sessionID;
  }



  /**
   * Retrieves a list of the request controls for the operation represented by
   * this access log entry, if any.
   *
   * @return  A list of the request controls for the operation represented by
   *          this access log entry, or an empty list if there were no request
   *          controls included in the access log entry.
   */
  @NotNull()
  public final List<Control> getRequestControls()
  {
    return requestControls;
  }



  /**
   * Retrieves the set of request controls as an array rather than a list.  This
   * is a convenience method for subclasses that need to create LDAP requests
   * whose constructors need an array of controls rather than a list.
   *
   * @return  The set of request controls as an array rather than a list.
   */
  @NotNull()
  final Control[] getRequestControlArray()
  {
    return requestControls.toArray(StaticUtils.NO_CONTROLS);
  }



  /**
   * Retrieves the result code for the operation represented by this access log
   * entry, if any.
   *
   * @return  The result code for the operation represented by this access log
   *          entry, or {@code null} if no result code was included in the
   *          access log entry.
   */
  @Nullable()
  public final ResultCode getResultCode()
  {
    return resultCode;
  }



  /**
   * Retrieves the diagnostic message for the operation represented by this
   * access log entry, if any.
   *
   * @return  The diagnostic message for the operation represented by this
   *          access log entry, or {@code null} if no result code was included
   *          in the access log entry.
   */
  @Nullable()
  public final String getDiagnosticMessage()
  {
    return diagnosticMessage;
  }



  /**
   * Retrieves the list of referral URLs for the operation represented by this
   * access log entry, if any.
   *
   * @return  The list of referral URLs for the operation represented by this
   *          access log entry, or an empty list if no referral URLs were
   *          included in the access log entry.
   */
  @NotNull()
  public final List<String> getReferralURLs()
  {
    return referralURLs;
  }



  /**
   * Retrieves a list of the response controls for the operation represented by
   * this access log entry, if any.
   *
   * @return  A list of the response controls for the operation represented by
   *          this access log entry, or an empty list if there were no response
   *          controls included in the access log entry.
   */
  @NotNull()
  public final List<Control> getResponseControls()
  {
    return responseControls;
  }



  /**
   * Retrieves the DN of the account that served as the authorization identity
   * for the operation represented by this access log entry, if any.
   *
   * @return  The DN of the account that served as the authorization identity
   *          for the operation represented by this access log entry, or
   *          {@code null} if the authorization identity is not available.
   */
  @Nullable()
  public final String getAuthorizationIdentityDN()
  {
    return authorizationIdentityDN;
  }



  /**
   * Retrieves an {@code LDAPResult} object that represents the server response
   * described by this access log entry, if any.  Note that for some types of
   * operations, like abandon and unbind operations, the server will not return
   * a result to the client.
   *
   * @return  An {@code LDAPResult} object that represents the server response
   *          described by this access log entry, or {@code null} if no response
   *          information is available.
   */
  @Nullable()
  public final LDAPResult toLDAPResult()
  {
    if (resultCode == null)
    {
      return null;
    }

    return new LDAPResult(-1, resultCode, diagnosticMessage, null, referralURLs,
         responseControls);
  }



  /**
   * Decodes the provided entry as an access log entry of the appropriate type.
   *
   * @param  entry  The entry to decode as an access log entry.  It must not be
   *                {@code null}.
   *
   * @return  The decoded access log entry.
   *
   * @throws  LDAPException  If the provided entry cannot be decoded as a valid
   *                         access log entry as per the specification contained
   *                         in draft-chu-ldap-logschema-00.
   */
  @NotNull()
  public static DraftChuLDAPLogSchema00Entry decode(@NotNull final Entry entry)
         throws LDAPException
  {
    final String opType = entry.getAttributeValue(ATTR_OPERATION_TYPE);
    if (opType == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_LOGSCHEMA_DECODE_NO_OP_TYPE.get(entry.getDN(),
                ATTR_OPERATION_TYPE));
    }

    final String lowerOpType = StaticUtils.toLowerCase(opType);
    if (lowerOpType.equals("abandon"))
    {
      return new DraftChuLDAPLogSchema00AbandonEntry(entry);
    }
    else if (lowerOpType.equals("add"))
    {
      return new DraftChuLDAPLogSchema00AddEntry(entry);
    }
    else if (lowerOpType.equals("bind"))
    {
      return new DraftChuLDAPLogSchema00BindEntry(entry);
    }
    else if (lowerOpType.equals("compare"))
    {
      return new DraftChuLDAPLogSchema00CompareEntry(entry);
    }
    else if (lowerOpType.equals("delete"))
    {
      return new DraftChuLDAPLogSchema00DeleteEntry(entry);
    }
    else if (lowerOpType.startsWith("extended"))
    {
      return new DraftChuLDAPLogSchema00ExtendedEntry(entry);
    }
    else if (lowerOpType.equals("modify"))
    {
      return new DraftChuLDAPLogSchema00ModifyEntry(entry);
    }
    else if (lowerOpType.equals("modrdn"))
    {
      return new DraftChuLDAPLogSchema00ModifyDNEntry(entry);
    }
    else if (lowerOpType.equals("search"))
    {
      return new DraftChuLDAPLogSchema00SearchEntry(entry);
    }
    else if (lowerOpType.equals("unbind"))
    {
      return new DraftChuLDAPLogSchema00UnbindEntry(entry);
    }
    else
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_LOGSCHEMA_DECODE_UNRECOGNIZED_OP_TYPE.get(
                entry.getDN(), ATTR_OPERATION_TYPE, opType));
    }
  }
}
