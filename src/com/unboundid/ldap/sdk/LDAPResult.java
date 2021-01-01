/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
import java.util.List;

import com.unboundid.asn1.ASN1Exception;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1StreamReaderSequence;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.LDAPResponse;
import com.unboundid.util.Debug;
import com.unboundid.util.Extensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides a data structure for holding the elements that are common
 * to most types of LDAP responses.  The elements contained in an LDAP result
 * include:
 * <UL>
 *   <LI>Result Code -- An integer value that provides information about the
 *       status of the operation.  See the {@link ResultCode} class for
 *       information about a number of result codes defined in LDAP.</LI>
 *   <LI>Diagnostic Message -- An optional string that may provide additional
 *       information about the operation.  For example, if the operation failed,
 *       it may include information about the reason for the failure.  It will
 *       often (but not always) be absent in the result for successful
 *       operations, and it may be absent in the result for failed
 *       operations.</LI>
 *   <LI>Matched DN -- An optional DN which specifies the entry that most
 *       closely matched the DN of a non-existent entry in the server.  For
 *       example, if an operation failed because the target entry did not exist,
 *       then the matched DN field may specify the DN of the closest ancestor
 *       to that entry that does exist in the server.</LI>
 *   <LI>Referral URLs -- An optional set of LDAP URLs which refer to other
 *       directories and/or locations within the DIT in which the operation may
 *       be attempted.  If multiple referral URLs are provided, then they should
 *       all be considered equivalent for the purpose of attempting the
 *       operation (e.g., the different URLs may simply refer to different
 *       servers in which the operation could be processed).</LI>
 *   <LI>Response Controls -- An optional set of controls included in the
 *       response from the server.  If any controls are included, then they may
 *       provide additional information about the processing that was performed
 *       by the server.</LI>
 * </UL>
 * <BR><BR>
 * Note that even though this class is marked with the @Extensible annotation
 * type, it should not be directly subclassed by third-party code.  Only the
 * {@link BindResult} and {@link ExtendedResult} subclasses are actually
 * intended to be extended by third-party code.
 */
@Extensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class LDAPResult
       implements Serializable, LDAPResponse
{
  /**
   * The BER type for the set of referral URLs.
   */
  static final byte TYPE_REFERRAL_URLS = (byte) 0xA3;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2215819095653175991L;



  // The protocol op type for this result, if available.
  @Nullable private final Byte protocolOpType;

  // The set of controls from the response.
  @NotNull private final Control[] responseControls;

  // The message ID for the LDAP message that is associated with this LDAP
  // result.
  private final int messageID;

  // The result code from the response.
  @NotNull private final ResultCode resultCode;

  // The diagnostic message from the response, if available.
  @Nullable private final String diagnosticMessage;

  // The matched DN from the response, if available.
  @Nullable private final String matchedDN;

  // The set of referral URLs from the response, if available.
  @NotNull private final String[] referralURLs;



  /**
   * Creates a new LDAP result object based on the provided result.
   *
   * @param  result  The LDAP result object to use to initialize this result.
   */
  protected LDAPResult(@NotNull final LDAPResult result)
  {
    protocolOpType    = result.protocolOpType;
    messageID         = result.messageID;
    resultCode        = result.resultCode;
    diagnosticMessage = result.diagnosticMessage;
    matchedDN         = result.matchedDN;
    referralURLs      = result.referralURLs;
    responseControls  = result.responseControls;
  }



  /**
   * Creates a new LDAP result object with the provided message ID and result
   * code, and no other information.
   *
   * @param  messageID   The message ID for the LDAP message that is associated
   *                     with this LDAP result.
   * @param  resultCode  The result code from the response.
   */
  public LDAPResult(final int messageID, @NotNull final ResultCode resultCode)
  {
    this(null, messageID, resultCode, null, null, StaticUtils.NO_STRINGS,
         NO_CONTROLS);
  }



  /**
   * Creates a new LDAP result object with the provided information.
   *
   * @param  messageID          The message ID for the LDAP message that is
   *                            associated with this LDAP result.
   * @param  resultCode         The result code from the response.
   * @param  diagnosticMessage  The diagnostic message from the response, if
   *                            available.
   * @param  matchedDN          The matched DN from the response, if available.
   * @param  referralURLs       The set of referral URLs from the response, if
   *                            available.
   * @param  responseControls   The set of controls from the response, if
   *                            available.
   */
  public LDAPResult(final int messageID, @NotNull final ResultCode resultCode,
                    @Nullable final String diagnosticMessage,
                    @Nullable final String matchedDN,
                    @Nullable final String[] referralURLs,
                    @Nullable final Control[] responseControls)
  {
    this(null, messageID, resultCode, diagnosticMessage, matchedDN,
         referralURLs, responseControls);
  }



  /**
   * Creates a new LDAP result object with the provided information.
   *
   * @param  messageID          The message ID for the LDAP message that is
   *                            associated with this LDAP result.
   * @param  resultCode         The result code from the response.
   * @param  diagnosticMessage  The diagnostic message from the response, if
   *                            available.
   * @param  matchedDN          The matched DN from the response, if available.
   * @param  referralURLs       The set of referral URLs from the response, if
   *                            available.
   * @param  responseControls   The set of controls from the response, if
   *                            available.
   */
  public LDAPResult(final int messageID, @NotNull final ResultCode resultCode,
                    @Nullable final String diagnosticMessage,
                    @Nullable final String matchedDN,
                    @Nullable final List<String> referralURLs,
                    @Nullable final List<Control> responseControls)
  {
    this(null, messageID, resultCode, diagnosticMessage, matchedDN,
         referralURLs, responseControls);
  }



  /**
   * Creates a new LDAP result object with the provided information.
   *
   * @param  protocolOpType     The protocol op type for this result, if
   *                            available.
   * @param  messageID          The message ID for the LDAP message that is
   *                            associated with this LDAP result.
   * @param  resultCode         The result code from the response.
   * @param  diagnosticMessage  The diagnostic message from the response, if
   *                            available.
   * @param  matchedDN          The matched DN from the response, if available.
   * @param  referralURLs       The set of referral URLs from the response, if
   *                            available.
   * @param  responseControls   The set of controls from the response, if
   *                            available.
   */
  private LDAPResult(@Nullable final Byte protocolOpType, final int messageID,
                     @NotNull final ResultCode resultCode,
                     @Nullable final String diagnosticMessage,
                     @Nullable final String matchedDN,
                     @Nullable final String[] referralURLs,
                     @Nullable final Control[] responseControls)
  {
    this.protocolOpType    = protocolOpType;
    this.messageID         = messageID;
    this.resultCode        = resultCode;
    this.diagnosticMessage = diagnosticMessage;
    this.matchedDN         = matchedDN;

    if (referralURLs == null)
    {
      this.referralURLs = StaticUtils.NO_STRINGS;
    }
    else
    {
      this.referralURLs = referralURLs;
    }

    if (responseControls == null)
    {
      this.responseControls = NO_CONTROLS;
    }
    else
    {
      this.responseControls = responseControls;
    }
  }



  /**
   * Creates a new LDAP result object with the provided information.
   *
   * @param  protocolOpType     The protocol op type for this result, if
   *                            available.
   * @param  messageID          The message ID for the LDAP message that is
   *                            associated with this LDAP result.
   * @param  resultCode         The result code from the response.
   * @param  diagnosticMessage  The diagnostic message from the response, if
   *                            available.
   * @param  matchedDN          The matched DN from the response, if available.
   * @param  referralURLs       The set of referral URLs from the response, if
   *                            available.
   * @param  responseControls   The set of controls from the response, if
   *                            available.
   */
  private LDAPResult(@Nullable final Byte protocolOpType, final int messageID,
                     @NotNull final ResultCode resultCode,
                     @Nullable final String diagnosticMessage,
                     @Nullable final String matchedDN,
                     @Nullable final List<String> referralURLs,
                     @Nullable final List<Control> responseControls)
  {
    this.protocolOpType    = protocolOpType;
    this.messageID         = messageID;
    this.resultCode        = resultCode;
    this.diagnosticMessage = diagnosticMessage;
    this.matchedDN         = matchedDN;

    if ((referralURLs == null) || referralURLs.isEmpty())
    {
      this.referralURLs = StaticUtils.NO_STRINGS;
    }
    else
    {
      this.referralURLs = new String[referralURLs.size()];
      referralURLs.toArray(this.referralURLs);
    }

    if ((responseControls == null) || responseControls.isEmpty())
    {
      this.responseControls = NO_CONTROLS;
    }
    else
    {
      this.responseControls = new Control[responseControls.size()];
      responseControls.toArray(this.responseControls);
    }
  }



  /**
   * Creates a new LDAP result object with the provided message ID and with the
   * protocol op and controls read from the given ASN.1 stream reader.
   *
   * @param  messageID        The LDAP message ID for the LDAP message that is
   *                          associated with this LDAP result.
   * @param  messageSequence  The ASN.1 stream reader sequence used in the
   *                          course of reading the LDAP message elements.
   * @param  reader           The ASN.1 stream reader from which to read the
   *                          protocol op and controls.
   *
   * @return  The decoded LDAP result.
   *
   * @throws  LDAPException  If a problem occurs while reading or decoding data
   *                         from the ASN.1 stream reader.
   */
  @NotNull()
  static LDAPResult readLDAPResultFrom(final int messageID,
              @NotNull final ASN1StreamReaderSequence messageSequence,
              @NotNull final ASN1StreamReader reader)
         throws LDAPException
  {
    try
    {
      final ASN1StreamReaderSequence protocolOpSequence =
           reader.beginSequence();
      final byte protocolOpType = protocolOpSequence.getType();

      final ResultCode resultCode = ResultCode.valueOf(reader.readEnumerated());

      String matchedDN = reader.readString();
      if (matchedDN.isEmpty())
      {
        matchedDN = null;
      }

      String diagnosticMessage = reader.readString();
      if (diagnosticMessage.isEmpty())
      {
        diagnosticMessage = null;
      }

      String[] referralURLs = StaticUtils.NO_STRINGS;
      if (protocolOpSequence.hasMoreElements())
      {
        final ArrayList<String> refList = new ArrayList<>(1);
        final ASN1StreamReaderSequence refSequence = reader.beginSequence();
        while (refSequence.hasMoreElements())
        {
          refList.add(reader.readString());
        }

        referralURLs = new String[refList.size()];
        refList.toArray(referralURLs);
      }

      Control[] responseControls = NO_CONTROLS;
      if (messageSequence.hasMoreElements())
      {
        final ArrayList<Control> controlList = new ArrayList<>(1);
        final ASN1StreamReaderSequence controlSequence = reader.beginSequence();
        while (controlSequence.hasMoreElements())
        {
          controlList.add(Control.readFrom(reader));
        }

        responseControls = new Control[controlList.size()];
        controlList.toArray(responseControls);
      }

      return new LDAPResult(protocolOpType, messageID, resultCode,
           diagnosticMessage, matchedDN, referralURLs, responseControls);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw le;
    }
    catch (final ASN1Exception ae)
    {
      Debug.debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_RESULT_CANNOT_DECODE.get(ae.getMessage()), ae);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_RESULT_CANNOT_DECODE.get(StaticUtils.getExceptionMessage(e)), e);
    }
  }



  /**
   * Retrieves the message ID for the LDAP message with which this LDAP result
   * is associated.
   *
   * @return  The message ID for the LDAP message with which this LDAP result
   *          is associated.
   */
  @Override()
  public final int getMessageID()
  {
    return messageID;
  }



  /**
   * Retrieves the type of operation that triggered this result, if available.
   *
   * @return  The type of operation that triggered this result, or {@code null}
   *          if the operation type is not available.
   *
   * Retrieves the BER type for the LDAP protocol op from which this
   */
  @Nullable()
  public final OperationType getOperationType()
  {
    if (protocolOpType != null)
    {
      switch (protocolOpType)
      {
        case LDAPMessage.PROTOCOL_OP_TYPE_ADD_RESPONSE:
          return OperationType.ADD;
        case LDAPMessage.PROTOCOL_OP_TYPE_BIND_RESPONSE:
          return OperationType.BIND;
        case LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_RESPONSE:
          return OperationType.COMPARE;
        case LDAPMessage.PROTOCOL_OP_TYPE_DELETE_RESPONSE:
          return OperationType.DELETE;
        case LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_RESPONSE:
          return OperationType.EXTENDED;
        case LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_RESPONSE:
          return OperationType.MODIFY;
        case LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_RESPONSE:
          return OperationType.MODIFY_DN;
        case LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_RESULT_DONE:
          return OperationType.SEARCH;
      }
    }

    return null;
  }



  /**
   * Retrieves the result code from the response.
   *
   * @return  The result code from the response.
   */
  @NotNull()
  public final ResultCode getResultCode()
  {
    return resultCode;
  }



  /**
   * Retrieves the diagnostic message from the response, if available.
   *
   * @return  The diagnostic message from the response, or {@code null} if none
   *          was provided.
   */
  @Nullable()
  public final String getDiagnosticMessage()
  {
    return diagnosticMessage;
  }



  /**
   * Retrieves the matched DN from the response, if available.
   *
   * @return  The matched DN from the response, or {@code null} if none was
   *          provided.
   */
  @Nullable()
  public final String getMatchedDN()
  {
    return matchedDN;
  }



  /**
   * Retrieves the set of referral URLs from the response, if available.
   *
   * @return  The set of referral URLs from the response.  The array returned
   *          may be empty if the response did not include any referral URLs.
   */
  @NotNull()
  public final String[] getReferralURLs()
  {
    return referralURLs;
  }



  /**
   * Retrieves the set of controls from the response, if available.  Individual
   * response controls of a specific type may be retrieved and decoded using the
   * {@code get} method in the response control class.
   *
   * @return  The set of controls from the response.  The array returned may be
   *          empty if the response did not include any controls.
   */
  @NotNull()
  public final Control[] getResponseControls()
  {
    return responseControls;
  }



  /**
   * Indicates whether this result contains at least one control.
   *
   * @return  {@code true} if this result contains at least one control, or
   *          {@code false} if not.
   */
  public final boolean hasResponseControl()
  {
    return (responseControls.length > 0);
  }



  /**
   * Indicates whether this result contains at least one control with the
   * specified OID.
   *
   * @param  oid  The object identifier for which to make the determination.  It
   *              must not be {@code null}.
   *
   * @return  {@code true} if this result contains at least one control with
   *          the specified OID, or {@code false} if not.
   */
  public final boolean hasResponseControl(@NotNull final String oid)
  {
    for (final Control c : responseControls)
    {
      if (c.getOID().equals(oid))
      {
        return true;
      }
    }

    return false;
  }



  /**
   * Retrieves the response control with the specified OID.  If there is more
   * than one response control with the specified OID, then the first will be
   * returned.
   *
   * @param  oid  The OID for the response control to retrieve.
   *
   * @return  The requested response control, or {@code null} if there is no
   *          such response control.
   */
  @Nullable()
  public final Control getResponseControl(@NotNull final String oid)
  {
    for (final Control c : responseControls)
    {
      if (c.getOID().equals(oid))
      {
        return c;
      }
    }

    return null;
  }



  /**
   * Retrieves a string representation of this LDAP result, consisting of
   * the result code, diagnostic message (if present), matched DN (if present),
   * and referral URLs (if present).
   *
   * @return  A string representation of this LDAP result.
   */
  @NotNull()
  public String getResultString()
  {
    final StringBuilder buffer = new StringBuilder();
    buffer.append("result code='");
    buffer.append(resultCode);
    buffer.append('\'');

    if ((diagnosticMessage != null) && (! diagnosticMessage.isEmpty()))
    {
      buffer.append(" diagnostic message='");
      buffer.append(diagnosticMessage);
      buffer.append('\'');
    }

    if ((matchedDN != null) && (! matchedDN.isEmpty()))
    {
      buffer.append("  matched DN='");
      buffer.append(matchedDN);
      buffer.append('\'');
    }

    if ((referralURLs != null) && (referralURLs.length > 0))
    {
      buffer.append("  referral URLs={");

      for (int i=0; i < referralURLs.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append('\'');
        buffer.append(referralURLs[i]);
        buffer.append('\'');
      }

      buffer.append('}');
    }

    return buffer.toString();
  }



  /**
   * Retrieves a string representation of this LDAP result.
   *
   * @return  A string representation of this LDAP result.
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
   * Appends a string representation of this LDAP result to the provided buffer.
   *
   * @param  buffer  The buffer to which to append a string representation of
   *                 this LDAP result.
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("LDAPResult(resultCode=");
    buffer.append(resultCode);

    if (messageID >= 0)
    {
      buffer.append(", messageID=");
      buffer.append(messageID);
    }

    if (protocolOpType != null)
    {
      switch (protocolOpType)
      {
        case LDAPMessage.PROTOCOL_OP_TYPE_ADD_RESPONSE:
          buffer.append(", opType='add'");
          break;
        case LDAPMessage.PROTOCOL_OP_TYPE_BIND_RESPONSE:
          buffer.append(", opType='bind'");
          break;
        case LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_RESPONSE:
          buffer.append(", opType='compare'");
          break;
        case LDAPMessage.PROTOCOL_OP_TYPE_DELETE_RESPONSE:
          buffer.append(", opType='delete'");
          break;
        case LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_RESPONSE:
          buffer.append(", opType='extended'");
          break;
        case LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_RESPONSE:
          buffer.append(", opType='modify'");
          break;
        case LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_RESPONSE:
          buffer.append(", opType='modify DN'");
          break;
        case LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_RESULT_DONE:
          buffer.append(", opType='search'");
          break;
      }
    }

    if (diagnosticMessage != null)
    {
      buffer.append(", diagnosticMessage='");
      buffer.append(diagnosticMessage);
      buffer.append('\'');
    }

    if (matchedDN != null)
    {
      buffer.append(", matchedDN='");
      buffer.append(matchedDN);
      buffer.append('\'');
    }

    if (referralURLs.length > 0)
    {
      buffer.append(", referralURLs={");
      for (int i=0; i < referralURLs.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append('\'');
        buffer.append(referralURLs[i]);
        buffer.append('\'');
      }
      buffer.append('}');
    }

    if (responseControls.length > 0)
    {
      buffer.append(", responseControls={");
      for (int i=0; i < responseControls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(responseControls[i]);
      }
      buffer.append('}');
    }

    buffer.append(')');
  }
}
