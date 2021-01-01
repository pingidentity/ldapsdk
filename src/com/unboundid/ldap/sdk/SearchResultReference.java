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

import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1StreamReaderSequence;
import com.unboundid.ldap.protocol.LDAPResponse;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides a data structure for representing an LDAP search result
 * reference.  A search result reference consists of a set of referral URLs and
 * may also include zero or more controls.  It describes an alternate location
 * in which additional results for the search may be found.  If there are
 * multiple referral URLs, then they should all be considered equivalent ways
 * to access the information (e.g., referrals referencing different servers that
 * may be contacted).
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SearchResultReference
       implements Serializable, LDAPResponse
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5675961266319346053L;



  // The set of controls returned with this search result reference.
  @NotNull private final Control[] controls;

  // The message ID for the LDAP message containing this response.
  private final int messageID;

  // The set of referral URLs for this search result reference.
  @NotNull private final String[] referralURLs;



  /**
   * Creates a new search result reference with the provided information.
   *
   * @param  referralURLs  The set of referral URLs for this search result
   *                       reference.  It must not be {@code null}.
   * @param  controls      The set of controls returned with this search result
   *                       reference.  It must not be {@code null}.
   */
  public SearchResultReference(@NotNull final String[] referralURLs,
                               @NotNull final Control[] controls)
  {
    this(-1, referralURLs, controls);
  }



  /**
   * Creates a new search result reference with the provided information.
   *
   * @param  messageID     The message ID for the LDAP message containing this
   *                       response.
   * @param  referralURLs  The set of referral URLs for this search result
   *                       reference.  It must not be {@code null}.
   * @param  controls      The set of controls returned with this search result
   *                       reference.  It must not be {@code null}.
   */
  public SearchResultReference(final int messageID,
                               @NotNull final String[] referralURLs,
                               @NotNull final Control[] controls)
  {
    Validator.ensureNotNull(referralURLs);

    this.messageID    = messageID;
    this.referralURLs = referralURLs;

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
   * Creates a new search result reference object with the protocol op and
   * controls read from the given ASN.1 stream reader.
   *
   * @param  messageID        The message ID for the LDAP message containing
   *                          this response.
   * @param  messageSequence  The ASN.1 stream reader sequence used in the
   *                          course of reading the LDAP message elements.
   * @param  reader           The ASN.1 stream reader from which to read the
   *                          protocol op and controls.
   *
   * @return  The decoded search result reference object.
   *
   * @throws  LDAPException  If a problem occurs while reading or decoding data
   *                         from the ASN.1 stream reader.
   */
  @NotNull()
  static SearchResultReference readSearchReferenceFrom(final int messageID,
              @NotNull final ASN1StreamReaderSequence messageSequence,
              @NotNull final ASN1StreamReader reader)
         throws LDAPException
  {
    try
    {
      final ArrayList<String> refList = new ArrayList<>(5);
      final ASN1StreamReaderSequence refSequence = reader.beginSequence();
      while (refSequence.hasMoreElements())
      {
        refList.add(reader.readString());
      }

      final String[] referralURLs = new String[refList.size()];
      refList.toArray(referralURLs);

      Control[] controls = NO_CONTROLS;
      if (messageSequence.hasMoreElements())
      {
        final ArrayList<Control> controlList = new ArrayList<>(5);
        final ASN1StreamReaderSequence controlSequence = reader.beginSequence();
        while (controlSequence.hasMoreElements())
        {
          controlList.add(Control.readFrom(reader));
        }

        controls = new Control[controlList.size()];
        controlList.toArray(controls);
      }

      return new SearchResultReference(messageID, referralURLs, controls);
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
           ERR_SEARCH_REFERENCE_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
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
   * Retrieves the set of referral URLs for this search result reference.
   *
   * @return  The set of referral URLs for this search result reference.
   */
  @NotNull()
  public String[] getReferralURLs()
  {
    return referralURLs;
  }



  /**
   * Retrieves the set of controls returned with this search result reference.
   * Individual response controls of a specific type may be retrieved and
   * decoded using the {@code get} method in the response control class.
   *
   * @return  The set of controls returned with this search result reference.
   */
  @NotNull()
  public Control[] getControls()
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
   *          such control for this search result reference.
   */
  @Nullable()
  public Control getControl(@NotNull final String oid)
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
   * Retrieves a string representation of this search result reference.
   *
   * @return  A string representation of this search result reference.
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
   * Appends a string representation of this search result reference to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which to append the string representation of
   *                 this search result reference.
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("SearchResultReference(referralURLs={");
    for (int i=0; i < referralURLs.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }
      buffer.append(referralURLs[i]);
    }
    buffer.append('}');

    if (messageID >= 0)
    {
      buffer.append(", messageID=");
      buffer.append(messageID);
    }

    buffer.append(", controls={");

    for (int i=0; i < controls.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }

      controls[i].toString(buffer);
    }

    buffer.append("})");
  }
}
