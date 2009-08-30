/*
 * Copyright 2009 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009 UnboundID Corp.
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



import java.util.List;

import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.util.NotMutable;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an implementation of a search result done protocol op.
 */
@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SearchResultDoneProtocolOp
       extends GenericResponseProtocolOp
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8246922907244250622L;



  /**
   * Creates a new instance of this search result done protocol op with the
   * provided information.
   *
   * @param  resultCode         The result code for this search result done.
   * @param  matchedDN          The matched DN for this search result done, if
   *                            any.
   * @param  diagnosticMessage  The diagnostic message for this search result
   *                            done, if any.
   * @param  referralURLs       The list of referral URLs for this search result
   *                            done, if any.
   */
  public SearchResultDoneProtocolOp(final int resultCode,
                                    final String matchedDN,
                                    final String diagnosticMessage,
                                    final List<String> referralURLs)
  {
    super(LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_RESULT_DONE, resultCode,
          matchedDN, diagnosticMessage, referralURLs);
  }



  /**
   * Creates a new search result done protocol op read from the provided ASN.1
   * stream reader.
   *
   * @param  reader  The ASN.1 stream reader from which to read the search
   *                 result done protocol op.
   *
   * @throws  LDAPException  If a problem occurs while reading or parsing the
   *                         search result done.
   */
  SearchResultDoneProtocolOp(final ASN1StreamReader reader)
       throws LDAPException
  {
    super(reader);
  }
}
