/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
package com.unboundid.util.ssl.cert;



import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.OID;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.ssl.cert.CertMessages.*;



/**
 * This class provides an implementation of the subject alternative name X.509
 * certificate extension as described in
 * <A HREF="https://www.ietf.org/rfc/rfc5280.txt">RFC 5280</A> section 4.2.1.6.
 * It can provide additional information about the entity that is being
 * certified, including alternate DNS hostnames or IP addresses that may be used
 * to access the server, email addresses or DNs of end users, URIs of services,
 * etc.  This information may be used in the course of determining whether to
 * trust a peer certificate.
 * <BR><BR>
 * The OID for this extension is 2.5.29.17.  See the
 * {@link GeneralAlternativeNameExtension} class for implementation details and
 * the value encoding.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SubjectAlternativeNameExtension
       extends GeneralAlternativeNameExtension
{
  /**
   * The OID (2.5.29.17) for subject alternative name extensions.
   */
  @NotNull public static final OID SUBJECT_ALTERNATIVE_NAME_OID =
       new OID("2.5.29.17");



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4194307412985686108L;



  /**
   * Creates a new subject alternative name extension with the provided
   * information.
   *
   * @param  isCritical    Indicates whether this extension should be considered
   *                       critical.
   * @param  generalNames  The set of names to include in this extension.  This
   *                       must not be {@code null}.
   *
   * @throws  CertException  If a problem occurs while trying to encode the
   *                         value.
   */
  SubjectAlternativeNameExtension(final boolean isCritical,
                                  @NotNull final GeneralNames generalNames)
       throws CertException
  {
    super(SUBJECT_ALTERNATIVE_NAME_OID, isCritical, generalNames);
  }



  /**
   * Creates a new subject alternative name extension from the provided generic
   * extension.
   *
   * @param  extension  The extension to decode as a subject alternative name
   *                    extension.
   *
   * @throws  CertException  If the provided extension cannot be decoded as a
   *                         subject alternative name extension.
   */
  SubjectAlternativeNameExtension(
       @NotNull final X509CertificateExtension extension)
       throws CertException
  {
    super(extension);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtensionName()
  {
    return INFO_SUBJECT_ALT_NAME_EXTENSION_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    toString("SubjectAlternativeNameExtension", buffer);
  }
}
