/*
 * Copyright 2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2023 Ping Identity Corporation
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
 * Copyright (C) 2023 Ping Identity Corporation
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



import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines the type of communication security that the
 * {@link PooledReferralConnector} will use when following LDAP URLs that have
 * a scheme of "ldap" rather than "ldaps".  The referral connector will always
 * use LDAPS for LDAP referrals that have a scheme of "ldaps", but it is more
 * ambiguous for referrals that have a scheme of "ldap".
 * <BR><BR>
 * Although some LDAP URL implementations (including the LDAP SDK) support using
 * a scheme of "ldaps" to indicate that connections should be created as secure,
 * the official LDAP URL specification in
 * <A HREF="http://www.ietf.org/rfc/rfc4516.txt">RFC 4516</A> lists "ldap" as
 * the only allowed scheme.  As such, if a client receives a referral URL with
 * a scheme of "ldap", it isn't necessarily clear whether it should establish an
 * insecure LDAP connection or a secure LDAPS connection.  Further, for the case
 * in which it establishes an insecure LDAP connection, it isn't clear if that
 * connection should be subsequently secured with the StartTLS extended
 * operation.  This enum will be used to address that ambiguity.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum PooledReferralConnectorLDAPURLSecurityType
{
  /**
   * Indicates that the referral connector should always create unencrypted LDAP
   * connections for referral URLs with a scheme of "ldap", and that it should
   * never attempt to secure them with the StartTLS extended operation.
   */
  ALWAYS_USE_LDAP_AND_NEVER_USE_START_TLS,



  /**
   * Indicates that the referral connector should always create unencrypted LDAP
   * connections for referral URLs with a scheme of "ldap", and that it should
   * always attempt to secure them with the StartTLS extended operation.
   */
  ALWAYS_USE_LDAP_AND_ALWAYS_USE_START_TLS,



  /**
   * Indicates that the referral connector should always create unencrypted LDAP
   * connections for referral URLs with a scheme of "ldap".  If the connection
   * on which the referral was received was secured by either LDAPS or StartTLS,
   * then the referral connector will subsequently attempt to secure those
   * connections with StartTLS.  On the other hand, if the connection on which
   * the referral was received was an unencrypted LDAP connection, then the
   * referral connection will also use unencrypted LDAP and will not be secured
   * with StartTLS.
   */
  ALWAYS_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS,



  /**
   * Indicates that the referral connector should determine whether to create
   * unencrypted LDAP or encrypted LDAPS connections based on whether the
   * connection on which the referral was received was using LDAP or LDAPS.  If
   * the connection on which the referral was received was using unencrypted
   * LDAP (regardless of whether it was secured with StartTLS), then the
   * referral connector will create unencrypted LDAP connections, and it will
   * never attempt to secure them with StartTLS.  If the connection on which the
   * referral was received was secured by LDAPS, then the referral connector
   * will create secure LDAPS connections.
   */
  CONDITIONALLY_USE_LDAP_AND_NEVER_USE_START_TLS,



  /**
   * Indicates that the referral connector should determine whether to create
   * unencrypted LDAP or encrypted LDAPS connections based on whether the
   * connection on which the referral was received was using LDAP or LDAPS.  If
   * the connection on which the referral was received was using unencrypted
   * LDAP (regardless of whether it was secured with StartTLS), then the
   * referral connector will create unencrypted LDAP connections, and it will
   * always attempt to secure them with StartTLS.  If the connection on which
   * the referral was received was secured by LDAPS, then the referral connector
   * will create secure LDAPS connections.
   */
  CONDITIONALLY_USE_LDAP_AND_ALWAYS_USE_START_TLS,



  /**
   * Indicates that the referral connector should determine whether to create
   * unencrypted LDAP or encrypted LDAPS connections based on whether the
   * connection on which the referral was received was using LDAP or LDAPS.  If
   * the connection on which the referral was received was using unencrypted
   * LDAP that was not secured by StartTLS, then the referral connector will
   * create unencrypted LDAP connections, and it will not attempt to secure them
   * with StartTLS.  If the connection on which the referral was received was
   * using unencrypted LDAP that was subsequently secured with StartTLS, then
   * the referral connector will create unencrypted LDAP connections, and it
   * will attempt to secure them with StartTLS.  If the connection on which the
   * referral was received was secured by LDAPS, then the referral connector
   * will create secure LDAPS connections.
   */
  CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS,



  /**
   * Indicates that the referral connector should always create encrypted LDAPS
   * connections for referral URLs with a scheme of "ldap".
   */
  ALWAYS_USE_LDAPS;
}
