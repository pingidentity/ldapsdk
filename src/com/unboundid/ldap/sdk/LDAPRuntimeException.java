/*
 * Copyright 2011-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2011-2018 Ping Identity Corporation
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



import com.unboundid.util.LDAPSDKRuntimeException;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines a version of the {@link LDAPException} class that may be
 * thrown as a {@code RuntimeException} without the need for it to have been
 * explicitly declared in the method's throws list.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPRuntimeException
       extends LDAPSDKRuntimeException
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6201514484547092642L;



  // The LDAPException object wrapped by this runtime exception.
  private final LDAPException ldapException;



  /**
   * Creates a new instance of this {@code LDAPRuntimeException} using the
   * provided {@code LDAPException}.
   *
   * @param  ldapException  The {@code LDAPException} object wrapped by this
   *                        runtime exception.
   */
  public LDAPRuntimeException(final LDAPException ldapException)
  {
    super(ldapException.getMessage(), ldapException.getCause());

    this.ldapException = ldapException;
  }



  /**
   * Retrieves the {@code LDAPException} object wrapped by this runtime
   * exception.
   *
   * @return  The {@code LDAPException} object wrapped by this runtime
   *          exception.
   */
  public LDAPException getLDAPException()
  {
    return ldapException;
  }



  /**
   * Throws the wrapped {@code LDAPException} object.
   *
   * @throws  LDAPException  The wrapped {@code LDAPException} object.
   */
  public void throwLDAPException()
         throws LDAPException
  {
    throw ldapException;
  }



  /**
   * Retrieves the result code for this LDAP exception.
   *
   * @return  The result code for this LDAP exception.
   */
  public ResultCode getResultCode()
  {
    return ldapException.getResultCode();
  }



  /**
   * Retrieves the matched DN for this LDAP exception.
   *
   * @return  The matched DN for this LDAP exception, or {@code null} if there
   *          is none.
   */
  public String getMatchedDN()
  {
    return ldapException.getMatchedDN();
  }



  /**
   * Retrieves the diagnostic message returned by the directory server.
   *
   * @return  The diagnostic message returned by the directory server, or
   *          {@code null} if there is none.
   */
  public String getDiagnosticMessage()
  {
    return ldapException.getDiagnosticMessage();
  }



  /**
   * Retrieves the set of referral URLs for this LDAP exception.
   *
   * @return  The set of referral URLs for this LDAP exception, or an empty
   *          array if there are none.
   */
  public String[] getReferralURLs()
  {
    return ldapException.getReferralURLs();
  }



  /**
   * Indicates whether this result contains at least one control.
   *
   * @return  {@code true} if this result contains at least one control, or
   *          {@code false} if not.
   */
  public boolean hasResponseControl()
  {
    return ldapException.hasResponseControl();
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
  public boolean hasResponseControl(final String oid)
  {
    return ldapException.hasResponseControl(oid);
  }



  /**
   * Retrieves the set of response controls for this LDAP exception.
   *
   * @return  The set of response controls for this LDAP exception, or an empty
   *          array if there are none.
   */
  public Control[] getResponseControls()
  {
    return ldapException.getResponseControls();
  }



  /**
   * Retrieves the response control with the specified OID.
   *
   * @param  oid  The OID of the control to retrieve.
   *
   * @return  The response control with the specified OID, or {@code null} if
   *          there is no such control.
   */
  public Control getResponseControl(final String oid)
  {
    return ldapException.getResponseControl(oid);
  }



  /**
   * Creates a new {@code LDAPResult} object from this exception.
   *
   * @return  The {@code LDAPResult} object created from this exception.
   */
  public LDAPResult toLDAPResult()
  {
    return ldapException.toLDAPResult();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    ldapException.toString(buffer);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getExceptionMessage()
  {
    return ldapException.getExceptionMessage();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getExceptionMessage(final boolean includeStackTrace,
                                    final boolean includeCause)
  {
    return ldapException.getExceptionMessage(includeStackTrace, includeCause);
  }
}
