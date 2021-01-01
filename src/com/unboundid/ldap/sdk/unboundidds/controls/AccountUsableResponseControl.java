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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides an implementation of the account usable response control,
 * which may be returned with search result entries to provide information about
 * the usability of the associated user accounts.
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
 * Information that may be included in the account usable response control
 * includes:
 * <UL>
 *   <LI>{@code accountIsActive} -- Indicates that the account is active and may
 *       include the length of time in seconds until the password expires.</LI>
 *   <LI>{@code accountIsInactive} -- Indicates that the account has been locked
 *       or deactivated.</LI>
 *   <LI>{@code mustChangePassword} -- Indicates that the user must change his
 *       or her password before being allowed to perform any other
 *       operations.</LI>
 *   <LI>{@code passwordIsExpired} -- Indicates that the user's password has
 *       expired.</LI>
 *   <LI>{@code remainingGraceLogins} -- Indicates the number of grace logins
 *       remaining for the user.</LI>
 *   <LI>{@code secondsUntilUnlock} -- Indicates the length of time in seconds
 *       until the account will be automatically unlocked.</LI>
 * </UL>
 * See the {@link AccountUsableRequestControl} documentation for an example
 * demonstrating the use of the account usable request and response controls.
 * <BR><BR>
 * This control was designed by Sun Microsystems and is not based on any RFC or
 * Internet draft.  The value of this control is encoded as follows:
 * <BR><BR>
 * <PRE>
 * ACCOUNT_USABLE_RESPONSE ::= CHOICE {
 *   isUsable     [0] INTEGER, -- Seconds until password expiration --
 *   isNotUsable  [1] MORE_INFO }
 *
 * MORE_INFO ::= SEQUENCE {
 *   accountIsInactive     [0] BOOLEAN DEFAULT FALSE,
 *   mustChangePassword    [1] BOOLEAN DEFAULT FALSE,
 *   passwordIsExpired     [2] BOOLEAN DEFAULT FALSE,
 *   remainingGraceLogins  [3] INTEGER OPTIONAL,
 *   secondsUntilUnlock    [4] INTEGER OPTIONAL }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AccountUsableResponseControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (1.3.6.1.4.1.42.2.27.9.5.8) for the account usable response
   * control.
   */
  @NotNull public static final String ACCOUNT_USABLE_RESPONSE_OID =
       "1.3.6.1.4.1.42.2.27.9.5.8";



  /**
   * The BER type that will be used for the element that indicates the account
   * is usable and provides the number of seconds until expiration.
   */
  private static final byte TYPE_SECONDS_UNTIL_EXPIRATION = (byte) 0x80;



  /**
   * The BER type that will be used for the element that indicates the account
   * is not usable and provides additional information about the reason.
   */
  private static final byte TYPE_MORE_INFO = (byte) 0xA1;



  /**
   * The BER type that will be used for the element that indicates whether the
   * account is inactive.
   */
  private static final byte TYPE_IS_INACTIVE = (byte) 0x80;



  /**
   * The BER type that will be used for the element that indicates whether the
   * user must change their password.
   */
  private static final byte TYPE_MUST_CHANGE = (byte) 0x81;



  /**
   * The BER type that will be used for the element that indicates whether the
   * password is expired.
   */
  private static final byte TYPE_IS_EXPIRED = (byte) 0x82;



  /**
   * The BER type that will be used for the element that provides the number of
   * remaining grace logins.
   */
  private static final byte TYPE_REMAINING_GRACE_LOGINS = (byte) 0x83;



  /**
   * The BER type that will be used for the element that provides the number of
   * seconds until the account is unlocked.
   */
  private static final byte TYPE_SECONDS_UNTIL_UNLOCK = (byte) 0x84;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -9150988495337467770L;



  // Indicates whether the account has been inactivated.
  private final boolean isInactive;

  // Indicates whether the account is usable.
  private final boolean isUsable;

  // Indicates whether the user's password must be changed before other
  // operations will be allowed.
  private final boolean mustChangePassword;

  // Indicates whether the user's password is expired.
  private final boolean passwordIsExpired;

  // The list of reasons that this account may be considered unusable.
  @NotNull private final List<String> unusableReasons;

  // The number of grace logins remaining.
  private final int remainingGraceLogins;

  // The length of time in seconds until the password expires.
  private final int secondsUntilExpiration;

  // The length of time in seconds until the account is unlocked.
  private final int secondsUntilUnlock;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  AccountUsableResponseControl()
  {
    isUsable               = false;
    secondsUntilExpiration = 0;
    isInactive             = false;
    mustChangePassword     = false;
    passwordIsExpired      = false;
    remainingGraceLogins   = 0;
    secondsUntilUnlock     = 0;
    unusableReasons        = Collections.emptyList();
  }



  /**
   * Creates a new account usable response control which indicates that the
   * account is usable.
   *
   * @param  secondsUntilExpiration  The length of time in seconds until the
   *                                 user's password expires, or -1 if password
   *                                 expiration is not enabled for the user.
   */
  public AccountUsableResponseControl(final int secondsUntilExpiration)
  {
    super(ACCOUNT_USABLE_RESPONSE_OID, false,
          encodeValue(secondsUntilExpiration));

    isUsable                    = true;
    this.secondsUntilExpiration = secondsUntilExpiration;
    isInactive                  = false;
    mustChangePassword          = false;
    passwordIsExpired           = false;
    remainingGraceLogins        = -1;
    secondsUntilUnlock          = -1;
    unusableReasons             = Collections.emptyList();
  }



  /**
   * Creates a new account usable response control which indicates that the
   * account is not usable.
   *
   * @param  isInactive            Indicates whether the user account has been
   *                               inactivated.
   * @param  mustChangePassword    Indicates whether the user is required to
   *                               change his/her password before any other
   *                               operations will be allowed.
   * @param  passwordIsExpired     Indicates whether the user's password has
   *                               expired.
   * @param  remainingGraceLogins  The number of remaining grace logins for the
   *                               user.
   * @param  secondsUntilUnlock    The length of time in seconds until the
   *                               user's account will be automatically
   *                               unlocked.
   */
  public AccountUsableResponseControl(final boolean isInactive,
                                      final boolean mustChangePassword,
                                      final boolean passwordIsExpired,
                                      final int remainingGraceLogins,
                                      final int secondsUntilUnlock)
  {
    super(ACCOUNT_USABLE_RESPONSE_OID, false,
          encodeValue(isInactive, mustChangePassword, passwordIsExpired,
                      remainingGraceLogins, secondsUntilUnlock));

    isUsable                  = false;
    secondsUntilExpiration    = -1;
    this.isInactive           = isInactive;
    this.mustChangePassword   = mustChangePassword;
    this.passwordIsExpired    = passwordIsExpired;
    this.remainingGraceLogins = remainingGraceLogins;
    this.secondsUntilUnlock   = secondsUntilUnlock;

    final ArrayList<String> unusableList = new ArrayList<>(5);
    if (isInactive)
    {
      unusableList.add(ERR_ACCT_UNUSABLE_INACTIVE.get());
    }

    if (mustChangePassword)
    {
      unusableList.add(ERR_ACCT_UNUSABLE_MUST_CHANGE_PW.get());
    }

    if (passwordIsExpired)
    {
      unusableList.add(ERR_ACCT_UNUSABLE_PW_EXPIRED.get());
    }

    if (remainingGraceLogins >= 0)
    {
      switch (remainingGraceLogins)
      {
        case 0:
          unusableList.add(ERR_ACCT_UNUSABLE_REMAINING_GRACE_NONE.get());
          break;
        case 1:
          unusableList.add(ERR_ACCT_UNUSABLE_REMAINING_GRACE_ONE.get());
          break;
        default:
          unusableList.add(ERR_ACCT_UNUSABLE_REMAINING_GRACE_MULTIPLE.get(
                                remainingGraceLogins));
          break;
      }
    }

    if (secondsUntilUnlock > 0)
    {
      unusableList.add(
           ERR_ACCT_UNUSABLE_SECONDS_UNTIL_UNLOCK.get(secondsUntilUnlock));
    }

    unusableReasons = Collections.unmodifiableList(unusableList);
  }



  /**
   * Creates a new account usable response control with the provided
   * information.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   * @param  value       The encoded value for the control.  This may be
   *                     {@code null} if no value was provided.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as an
   *                         account usable response control.
   */
  public AccountUsableResponseControl(@NotNull final String oid,
                                      final boolean isCritical,
                                      @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical,  value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ACCOUNT_USABLE_RESPONSE_NO_VALUE.get());
    }

    final ASN1Element valueElement;
    try
    {
      valueElement = ASN1Element.decode(value.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                     ERR_ACCOUNT_USABLE_RESPONSE_VALUE_NOT_ELEMENT.get(e), e);
    }


    final boolean decodedIsUsable;
    boolean decodedIsInactive             = false;
    boolean decodedMustChangePassword     = false;
    boolean decodedPasswordIsExpired      = false;
    int     decodedRemainingGraceLogins   = -1;
    int     decodedSecondsUntilExpiration = -1;
    int     decodedSecondsUntilUnlock     = -1;

    final List<String> decodedUnusableReasons = new ArrayList<>(5);


    final byte type = valueElement.getType();
    if (type == TYPE_SECONDS_UNTIL_EXPIRATION)
    {
      decodedIsUsable = true;

      try
      {
        decodedSecondsUntilExpiration =
             ASN1Integer.decodeAsInteger(valueElement).intValue();
        if (decodedSecondsUntilExpiration < 0)
        {
          decodedSecondsUntilExpiration = -1;
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.DECODING_ERROR,
                       ERR_ACCOUNT_USABLE_RESPONSE_STE_NOT_INT.get(e), e);
      }
    }
    else if (type == TYPE_MORE_INFO)
    {
      decodedIsUsable = false;

      final ASN1Element[] elements;
      try
      {
        elements = ASN1Sequence.decodeAsSequence(valueElement).elements();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.DECODING_ERROR,
                       ERR_ACCOUNT_USABLE_RESPONSE_VALUE_NOT_SEQUENCE.get(e),
                       e);
      }

      for (final ASN1Element element : elements)
      {
        switch (element.getType())
        {
          case TYPE_IS_INACTIVE:
            try
            {
              decodedIsInactive =
                   ASN1Boolean.decodeAsBoolean(element).booleanValue();
              decodedUnusableReasons.add(ERR_ACCT_UNUSABLE_INACTIVE.get());
            }
            catch (final Exception e)
            {
              Debug.debugException(e);
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_ACCOUNT_USABLE_RESPONSE_INACTIVE_NOT_BOOLEAN.get(e), e);
            }
            break;

          case TYPE_MUST_CHANGE:
            try
            {
              decodedMustChangePassword =
                   ASN1Boolean.decodeAsBoolean(element).booleanValue();
              decodedUnusableReasons.add(
                   ERR_ACCT_UNUSABLE_MUST_CHANGE_PW.get());
            }
            catch (final Exception e)
            {
              Debug.debugException(e);
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_ACCOUNT_USABLE_RESPONSE_MUST_CHANGE_NOT_BOOLEAN.get(e),
                   e);
            }
            break;

          case TYPE_IS_EXPIRED:
            try
            {
              decodedPasswordIsExpired =
                   ASN1Boolean.decodeAsBoolean(element).booleanValue();
              decodedUnusableReasons.add(ERR_ACCT_UNUSABLE_PW_EXPIRED.get());
            }
            catch (final Exception e)
            {
              Debug.debugException(e);
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_ACCOUNT_USABLE_RESPONSE_IS_EXP_NOT_BOOLEAN.get(e), e);
            }
            break;

          case TYPE_REMAINING_GRACE_LOGINS:
            try
            {
              decodedRemainingGraceLogins =
                   ASN1Integer.decodeAsInteger(element).intValue();
              if (decodedRemainingGraceLogins < 0)
              {
                decodedRemainingGraceLogins = -1;
              }
              else
              {
                switch (decodedRemainingGraceLogins)
                {
                  case 0:
                    decodedUnusableReasons.add(
                         ERR_ACCT_UNUSABLE_REMAINING_GRACE_NONE.get());
                    break;
                  case 1:
                    decodedUnusableReasons.add(
                         ERR_ACCT_UNUSABLE_REMAINING_GRACE_ONE.get());
                    break;
                  default:
                    decodedUnusableReasons.add(
                         ERR_ACCT_UNUSABLE_REMAINING_GRACE_MULTIPLE.get(
                              decodedRemainingGraceLogins));
                    break;
                }
              }
            }
            catch (final Exception e)
            {
              Debug.debugException(e);
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_ACCOUNT_USABLE_RESPONSE_GRACE_LOGINS_NOT_INT.get(e), e);
            }
            break;

          case TYPE_SECONDS_UNTIL_UNLOCK:
            try
            {
              decodedSecondsUntilUnlock =
                   ASN1Integer.decodeAsInteger(element).intValue();
              if (decodedSecondsUntilUnlock < 0)
              {
                decodedSecondsUntilUnlock = -1;
              }
              else if (decodedSecondsUntilUnlock > 0)
              {
                decodedUnusableReasons.add(
                     ERR_ACCT_UNUSABLE_SECONDS_UNTIL_UNLOCK.get(
                          decodedSecondsUntilUnlock));
              }
            }
            catch (final Exception e)
            {
              Debug.debugException(e);
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_ACCOUNT_USABLE_RESPONSE_STU_NOT_INT.get(e), e);
            }
            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_ACCOUNT_USABLE_RESPONSE_MORE_INFO_INVALID_TYPE.get(
                      StaticUtils.toHex(element.getType())));
        }
      }
    }
    else
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ACCOUNT_USABLE_RESPONSE_INVALID_TYPE.get(
                StaticUtils.toHex(type)));
    }

    isUsable               = decodedIsUsable;
    secondsUntilExpiration = decodedSecondsUntilExpiration;
    isInactive             = decodedIsInactive;
    mustChangePassword     = decodedMustChangePassword;
    passwordIsExpired      = decodedPasswordIsExpired;
    remainingGraceLogins   = decodedRemainingGraceLogins;
    secondsUntilUnlock     = decodedSecondsUntilUnlock;
    unusableReasons        =
         Collections.unmodifiableList(decodedUnusableReasons);
  }



  /**
   * Creates an ASN.1 octet string that may be used as the value of an account
   * usable response control if the account is usable.
   *
   * @param  secondsUntilExpiration  The length of time in seconds until the
   *                                 user's password expires, or -1 if password
   *                                 expiration is not enabled for the user.
   *
   * @return  The ASN.1 octet string that may be used as the control value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(final int secondsUntilExpiration)
  {
    final ASN1Integer sueInteger =
         new ASN1Integer(TYPE_SECONDS_UNTIL_EXPIRATION, secondsUntilExpiration);

    return new ASN1OctetString(sueInteger.encode());
  }



  /**
   * Creates an ASN.1 octet string that may be used of the value of an account
   * usable response control if the account is not usable.
   *
   * @param  isInactive            Indicates whether the user account has been
   *                               inactivated.
   * @param  mustChangePassword    Indicates whether the user is required to
   *                               change his/her password before any other
   *                               operations will be allowed.
   * @param  passwordIsExpired     Indicates whether the user's password has
   *                               expired.
   * @param  remainingGraceLogins  The number of remaining grace logins for the
   *                               user.
   * @param  secondsUntilUnlock    The length of time in seconds until the
   *                               user's account will be automatically
   *                               unlocked.
   *
   * @return  The ASN.1 octet string that may be used as the control value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(final boolean isInactive,
                                             final boolean mustChangePassword,
                                             final boolean passwordIsExpired,
                                             final int remainingGraceLogins,
                                             final int secondsUntilUnlock)
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(5);

    if (isInactive)
    {
      elements.add(new ASN1Boolean(TYPE_IS_INACTIVE, true));
    }

    if (mustChangePassword)
    {
      elements.add(new ASN1Boolean(TYPE_MUST_CHANGE, true));
    }

    if (passwordIsExpired)
    {
      elements.add(new ASN1Boolean(TYPE_IS_EXPIRED, true));
    }

    if (remainingGraceLogins >= 0)
    {
      elements.add(new ASN1Integer(TYPE_REMAINING_GRACE_LOGINS,
                                   remainingGraceLogins));
    }

    if (secondsUntilUnlock >= 0)
    {
      elements.add(new ASN1Integer(TYPE_SECONDS_UNTIL_UNLOCK,
                                   secondsUntilUnlock));
    }

    final ASN1Sequence valueSequence =
         new ASN1Sequence(TYPE_MORE_INFO, elements);
    return new ASN1OctetString(valueSequence.encode());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public AccountUsableResponseControl decodeControl(@NotNull final String oid,
              final boolean isCritical,
              @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    return new AccountUsableResponseControl(oid, isCritical, value);
  }



  /**
   * Extracts an account usable response control from the provided search result
   * entry.
   *
   * @param  entry  The search result entry from which to retrieve the account
   *                usable response control.
   *
   * @return  The account usable response control contained in the provided
   *          search result entry, or {@code null} if the entry did not contain
   *          an account usable response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the account usable response control
   *                         contained in the provided result.
   */
  @Nullable()
  public static AccountUsableResponseControl get(
                     @NotNull final SearchResultEntry entry)
         throws LDAPException
  {
    final Control c = entry.getControl(ACCOUNT_USABLE_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof AccountUsableResponseControl)
    {
      return (AccountUsableResponseControl) c;
    }
    else
    {
      return new AccountUsableResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }



  /**
   * Indicates whether the associated user account is usable.
   *
   * @return  {@code true} if the user account is usable, or {@code false} if
   *          not.
   */
  public boolean isUsable()
  {
    return isUsable;
  }



  /**
   * Retrieves the list of reasons that this account may be unusable.
   *
   * @return  The list of reasons that this account may be unusable, or an empty
   *          list if the account is usable or no reasons are available.
   */
  @NotNull()
  public List<String> getUnusableReasons()
  {
    return unusableReasons;
  }



  /**
   * Retrieves the number of seconds until the user's password expires.  This
   * will only available if the account is usable.
   *
   * @return  The number of seconds until the user's password expires, or -1 if
   *          the user account is not usable, or if password expiration is not
   *          enabled in the directory server.
   */
  public int getSecondsUntilExpiration()
  {
    return secondsUntilExpiration;
  }



  /**
   * Indicates whether the user account has been inactivated by a server
   * administrator.
   *
   * @return  {@code true} if the user account has been inactivated by a server
   *          administrator, or {@code false} if not.
   */
  public boolean isInactive()
  {
    return isInactive;
  }



  /**
   * Indicates whether the user must change his or her password before being
   * allowed to perform any other operations.
   *
   * @return  {@code true} if the user must change his or her password before
   *          being allowed to perform any other operations, or {@code false} if
   *          not.
   */
  public boolean mustChangePassword()
  {
    return mustChangePassword;
  }



  /**
   * Indicates whether the user's password is expired.
   *
   * @return  {@code true} if the user's password is expired, or {@code false}
   *          if not.
   */
  public boolean passwordIsExpired()
  {
    return passwordIsExpired;
  }



  /**
   * Retrieves the number of remaining grace logins for the user.  This will
   * only be available if the user account is not usable.
   *
   * @return  The number of remaining grace logins for the user, or -1 if this
   *          is not available (e.g., because the account is usable or grace
   *          login functionality is disabled on the server).
   */
  public int getRemainingGraceLogins()
  {
    return remainingGraceLogins;
  }



  /**
   * Retrieves the length of time in seconds until the user's account is
   * automatically unlocked.  This will only be available if the user account is
   * not usable.
   *
   * @return  The length of time in seconds until the user's account is
   *          automatically unlocked, or -1 if this is not available (e.g.,
   *          because the account is usable, or because the account is not
   *          locked, or because automatic unlocking is disabled on the server).
   */
  public int getSecondsUntilUnlock()
  {
    return secondsUntilUnlock;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_ACCOUNT_USABLE_RESPONSE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("AccountUsableResponseControl(isUsable=");
    buffer.append(isUsable);

    if (isUsable)
    {
      if (secondsUntilExpiration >= 0)
      {
        buffer.append(", secondsUntilExpiration=");
        buffer.append(secondsUntilExpiration);
      }
    }
    else
    {
      buffer.append(", isInactive=");
      buffer.append(isInactive);
      buffer.append(", mustChangePassword=");
      buffer.append(mustChangePassword);
      buffer.append(", passwordIsExpired=");
      buffer.append(passwordIsExpired);

      if (remainingGraceLogins >= 0)
      {
        buffer.append(", remainingGraceLogins=");
        buffer.append(remainingGraceLogins);
      }

      if (secondsUntilUnlock >= 0)
      {
        buffer.append(", secondsUntilUnlock=");
        buffer.append(secondsUntilUnlock);
      }
    }

    buffer.append(')');
  }
}
