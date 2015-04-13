/*
 * Copyright 2011-2014 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2011-2014 UnboundID Corp.
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
package com.unboundid.ldap.listener;



import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.matchingrules.OctetStringMatchingRule;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedRequest;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedResult;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.StaticUtils ;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.listener.ListenerMessages.*;



/**
 * This class provides an implementation of an extended operation handler for
 * the in-memory directory server that can be used to process the password
 * modify extended operation as defined in
 * <A HREF="http://www.ietf.org/rfc/rfc3062.txt">RFC 3062</A>.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PasswordModifyExtendedOperationHandler
       extends InMemoryExtendedOperationHandler
{
  /**
   * Creates a new instance of this extended operation handler.
   */
  public PasswordModifyExtendedOperationHandler()
  {
    // No initialization is required.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getExtendedOperationHandlerName()
  {
    return "Password Modify";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public List<String> getSupportedExtendedRequestOIDs()
  {
    return Arrays.asList(
         PasswordModifyExtendedRequest.PASSWORD_MODIFY_REQUEST_OID);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ExtendedResult processExtendedOperation(
                             final InMemoryRequestHandler handler,
                             final int messageID, final ExtendedRequest request)
  {
    // This extended operation handler does not support any controls.  If the
    // request has any critical controls, then reject it.
    for (final Control c : request.getControls())
    {
      if (c.isCritical())
      {
        return new ExtendedResult(messageID,
             ResultCode.UNAVAILABLE_CRITICAL_EXTENSION,
             ERR_PW_MOD_EXTOP_UNSUPPORTED_CONTROL.get(c.getOID()),
             null, null, null, null, null);
      }
    }


    // Decode the request.
    final PasswordModifyExtendedRequest pwModRequest;
    try
    {
      pwModRequest = new PasswordModifyExtendedRequest(request);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      return new ExtendedResult(messageID, le.getResultCode(),
           le.getDiagnosticMessage(), le.getMatchedDN(), le.getReferralURLs(),
           null, null, null);
    }


    // Get the elements of the request.
    final String userIdentity = pwModRequest.getUserIdentity();
    final byte[] oldPWBytes = pwModRequest.getOldPasswordBytes();
    final byte[] newPWBytes = pwModRequest.getNewPasswordBytes();


    // Determine the DN of the target user.
    final DN targetDN;
    if (userIdentity == null)
    {
      targetDN = handler.getAuthenticatedDN();
    }
    else
    {
      // The user identity should generally be a DN, but we'll also allow an
      // authorization ID.
      DN authDN;
      try
      {
        authDN = new DN(userIdentity, handler.getSchema());
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        try
        {
          authDN = handler.getDNForAuthzID(userIdentity);
        }
        catch (final LDAPException le2)
        {
          Debug.debugException(le2);
          return new PasswordModifyExtendedResult(messageID,
               ResultCode.INVALID_DN_SYNTAX,
               ERR_PW_MOD_EXTOP_CANNOT_PARSE_USER_IDENTITY.get(userIdentity),
               null, null, null, null);
        }
      }
      targetDN = authDN;
    }

    if ((targetDN == null) || targetDN.isNullDN())
    {
      return new PasswordModifyExtendedResult(messageID,
           ResultCode.UNWILLING_TO_PERFORM, ERR_PW_MOD_NO_IDENTITY.get(),
           null, null, null, null);
    }

    final Entry userEntry = handler.getEntry(targetDN);
    if (userEntry == null)
    {
      return new PasswordModifyExtendedResult(messageID,
           ResultCode.UNWILLING_TO_PERFORM,
           ERR_PW_MOD_EXTOP_CANNOT_GET_USER_ENTRY.get(targetDN.toString()),
           null, null, null, null);
    }


    // If an old password was provided, then validate it.  If not, then
    // determine whether it is acceptable for no password to have been given.
    if (oldPWBytes == null)
    {
      if (handler.getAuthenticatedDN().isNullDN())
      {
        return new PasswordModifyExtendedResult(messageID,
             ResultCode.UNWILLING_TO_PERFORM,
             ERR_PW_MOD_EXTOP_NO_AUTHENTICATION.get(), null, null, null, null);
      }
    }
    else
    {
      if (! userEntry.hasAttributeValue("userPassword", oldPWBytes,
           OctetStringMatchingRule.getInstance()))
      {
        return new PasswordModifyExtendedResult(messageID,
             ResultCode.INVALID_CREDENTIALS, null, null, null, null, null);
      }
    }


    // If no new password was provided, then generate a random password to use.
    final byte[] pwBytes;
    final ASN1OctetString genPW;
    if (newPWBytes == null)
    {
      final SecureRandom random = new SecureRandom();
      final byte[] pwAlphabet = StaticUtils.getBytes(
           "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
      pwBytes = new byte[8];
      for (int i=0; i < pwBytes.length; i++)
      {
        pwBytes[i] = pwAlphabet[random.nextInt(pwAlphabet.length)];
      }
      genPW = new ASN1OctetString(pwBytes);
    }
    else
    {
      genPW   = null;
      pwBytes = newPWBytes;
    }


    // Attempt to modify the user password.
    try
    {
      handler.modifyEntry(userEntry.getDN(), Arrays.asList(new Modification(
           ModificationType.REPLACE, "userPassword", pwBytes)));
      return new PasswordModifyExtendedResult(messageID, ResultCode.SUCCESS,
           null, null, null, genPW, null);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      return new PasswordModifyExtendedResult(messageID, le.getResultCode(),
           ERR_PW_MOD_EXTOP_CANNOT_CHANGE_PW.get(userEntry.getDN(),
                le.getMessage()),
           null, null, null, null);
    }
  }
}
