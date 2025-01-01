/*
 * Copyright 2023-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2023-2025 Ping Identity Corporation
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
 * Copyright (C) 2023-2025 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.List;

import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedRequest;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedResult;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides a set of utility methods for following referrals received
 * in the course of processing operations.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ReferralHelper
{
  /**
   * Prevent this utility class from being instantiated.
   */
  private ReferralHelper()
  {
    // No implementation is required.
  }



  /**
   * Attempts to handle a referral received while processing the provided add
   * request.
   *
   * @param  addRequest      The add request for which the referral result was
   *                         received.  It must not be {@code null}.
   * @param  referralResult  The LDAP result containing the referrals to follow.
   *                         It must not be {@code null}.
   * @param  connection      The connection on which the referral result was
   *                         received.  It must not be {@code null}.
   *
   * @return  The result obtained while attempting to follow the referral, or
   *          the provided result if the referral could not be followed.
   */
  @NotNull()
  public static LDAPResult handleReferral(
              @NotNull final AddRequest addRequest,
              @NotNull final LDAPResult referralResult,
              @NotNull final LDAPConnection connection)
  {
    // If we've exceeded the referral hop limit, then return a result indicating
    // that the referral limit has been exceeded.
    final int depth = addRequest.getReferralDepth();
    if (depth > connection.getConnectionOptions().getReferralHopLimit())
    {
      return new LDAPResult(referralResult.getMessageID(),
           ResultCode.REFERRAL_LIMIT_EXCEEDED,
           ERR_REFERRAL_LIMIT_EXCEEDED.get(),
           referralResult.getMatchedDN(),
           referralResult.getReferralURLs(),
           referralResult.getResponseControls());
    }


    // Get the connector to use when attempting to follow referrals, and check
    // to see if it's a ReusableReferralConnector.
    final ReusableReferralConnector reusableReferralConnector;
    final ReferralConnector referralConnector =
         addRequest.getReferralConnector(connection);
    if (referralConnector instanceof ReusableReferralConnector)
    {
      reusableReferralConnector = (ReusableReferralConnector) referralConnector;
    }
    else
    {
      reusableReferralConnector = null;
    }


    // Iterate through the set of suitable URLs and use them to try to process
    // the request.
    for (final LDAPURL referralURL :
         getReferralURLs(referralResult.getReferralURLs()))
    {
      final AddRequest referralFollowingRequest;
      if (referralURL.baseDNProvided())
      {
        referralFollowingRequest = addRequest.duplicate();
        referralFollowingRequest.setDN(referralURL.getBaseDN());
      }
      else
      {
        referralFollowingRequest = addRequest;
      }

      referralFollowingRequest.setReferralDepth(depth+1);


      try
      {
        if (reusableReferralConnector == null)
        {
          final LDAPConnection referralConnection =
               referralConnector.getReferralConnection(referralURL, connection);
          try
          {
            final LDAPResult addResult = referralFollowingRequest.process(
                 referralConnection, (depth + 1));
            return addResult;
          }
          finally
          {
            referralConnection.setDisconnectInfo(DisconnectType.REFERRAL, null,
                 null);
            referralConnection.close();
          }
        }
        else
        {
          final FullLDAPInterface referralInterface =
               reusableReferralConnector.getReferralInterface(referralURL,
                    connection);
          return referralInterface.add(referralFollowingRequest);
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        if ((e instanceof LDAPException) &&
             (((LDAPException) e).getResultCode() == ResultCode.REFERRAL))
        {
          addRequest.setReferralDepth(depth + 1);
          return handleReferral(addRequest,
               ((LDAPException) e).toLDAPResult(), connection);
        }
      }
    }


    // If we've gotten here, then we couldn't follow the referral, so just
    // return the original referral result.
    return referralResult;
  }



  /**
   * Attempts to handle a referral received while processing the provided
   * compare request.
   *
   * @param  compareRequest  The compare request for which the referral result
   *                         was received.  It must not be {@code null}.
   * @param  referralResult  The compare result containing the referrals to
   *                         follow.  It must not be {@code null}.
   * @param  connection      The connection on which the referral result was
   *                         received.  It must not be {@code null}.
   *
   * @return  The result obtained while attempting to follow the referral, or
   *          the provided result if the referral could not be followed.
   */
  @NotNull()
  public static CompareResult handleReferral(
              @NotNull final CompareRequest compareRequest,
              @NotNull final CompareResult referralResult,
              @NotNull final LDAPConnection connection)
  {
    // If we've exceeded the referral hop limit, then return a result indicating
    // that the referral limit has been exceeded.
    final int depth = compareRequest.getReferralDepth();
    if (depth > connection.getConnectionOptions().getReferralHopLimit())
    {
      return new CompareResult(referralResult.getMessageID(),
           ResultCode.REFERRAL_LIMIT_EXCEEDED,
           ERR_REFERRAL_LIMIT_EXCEEDED.get(),
           referralResult.getMatchedDN(),
           referralResult.getReferralURLs(),
           referralResult.getResponseControls());
    }


    // Get the connector to use when attempting to follow referrals, and check
    // to see if it's a ReusableReferralConnector.
    final ReusableReferralConnector reusableReferralConnector;
    final ReferralConnector referralConnector =
         compareRequest.getReferralConnector(connection);
    if (referralConnector instanceof ReusableReferralConnector)
    {
      reusableReferralConnector = (ReusableReferralConnector) referralConnector;
    }
    else
    {
      reusableReferralConnector = null;
    }


    // Iterate through the set of suitable URLs and use them to try to process
    // the request.
    for (final LDAPURL referralURL :
         getReferralURLs(referralResult.getReferralURLs()))
    {
      final CompareRequest referralFollowingRequest;
      if (referralURL.baseDNProvided())
      {
        referralFollowingRequest = compareRequest.duplicate();
        referralFollowingRequest.setDN(referralURL.getBaseDN());
      }
      else
      {
        referralFollowingRequest = compareRequest;
      }

      referralFollowingRequest.setReferralDepth(depth+1);


      try
      {
        if (reusableReferralConnector == null)
        {
          final LDAPConnection referralConnection =
               referralConnector.getReferralConnection(referralURL, connection);
          try
          {
            return referralFollowingRequest.process(referralConnection,
                 (depth + 1));
          }
          finally
          {
            referralConnection.setDisconnectInfo(DisconnectType.REFERRAL, null,
                 null);
            referralConnection.close();
          }
        }
        else
        {
          final FullLDAPInterface referralInterface =
               reusableReferralConnector.getReferralInterface(referralURL,
                    connection);
          return referralInterface.compare(referralFollowingRequest);
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        if ((e instanceof LDAPException) &&
             (((LDAPException) e).getResultCode() == ResultCode.REFERRAL))
        {
          compareRequest.setReferralDepth(depth + 1);
          return handleReferral(compareRequest,
               new CompareResult((LDAPException) e), connection);
        }
      }
    }


    // If we've gotten here, then we couldn't follow the referral, so just
    // return the original referral result.
    return referralResult;
  }



  /**
   * Attempts to handle a referral received while processing the provided
   * delete request.
   *
   * @param  deleteRequest   The delete request for which the referral result
   *                         was received.  It must not be {@code null}.
   * @param  referralResult  The delete result containing the referrals to
   *                         follow.  It must not be {@code null}.
   * @param  connection      The connection on which the referral result was
   *                         received.  It must not be {@code null}.
   *
   * @return  The result obtained while attempting to follow the referral, or
   *          the provided result if the referral could not be followed.
   */
  @NotNull()
  public static LDAPResult handleReferral(
              @NotNull final DeleteRequest deleteRequest,
              @NotNull final LDAPResult referralResult,
              @NotNull final LDAPConnection connection)
  {
    // If we've exceeded the referral hop limit, then return a result indicating
    // that the referral limit has been exceeded.
    final int depth = deleteRequest.getReferralDepth();
    if (depth > connection.getConnectionOptions().getReferralHopLimit())
    {
      return new LDAPResult(referralResult.getMessageID(),
           ResultCode.REFERRAL_LIMIT_EXCEEDED,
           ERR_REFERRAL_LIMIT_EXCEEDED.get(),
           referralResult.getMatchedDN(),
           referralResult.getReferralURLs(),
           referralResult.getResponseControls());
    }


    // Get the connector to use when attempting to follow referrals, and check
    // to see if it's a ReusableReferralConnector.
    final ReusableReferralConnector reusableReferralConnector;
    final ReferralConnector referralConnector =
         deleteRequest.getReferralConnector(connection);
    if (referralConnector instanceof ReusableReferralConnector)
    {
      reusableReferralConnector = (ReusableReferralConnector) referralConnector;
    }
    else
    {
      reusableReferralConnector = null;
    }


    // Iterate through the set of suitable URLs and use them to try to process
    // the request.
    for (final LDAPURL referralURL :
         getReferralURLs(referralResult.getReferralURLs()))
    {
      final DeleteRequest referralFollowingRequest;
      if (referralURL.baseDNProvided())
      {
        referralFollowingRequest = deleteRequest.duplicate();
        referralFollowingRequest.setDN(referralURL.getBaseDN());
      }
      else
      {
        referralFollowingRequest = deleteRequest;
      }

      referralFollowingRequest.setReferralDepth(depth+1);


      try
      {
        if (reusableReferralConnector == null)
        {
          final LDAPConnection referralConnection =
               referralConnector.getReferralConnection(referralURL, connection);
          try
          {
            return referralFollowingRequest.process(referralConnection,
                 (depth + 1));
          }
          finally
          {
            referralConnection.setDisconnectInfo(DisconnectType.REFERRAL, null,
                 null);
            referralConnection.close();
          }
        }
        else
        {
          final FullLDAPInterface referralInterface =
               reusableReferralConnector.getReferralInterface(referralURL,
                    connection);
          return referralInterface.delete(referralFollowingRequest);
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        if ((e instanceof LDAPException) &&
             (((LDAPException) e).getResultCode() == ResultCode.REFERRAL))
        {
          deleteRequest.setReferralDepth(depth + 1);
          return handleReferral(deleteRequest,
               ((LDAPException) e).toLDAPResult(), connection);
        }
      }
    }


    // If we've gotten here, then we couldn't follow the referral, so just
    // return the original referral result.
    return referralResult;
  }



  /**
   * Attempts to handle a referral received while processing the provided
   * modify request.
   *
   * @param  modifyRequest   The modify request for which the referral result
   *                         was received.  It must not be {@code null}.
   * @param  referralResult  The modify result containing the referrals to
   *                         follow.  It must not be {@code null}.
   * @param  connection      The connection on which the referral result was
   *                         received.  It must not be {@code null}.
   *
   * @return  The result obtained while attempting to follow the referral, or
   *          the provided result if the referral could not be followed.
   */
  @NotNull()
  public static LDAPResult handleReferral(
              @NotNull final ModifyRequest modifyRequest,
              @NotNull final LDAPResult referralResult,
              @NotNull final LDAPConnection connection)
  {
    // If we've exceeded the referral hop limit, then return a result indicating
    // that the referral limit has been exceeded.
    final int depth = modifyRequest.getReferralDepth();
    if (depth > connection.getConnectionOptions().getReferralHopLimit())
    {
      return new LDAPResult(referralResult.getMessageID(),
           ResultCode.REFERRAL_LIMIT_EXCEEDED,
           ERR_REFERRAL_LIMIT_EXCEEDED.get(),
           referralResult.getMatchedDN(),
           referralResult.getReferralURLs(),
           referralResult.getResponseControls());
    }


    // Get the connector to use when attempting to follow referrals, and check
    // to see if it's a ReusableReferralConnector.
    final ReusableReferralConnector reusableReferralConnector;
    final ReferralConnector referralConnector =
         modifyRequest.getReferralConnector(connection);
    if (referralConnector instanceof ReusableReferralConnector)
    {
      reusableReferralConnector = (ReusableReferralConnector) referralConnector;
    }
    else
    {
      reusableReferralConnector = null;
    }


    // Iterate through the set of suitable URLs and use them to try to process
    // the request.
    for (final LDAPURL referralURL :
         getReferralURLs(referralResult.getReferralURLs()))
    {
      final ModifyRequest referralFollowingRequest;
      if (referralURL.baseDNProvided())
      {
        referralFollowingRequest = modifyRequest.duplicate();
        referralFollowingRequest.setDN(referralURL.getBaseDN());
      }
      else
      {
        referralFollowingRequest = modifyRequest;
      }

      referralFollowingRequest.setReferralDepth(depth+1);


      try
      {
        if (reusableReferralConnector == null)
        {
          final LDAPConnection referralConnection =
               referralConnector.getReferralConnection(referralURL, connection);
          try
          {
            return referralFollowingRequest.process(referralConnection,
                 (depth + 1));
          }
          finally
          {
            referralConnection.setDisconnectInfo(DisconnectType.REFERRAL, null,
                 null);
            referralConnection.close();
          }
        }
        else
        {
          final FullLDAPInterface referralInterface =
               reusableReferralConnector.getReferralInterface(referralURL,
                    connection);
          return referralInterface.modify(referralFollowingRequest);
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        if ((e instanceof LDAPException) &&
             (((LDAPException) e).getResultCode() == ResultCode.REFERRAL))
        {
          modifyRequest.setReferralDepth(depth + 1);
          return handleReferral(modifyRequest,
               ((LDAPException) e).toLDAPResult(), connection);
        }
      }
    }


    // If we've gotten here, then we couldn't follow the referral, so just
    // return the original referral result.
    return referralResult;
  }



  /**
   * Attempts to handle a referral received while processing the provided
   * modify DN request.
   *
   * @param  modifyDNRequest  The modify DN request for which the referral
   *                          result was received.  It must not be {@code null}.
   * @param  referralResult   The modify DN result containing the referrals to
   *                          follow.  It must not be {@code null}.
   * @param  connection       The connection on which the referral result was
   *                          received.  It must not be {@code null}.
   *
   * @return  The result obtained while attempting to follow the referral, or
   *          the provided result if the referral could not be followed.
   */
  @NotNull()
  public static LDAPResult handleReferral(
              @NotNull final ModifyDNRequest modifyDNRequest,
              @NotNull final LDAPResult referralResult,
              @NotNull final LDAPConnection connection)
  {
    // If we've exceeded the referral hop limit, then return a result indicating
    // that the referral limit has been exceeded.
    final int depth = modifyDNRequest.getReferralDepth();
    if (depth > connection.getConnectionOptions().getReferralHopLimit())
    {
      return new LDAPResult(referralResult.getMessageID(),
           ResultCode.REFERRAL_LIMIT_EXCEEDED,
           ERR_REFERRAL_LIMIT_EXCEEDED.get(),
           referralResult.getMatchedDN(),
           referralResult.getReferralURLs(),
           referralResult.getResponseControls());
    }


    // If we've exceeded the referral hop limit, then just return the provided
    // result.
    if (depth > connection.getConnectionOptions().getReferralHopLimit())
    {
      return referralResult;
    }


    // Get the connector to use when attempting to follow referrals, and check
    // to see if it's a ReusableReferralConnector.
    final ReusableReferralConnector reusableReferralConnector;
    final ReferralConnector referralConnector =
         modifyDNRequest.getReferralConnector(connection);
    if (referralConnector instanceof ReusableReferralConnector)
    {
      reusableReferralConnector = (ReusableReferralConnector) referralConnector;
    }
    else
    {
      reusableReferralConnector = null;
    }


    // Iterate through the set of suitable URLs and use them to try to process
    // the request.
    for (final LDAPURL referralURL :
         getReferralURLs(referralResult.getReferralURLs()))
    {
      final ModifyDNRequest referralFollowingRequest;
      if (referralURL.baseDNProvided())
      {
        referralFollowingRequest = modifyDNRequest.duplicate();
        referralFollowingRequest.setDN(referralURL.getBaseDN());
      }
      else
      {
        referralFollowingRequest = modifyDNRequest;
      }

      referralFollowingRequest.setReferralDepth(depth+1);


      try
      {
        if (reusableReferralConnector == null)
        {
          final LDAPConnection referralConnection =
               referralConnector.getReferralConnection(referralURL, connection);
          try
          {
            return referralFollowingRequest.process(referralConnection,
                 (depth + 1));
          }
          finally
          {
            referralConnection.setDisconnectInfo(DisconnectType.REFERRAL, null,
                 null);
            referralConnection.close();
          }
        }
        else
        {
          final FullLDAPInterface referralInterface =
               reusableReferralConnector.getReferralInterface(referralURL,
                    connection);
          return referralInterface.modifyDN(referralFollowingRequest);
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        if ((e instanceof LDAPException) &&
             (((LDAPException) e).getResultCode() == ResultCode.REFERRAL))
        {
          modifyDNRequest.setReferralDepth(depth + 1);
          return handleReferral(modifyDNRequest,
               ((LDAPException) e).toLDAPResult(), connection);
        }
      }
    }


    // If we've gotten here, then we couldn't follow the referral, so just
    // return the original referral result.
    return referralResult;
  }



  /**
   * Attempts to handle a referral result received while processing the provided
   * search request.
   *
   * @param  searchRequest   The search request for which the referral result
   *                         was received.  It must not be {@code null}.
   * @param  referralResult  The search result containing the referrals to
   *                         follow.  It must not be {@code null}.
   * @param  connection      The connection on which the referral result was
   *                         received.  It must not be {@code null}.
   *
   * @return  The result obtained while attempting to follow the referral, or
   *          the provided result if the referral could not be followed.
   */
  @NotNull()
  public static SearchResult handleReferral(
              @NotNull final SearchRequest searchRequest,
              @NotNull final SearchResult referralResult,
              @NotNull final LDAPConnection connection)
  {
    // If we've exceeded the referral hop limit, then return a result indicating
    // that the referral limit has been exceeded.
    final int depth = searchRequest.getReferralDepth();
    if (depth > connection.getConnectionOptions().getReferralHopLimit())
    {
      return new SearchResult(referralResult.getMessageID(),
           ResultCode.REFERRAL_LIMIT_EXCEEDED,
           ERR_REFERRAL_LIMIT_EXCEEDED.get(),
           referralResult.getMatchedDN(),
           referralResult.getReferralURLs(),
           referralResult.getEntryCount(),
           referralResult.getReferenceCount(),
           referralResult.getResponseControls());
    }


    final SearchResult result = handleReferral(searchRequest,
         getReferralURLs(referralResult.getReferralURLs()), connection);
    if (result == null)
    {
      // This indicates that we couldn't follow the referral, so just return
      // the original referral result.
      return referralResult;
    }
    else
    {
      return result;
    }
  }



  /**
   * Attempts to handle a referral result received while processing the provided
   * search request.
   *
   * @param  searchRequest    The search request for which the referral result
   *                          was received.  It must not be {@code null}.
   * @param  searchReference  The search result reference containing the
   *                          referrals to follow.  It must not be {@code null}.
   * @param  connection       The connection on which the referral result was
   *                          received.  It must not be {@code null}.
   *
   * @return  The result obtained while attempting to follow the referral, or
   *          the provided result if the referral could not be followed.
   */
  @NotNull()
  public static SearchResult handleReferral(
              @NotNull final SearchRequest searchRequest,
              @NotNull final SearchResultReference searchReference,
              @NotNull final LDAPConnection connection)
  {
    // If we've exceeded the referral hop limit, then return a result indicating
    // that the referral limit has been exceeded.
    final int depth = searchRequest.getReferralDepth();
    if (depth > connection.getConnectionOptions().getReferralHopLimit())
    {
      return new SearchResult(searchReference.getMessageID(),
           ResultCode.REFERRAL_LIMIT_EXCEEDED,
           ERR_REFERRAL_LIMIT_EXCEEDED.get(), null,
           searchReference.getReferralURLs(), 0, 0, null);
    }


    final SearchResult result = handleReferral(searchRequest,
         getReferralURLs(searchReference.getReferralURLs()), connection);
    if (result == null)
    {
      // This indicates that we couldn't follow the referral.  Construct a
      // referral result to return.
      return new SearchResult(searchReference.getMessageID(),
           ResultCode.REFERRAL, null, null, searchReference.getReferralURLs(),
           0, 0, null);
    }
    else
    {
      return result;
    }
  }



  /**
   * Attempts to handle a referral result received while processing the provided
   * search request.
   *
   * @param  searchRequest  The search request for which the referral result
   *                        was received.  It must not be {@code null}.
   * @param  referralURLs   The set of referral URLs to follow.  It must not be
   * {@code null}.
   * @param  connection     The connection on which the referral result was
   *                        received.  It must not be {@code null}.
   *
   * @return  The result obtained while attempting to follow the referral, or
   *          the provided result if the referral could not be followed.
   */
  @Nullable()
  private static SearchResult handleReferral(
              @NotNull final SearchRequest searchRequest,
              @NotNull final List<LDAPURL> referralURLs,
              @NotNull final LDAPConnection connection)
  {
    // Get the connector to use when attempting to follow referrals, and check
    // to see if it's a ReusableReferralConnector.
    final ReusableReferralConnector reusableReferralConnector;
    final ReferralConnector referralConnector =
         searchRequest.getReferralConnector(connection);
    if (referralConnector instanceof ReusableReferralConnector)
    {
      reusableReferralConnector = (ReusableReferralConnector) referralConnector;
    }
    else
    {
      reusableReferralConnector = null;
    }


    // Iterate through the set of suitable URLs and use them to try to process
    // the request.
    for (final LDAPURL referralURL : referralURLs)
    {
      final SearchRequest referralFollowingRequest = searchRequest.duplicate();
      if (referralURL.baseDNProvided())
      {
        referralFollowingRequest.setBaseDN(referralURL.getBaseDN());
      }

      if (referralURL.scopeProvided())
      {
        referralFollowingRequest.setScope(referralURL.getScope());
      }

      if (referralURL.filterProvided())
      {
        referralFollowingRequest.setFilter(referralURL.getFilter());
      }

      final int depth = searchRequest.getReferralDepth();
      referralFollowingRequest.setReferralDepth(depth + 1);

      try
      {
        if (reusableReferralConnector == null)
        {
          final LDAPConnection referralConnection =
               referralConnector.getReferralConnection(referralURL, connection);
          try
          {
            return referralFollowingRequest.process(referralConnection,
                 (depth + 1));
          }
          finally
          {
            referralConnection.setDisconnectInfo(DisconnectType.REFERRAL, null,
                 null);
            referralConnection.close();
          }
        }
        else
        {
          final FullLDAPInterface referralInterface =
               reusableReferralConnector.getReferralInterface(referralURL,
                    connection);
          return referralInterface.search(referralFollowingRequest);
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        if ((e instanceof LDAPException) &&
             (((LDAPException) e).getResultCode() == ResultCode.REFERRAL))
        {
          searchRequest.setReferralDepth(depth + 1);
          return handleReferral(searchRequest,
               new SearchResult((LDAPException) e), connection);
        }
      }
    }


    // If we've gotten here, then we couldn't follow the referral.  Just return
    // null and let the caller figure out what result to return.
    return null;
  }



  /**
   * Attempts to handle a referral received while processing the provided
   * password modify extended request.
   *
   * @param  pwModifyRequest  The password modify extended request for which the
   *                          referral was received.  It must not be
   *                          {@code null}.
   * @param  referralResult   The extended result containing the referrals to
   *                          follow.  It must not be {@code null}.
   * @param  connection       The connection on which the referral result was
   *                          received.  It must not be {@code null}.
   *
   * @return  The result obtained while attempting to follow the referral, or
   *          the provided result if the referral could not be followed.
   */
  @NotNull()
  public static PasswordModifyExtendedResult handleReferral(
              @NotNull final PasswordModifyExtendedRequest pwModifyRequest,
              @NotNull final PasswordModifyExtendedResult referralResult,
              @NotNull final LDAPConnection connection)
  {
    // If we've exceeded the referral hop limit, then return a result indicating
    // that the referral limit has been exceeded.
    final int depth = pwModifyRequest.getReferralDepth();
    if (depth > connection.getConnectionOptions().getReferralHopLimit())
    {
      return new PasswordModifyExtendedResult(referralResult.getMessageID(),
           ResultCode.REFERRAL_LIMIT_EXCEEDED,
           ERR_REFERRAL_LIMIT_EXCEEDED.get(),
           referralResult.getMatchedDN(),
           referralResult.getReferralURLs(),
           referralResult.getRawGeneratedPassword(),
           referralResult.getResponseControls());
    }


    // Get the connector to use when attempting to follow referrals, and check
    // to see if it's a ReusableReferralConnector.
    final ReusableReferralConnector reusableReferralConnector;
    final ReferralConnector referralConnector =
         pwModifyRequest.getReferralConnector(connection);
    if (referralConnector instanceof ReusableReferralConnector)
    {
      reusableReferralConnector = (ReusableReferralConnector) referralConnector;
    }
    else
    {
      reusableReferralConnector = null;
    }


    // Iterate through the set of suitable URLs and use them to try to process
    // the request.
    for (final LDAPURL referralURL :
         getReferralURLs(referralResult.getReferralURLs()))
    {
      final String userIdentity;
      if (referralURL.getBaseDN().isNullDN())
      {
        userIdentity = pwModifyRequest.getUserIdentity();
      }
      else
      {
        userIdentity = referralURL.getBaseDN().toString();
      }

      final PasswordModifyExtendedRequest referralFollowingRequest =
           new PasswordModifyExtendedRequest(userIdentity,
                pwModifyRequest.getOldPassword(),
                pwModifyRequest.getNewPassword(),
                pwModifyRequest.getControls());
      referralFollowingRequest.setResponseTimeoutMillis(
           pwModifyRequest.getResponseTimeoutMillis(connection));
      referralFollowingRequest.setIntermediateResponseListener(
           pwModifyRequest.getIntermediateResponseListener());
      referralFollowingRequest.setReferralConnector(
           pwModifyRequest.getReferralConnector(connection));
      referralFollowingRequest.setReferralDepth(depth + 1);

      try
      {
        if (reusableReferralConnector == null)
        {
          final LDAPConnection referralConnection =
               referralConnector.getReferralConnection(referralURL, connection);
          try
          {
            return referralFollowingRequest.process(referralConnection,
                 (depth + 1));
          }
          finally
          {
            referralConnection.setDisconnectInfo(DisconnectType.REFERRAL, null,
                 null);
            referralConnection.close();
          }
        }
        else
        {
          final FullLDAPInterface referralInterface =
               reusableReferralConnector.getReferralInterface(referralURL,
                    connection);
          final ExtendedResult extendedResult =
               referralInterface.processExtendedOperation(
                    referralFollowingRequest);
          if (extendedResult instanceof PasswordModifyExtendedResult)
          {
            return (PasswordModifyExtendedResult) extendedResult;
          }
          else
          {
            return new PasswordModifyExtendedResult(extendedResult);
          }
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        if ((e instanceof LDAPException) &&
             (((LDAPException) e).getResultCode() == ResultCode.REFERRAL))
        {
          pwModifyRequest.setReferralDepth(depth + 1);

          final ExtendedResult extendedResult =
               new ExtendedResult((LDAPException) e);
          try
          {
            return handleReferral(pwModifyRequest,
                 new PasswordModifyExtendedResult(extendedResult), connection);
          }
          catch (final Exception e2)
          {
            Debug.debugException(e2);
          }
        }
      }
    }


    // If we've gotten here, then we couldn't follow the referral, so just
    // return the original referral result.
    return referralResult;
  }



  /**
   * Retrieves a list of the LDAP URLs contained in the provided array of URL
   * strings.
   *
   * @param  urlStrings  An array containing the string representations of the
   *                     referral URLs that were received.  It must not be
   *                     {@code null}.
   *
   * @return  A list of the LDAP URLs contained in the provided result, or an
   *          empty list if none of the referral URLs can be parsed as a valid
   *          LDAP URL.
   */
  @NotNull()
  private static List<LDAPURL> getReferralURLs(
               @NotNull final String[] urlStrings)
  {
    final List<LDAPURL> ldapURLs = new ArrayList<>(urlStrings.length);
    for (final String urlString : urlStrings)
    {
      try
      {
        // We will only support LDAP URLs in which the hostname was specified.
        final LDAPURL ldapURL = new LDAPURL(urlString);
        if (ldapURL.hostProvided())
        {
          ldapURLs.add(ldapURL);
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }

    return ldapURLs;
  }
}
