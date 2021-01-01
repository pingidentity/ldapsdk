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

import com.unboundid.util.ByteStringBuffer;
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
 * This class provides a data structure for interacting with LDAP URLs.  It may
 * be used to encode and decode URLs, as well as access the various elements
 * that they contain.  Note that this implementation currently does not support
 * the use of extensions in an LDAP URL.
 * <BR><BR>
 * The components that may be included in an LDAP URL include:
 * <UL>
 *   <LI>Scheme -- This specifies the protocol to use when communicating with
 *       the server.  The official LDAP URL specification only allows a scheme
 *       of "{@code ldap}", but this implementation also supports the use of the
 *       "{@code ldaps}" scheme to indicate that clients should attempt to
 *       perform SSL-based communication with the target server (LDAPS) rather
 *       than unencrypted LDAP.  It will also accept "{@code ldapi}", which is
 *       LDAP over UNIX domain sockets, although the LDAP SDK does not directly
 *       support that mechanism of communication.</LI>
 *   <LI>Host -- This specifies the address of the directory server to which the
 *       URL refers.  If no host is provided, then it is expected that the
 *       client has some prior knowledge of the host (it often implies the same
 *       server from which the URL was retrieved).</LI>
 *   <LI>Port -- This specifies the port of the directory server to which the
 *       URL refers.  If no host or port is provided, then it is assumed that
 *       the client has some prior knowledge of the instance to use (it often
 *       implies the same instance from which the URL was retrieved).  If a host
 *       is provided without a port, then it should be assumed that the standard
 *       LDAP port of 389 should be used (or the standard LDAPS port of 636 if
 *       the scheme is "{@code ldaps}", or a value of 0 if the scheme is
 *       "{@code ldapi}").</LI>
 *   <LI>Base DN -- This specifies the base DN for the URL.  If no base DN is
 *       provided, then a default of the null DN should be assumed.</LI>
 *   <LI>Requested attributes -- This specifies the set of requested attributes
 *       for the URL.  If no attributes are specified, then the behavior should
 *       be the same as if no attributes had been provided for a search request
 *       (i.e., all user attributes should be included).
 *       <BR><BR>
 *       In the string representation of an LDAP URL, the names of the requested
 *       attributes (if more than one is provided) should be separated by
 *       commas.</LI>
 *   <LI>Scope -- This specifies the scope for the URL.  It should be one of the
 *       standard scope values as defined in the {@link SearchRequest}
 *       class.  If no scope is provided, then it should be assumed that a
 *       scope of {@link SearchScope#BASE} should be used.
 *       <BR><BR>
 *       In the string representation, the names of the scope values that are
 *       allowed include:
 *       <UL>
 *         <LI>base -- Equivalent to {@link SearchScope#BASE}.</LI>
 *         <LI>one -- Equivalent to {@link SearchScope#ONE}.</LI>
 *         <LI>sub -- Equivalent to {@link SearchScope#SUB}.</LI>
 *         <LI>subordinates -- Equivalent to
 *             {@link SearchScope#SUBORDINATE_SUBTREE}.</LI>
 *       </UL></LI>
 *   <LI>Filter -- This specifies the filter for the URL.  If no filter is
 *       provided, then a default of "{@code (objectClass=*)}" should be
 *       assumed.</LI>
 * </UL>
 * An LDAP URL encapsulates many of the properties of a search request, and in
 * fact the {@link LDAPURL#toSearchRequest} method may be used  to create a
 * {@link SearchRequest} object from an LDAP URL.
 * <BR><BR>
 * See <A HREF="http://www.ietf.org/rfc/rfc4516.txt">RFC 4516</A> for a complete
 * description of the LDAP URL syntax.  Some examples of LDAP URLs include:
 * <UL>
 *   <LI>{@code ldap://} -- This is the smallest possible LDAP URL that can be
 *       represented.  The default values will be used for all components other
 *       than the scheme.</LI>
 *   <LI>{@code
 *        ldap://server.example.com:1234/dc=example,dc=com?cn,sn?sub?(uid=john)}
 *       -- This is an example of a URL containing all of the elements.  The
 *       scheme is "{@code ldap}", the host is "{@code server.example.com}",
 *       the port is "{@code 1234}", the base DN is "{@code dc=example,dc=com}",
 *       the requested attributes are "{@code cn}" and "{@code sn}", the scope
 *       is "{@code sub}" (which indicates a subtree scope equivalent to
 *       {@link SearchScope#SUB}), and a filter of
 *       "{@code (uid=john)}".</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPURL
       implements Serializable
{
  /**
   * The default filter that will be used if none is provided.
   */
  @NotNull private static final Filter DEFAULT_FILTER =
       Filter.createPresenceFilter("objectClass");



  /**
   * The default port number that will be used for LDAP URLs if none is
   * provided.
   */
  public static final int DEFAULT_LDAP_PORT = 389;



  /**
   * The default port number that will be used for LDAPS URLs if none is
   * provided.
   */
  public static final int DEFAULT_LDAPS_PORT = 636;



  /**
   * The default port number that will be used for LDAPI URLs if none is
   * provided.
   */
  public static final int DEFAULT_LDAPI_PORT = 0;



  /**
   * The default scope that will be used if none is provided.
   */
  @NotNull private static final SearchScope DEFAULT_SCOPE = SearchScope.BASE;



  /**
   * The default base DN that will be used if none is provided.
   */
  @NotNull private static final DN DEFAULT_BASE_DN = DN.NULL_DN;



  /**
   * The default set of attributes that will be used if none is provided.
   */
  @NotNull private static final String[] DEFAULT_ATTRIBUTES =
       StaticUtils.NO_STRINGS;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 3420786933570240493L;



  // Indicates whether the attribute list was provided in the URL.
  private final boolean attributesProvided;

  // Indicates whether the base DN was provided in the URL.
  private final boolean baseDNProvided;

  // Indicates whether the filter was provided in the URL.
  private final boolean filterProvided;

  // Indicates whether the port was provided in the URL.
  private final boolean portProvided;

  // Indicates whether the scope was provided in the URL.
  private final boolean scopeProvided;

  // The base DN used by this URL.
  @NotNull private final DN baseDN;

  // The filter used by this URL.
  @NotNull private final Filter filter;

  // The port used by this URL.
  private final int port;

  // The search scope used by this URL.
  @NotNull private final SearchScope scope;

  // The host used by this URL.
  @Nullable private final String host;

  // The normalized representation of this LDAP URL.
  @Nullable private volatile String normalizedURLString;

  // The scheme used by this LDAP URL.  The standard only accepts "ldap", but
  // we will also accept "ldaps" and "ldapi".
  @NotNull private final String scheme;

  // The string representation of this LDAP URL.
  @NotNull private final String urlString;

  // The set of attributes included in this URL.
  @NotNull private final String[] attributes;



  /**
   * Creates a new LDAP URL from the provided string representation.
   *
   * @param  urlString  The string representation for this LDAP URL.  It must
   *                    not be {@code null}.
   *
   * @throws  LDAPException  If the provided URL string cannot be parsed as an
   *                         LDAP URL.
   */
  public LDAPURL(@NotNull final String urlString)
         throws LDAPException
  {
    Validator.ensureNotNull(urlString);

    this.urlString = urlString;


    // Find the location of the first colon.  It should mark the end of the
    // scheme.
    final int colonPos = urlString.indexOf("://");
    if (colonPos < 0)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_LDAPURL_NO_COLON_SLASHES.get());
    }

    scheme = StaticUtils.toLowerCase(urlString.substring(0, colonPos));
    final int defaultPort;
    if (scheme.equals("ldap"))
    {
      defaultPort = DEFAULT_LDAP_PORT;
    }
    else if (scheme.equals("ldaps"))
    {
      defaultPort = DEFAULT_LDAPS_PORT;
    }
    else if (scheme.equals("ldapi"))
    {
      defaultPort = DEFAULT_LDAPI_PORT;
    }
    else
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_LDAPURL_INVALID_SCHEME.get(scheme));
    }


    // Look for the first slash after the "://".  It will designate the end of
    // the hostport section.
    final int slashPos = urlString.indexOf('/', colonPos+3);
    if (slashPos < 0)
    {
      // This is fine.  It just means that the URL won't have a base DN,
      // attribute list, scope, or filter, and that the rest of the value is
      // the hostport element.
      baseDN             = DEFAULT_BASE_DN;
      baseDNProvided     = false;
      attributes         = DEFAULT_ATTRIBUTES;
      attributesProvided = false;
      scope              = DEFAULT_SCOPE;
      scopeProvided      = false;
      filter             = DEFAULT_FILTER;
      filterProvided     = false;

      final String hostPort = urlString.substring(colonPos+3);
      final StringBuilder hostBuffer = new StringBuilder(hostPort.length());
      final int portValue = decodeHostPort(hostPort, hostBuffer);
      if (portValue < 0)
      {
        port         = defaultPort;
        portProvided = false;
      }
      else
      {
        port         = portValue;
        portProvided = true;
      }

      if (hostBuffer.length() == 0)
      {
        host = null;
      }
      else
      {
        host = hostBuffer.toString();
      }
      return;
    }

    final String hostPort = urlString.substring(colonPos+3, slashPos);
    final StringBuilder hostBuffer = new StringBuilder(hostPort.length());
    final int portValue = decodeHostPort(hostPort, hostBuffer);
    if (portValue < 0)
    {
      port         = defaultPort;
      portProvided = false;
    }
    else
    {
      port         = portValue;
      portProvided = true;
    }

    if (hostBuffer.length() == 0)
    {
      host = null;
    }
    else
    {
      host = hostBuffer.toString();
    }


    // Look for the first question mark after the slash.  It will designate the
    // end of the base DN.
    final int questionMarkPos = urlString.indexOf('?', slashPos+1);
    if (questionMarkPos < 0)
    {
      // This is fine.  It just means that the URL won't have an attribute list,
      // scope, or filter, and that the rest of the value is the base DN.
      attributes         = DEFAULT_ATTRIBUTES;
      attributesProvided = false;
      scope              = DEFAULT_SCOPE;
      scopeProvided      = false;
      filter             = DEFAULT_FILTER;
      filterProvided     = false;

      baseDN = new DN(percentDecode(urlString.substring(slashPos+1)));
      baseDNProvided = (! baseDN.isNullDN());
      return;
    }

    baseDN = new DN(percentDecode(urlString.substring(slashPos+1,
                                                      questionMarkPos)));
    baseDNProvided = (! baseDN.isNullDN());


    // Look for the next question mark.  It will designate the end of the
    // attribute list.
    final int questionMark2Pos = urlString.indexOf('?', questionMarkPos+1);
    if (questionMark2Pos < 0)
    {
      // This is fine.  It just means that the URL won't have a scope or filter,
      // and that the rest of the value is the attribute list.
      scope          = DEFAULT_SCOPE;
      scopeProvided  = false;
      filter         = DEFAULT_FILTER;
      filterProvided = false;

      attributes = decodeAttributes(urlString.substring(questionMarkPos+1));
      attributesProvided = (attributes.length > 0);
      return;
    }

    attributes = decodeAttributes(urlString.substring(questionMarkPos+1,
                                                      questionMark2Pos));
    attributesProvided = (attributes.length > 0);


    // Look for the next question mark.  It will designate the end of the scope.
    final int questionMark3Pos = urlString.indexOf('?', questionMark2Pos+1);
    if (questionMark3Pos < 0)
    {
      // This is fine.  It just means that the URL won't have a filter, and that
      // the rest of the value is the scope.
      filter         = DEFAULT_FILTER;
      filterProvided = false;

      final String scopeStr =
           StaticUtils.toLowerCase(urlString.substring(questionMark2Pos+1));
      if (scopeStr.isEmpty())
      {
        scope         = SearchScope.BASE;
        scopeProvided = false;
      }
      else if (scopeStr.equals("base"))
      {
        scope         = SearchScope.BASE;
        scopeProvided = true;
      }
      else if (scopeStr.equals("one"))
      {
        scope         = SearchScope.ONE;
        scopeProvided = true;
      }
      else if (scopeStr.equals("sub"))
      {
        scope         = SearchScope.SUB;
        scopeProvided = true;
      }
      else if (scopeStr.equals("subord") || scopeStr.equals("subordinates"))
      {
        scope         = SearchScope.SUBORDINATE_SUBTREE;
        scopeProvided = true;
      }
      else
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_LDAPURL_INVALID_SCOPE.get(scopeStr));
      }
      return;
    }

    final String scopeStr = StaticUtils.toLowerCase(
         urlString.substring(questionMark2Pos+1, questionMark3Pos));
    if (scopeStr.isEmpty())
    {
      scope         = SearchScope.BASE;
      scopeProvided = false;
    }
    else if (scopeStr.equals("base"))
    {
      scope         = SearchScope.BASE;
      scopeProvided = true;
    }
    else if (scopeStr.equals("one"))
    {
      scope         = SearchScope.ONE;
      scopeProvided = true;
    }
    else if (scopeStr.equals("sub"))
    {
      scope         = SearchScope.SUB;
      scopeProvided = true;
    }
        else if (scopeStr.equals("subord") || scopeStr.equals("subordinates"))
    {
      scope         = SearchScope.SUBORDINATE_SUBTREE;
      scopeProvided = true;
    }
    else
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_LDAPURL_INVALID_SCOPE.get(scopeStr));
    }


    // The remainder of the value must be the filter.
    final String filterStr =
         percentDecode(urlString.substring(questionMark3Pos+1));
    if (filterStr.isEmpty())
    {
      filter = DEFAULT_FILTER;
      filterProvided = false;
    }
    else
    {
      filter = Filter.create(filterStr);
      filterProvided = true;
    }
  }



  /**
   * Creates a new LDAP URL with the provided information.
   *
   * @param  scheme      The scheme for this LDAP URL.  It must not be
   *                     {@code null} and must be either "ldap", "ldaps", or
   *                     "ldapi".
   * @param  host        The host for this LDAP URL.  It may be {@code null} if
   *                     no host is to be included.
   * @param  port        The port for this LDAP URL.  It may be {@code null} if
   *                     no port is to be included.  If it is provided, it must
   *                     be between 1 and 65535, inclusive.
   * @param  baseDN      The base DN for this LDAP URL.  It may be {@code null}
   *                     if no base DN is to be included.
   * @param  attributes  The set of requested attributes for this LDAP URL.  It
   *                     may be {@code null} or empty if no attribute list is to
   *                     be included.
   * @param  scope       The scope for this LDAP URL.  It may be {@code null} if
   *                     no scope is to be included.  Otherwise, it must be a
   *                     value between zero and three, inclusive.
   * @param  filter      The filter for this LDAP URL.  It may be {@code null}
   *                     if no filter is to be included.
   *
   * @throws  LDAPException  If there is a problem with any of the provided
   *                         arguments.
   */
  public LDAPURL(@NotNull final String scheme, @Nullable final String host,
                 @Nullable final Integer port, @Nullable final DN baseDN,
                 @Nullable final String[] attributes,
                 @Nullable final SearchScope scope,
                 @Nullable final Filter filter)
         throws LDAPException
  {
    Validator.ensureNotNull(scheme);

    final StringBuilder buffer = new StringBuilder();

    this.scheme = StaticUtils.toLowerCase(scheme);
    final int defaultPort;
    if (scheme.equals("ldap"))
    {
      defaultPort = DEFAULT_LDAP_PORT;
    }
    else if (scheme.equals("ldaps"))
    {
      defaultPort = DEFAULT_LDAPS_PORT;
    }
    else if (scheme.equals("ldapi"))
    {
      defaultPort = DEFAULT_LDAPI_PORT;
    }
    else
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_LDAPURL_INVALID_SCHEME.get(scheme));
    }

    buffer.append(scheme);
    buffer.append("://");

    if ((host == null) || host.isEmpty())
    {
      this.host = null;
    }
    else
    {
      this.host = host;
      buffer.append(host);
    }

    if (port == null)
    {
      this.port = defaultPort;
      portProvided = false;
    }
    else
    {
      this.port = port;
      portProvided = true;
      buffer.append(':');
      buffer.append(port);

      if ((port < 1) || (port > 65_535))
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
                                ERR_LDAPURL_INVALID_PORT.get(port));
      }
    }

    buffer.append('/');
    if (baseDN == null)
    {
      this.baseDN = DEFAULT_BASE_DN;
      baseDNProvided = false;
    }
    else
    {
      this.baseDN = baseDN;
      baseDNProvided = true;
      percentEncode(baseDN.toString(), buffer);
    }

    final boolean continueAppending;
    if (((attributes == null) || (attributes.length == 0)) && (scope == null) &&
        (filter == null))
    {
      continueAppending = false;
    }
    else
    {
      continueAppending = true;
    }

    if (continueAppending)
    {
      buffer.append('?');
    }
    if ((attributes == null) || (attributes.length == 0))
    {
      this.attributes = DEFAULT_ATTRIBUTES;
      attributesProvided = false;
    }
    else
    {
      this.attributes = attributes;
      attributesProvided = true;

      for (int i=0; i < attributes.length; i++)
      {
        if (i > 0)
        {
          buffer.append(',');
        }
        buffer.append(attributes[i]);
      }
    }

    if (continueAppending)
    {
      buffer.append('?');
    }
    if (scope == null)
    {
      this.scope = DEFAULT_SCOPE;
      scopeProvided = false;
    }
    else
    {
      switch (scope.intValue())
      {
        case 0:
          this.scope = scope;
          scopeProvided = true;
          buffer.append("base");
          break;
        case 1:
          this.scope = scope;
          scopeProvided = true;
          buffer.append("one");
          break;
        case 2:
          this.scope = scope;
          scopeProvided = true;
          buffer.append("sub");
          break;
        case 3:
          this.scope = scope;
          scopeProvided = true;
          buffer.append("subordinates");
          break;
        default:
          throw new LDAPException(ResultCode.PARAM_ERROR,
                                  ERR_LDAPURL_INVALID_SCOPE_VALUE.get(scope));
      }
    }

    if (continueAppending)
    {
      buffer.append('?');
    }
    if (filter == null)
    {
      this.filter = DEFAULT_FILTER;
      filterProvided = false;
    }
    else
    {
      this.filter = filter;
      filterProvided = true;
      percentEncode(filter.toString(), buffer);
    }

    urlString = buffer.toString();
  }



  /**
   * Decodes the provided string as a host and optional port number.
   *
   * @param  hostPort    The string to be decoded.
   * @param  hostBuffer  The buffer to which the decoded host address will be
   *                     appended.
   *
   * @return  The port number decoded from the provided string, or -1 if there
   *          was no port number.
   *
   * @throws  LDAPException  If the provided string cannot be decoded as a
   *                         hostport element.
   */
  private static int decodeHostPort(@NotNull final String hostPort,
                                    @NotNull final StringBuilder hostBuffer)
          throws LDAPException
  {
    final int length = hostPort.length();
    if (length == 0)
    {
      // It's an empty string, so we'll just use the defaults.
      return -1;
    }

    if (hostPort.charAt(0) == '[')
    {
      // It starts with a square bracket, which means that the address is an
      // IPv6 literal address.  Find the closing bracket, and the address
      // will be inside them.
      final int closingBracketPos = hostPort.indexOf(']');
      if (closingBracketPos < 0)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_LDAPURL_IPV6_HOST_MISSING_BRACKET.get());
      }

      hostBuffer.append(hostPort.substring(1, closingBracketPos).trim());
      if (hostBuffer.length() == 0)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_LDAPURL_IPV6_HOST_EMPTY.get());
      }

      // The closing bracket must either be the end of the hostport element
      // (in which case we'll use the default port), or it must be followed by
      // a colon and an integer (which will be the port).
      if (closingBracketPos == (length - 1))
      {
        return -1;
      }
      else
      {
        if (hostPort.charAt(closingBracketPos+1) != ':')
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_LDAPURL_IPV6_HOST_UNEXPECTED_CHAR.get(
                                       hostPort.charAt(closingBracketPos+1)));
        }
        else
        {
          try
          {
            final int decodedPort =
                 Integer.parseInt(hostPort.substring(closingBracketPos+2));
            if ((decodedPort >= 1) && (decodedPort <= 65_535))
            {
              return decodedPort;
            }
            else
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                                      ERR_LDAPURL_INVALID_PORT.get(
                                           decodedPort));
            }
          }
          catch (final NumberFormatException nfe)
          {
            Debug.debugException(nfe);
            throw new LDAPException(ResultCode.DECODING_ERROR,
                                    ERR_LDAPURL_PORT_NOT_INT.get(hostPort),
                                    nfe);
          }
        }
      }
    }


    // If we've gotten here, then the address is either a resolvable name or an
    // IPv4 address.  If there is a colon in the string, then it will separate
    // the address from the port.  Otherwise, the remaining value will be the
    // address and we'll use the default port.
    final int colonPos = hostPort.indexOf(':');
    if (colonPos < 0)
    {
      hostBuffer.append(hostPort);
      return -1;
    }
    else
    {
      try
      {
        final int decodedPort =
             Integer.parseInt(hostPort.substring(colonPos+1));
        if ((decodedPort >= 1) && (decodedPort <= 65_535))
        {
          hostBuffer.append(hostPort.substring(0, colonPos));
          return decodedPort;
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_LDAPURL_INVALID_PORT.get(decodedPort));
        }
      }
      catch (final NumberFormatException nfe)
      {
        Debug.debugException(nfe);
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_LDAPURL_PORT_NOT_INT.get(hostPort), nfe);
      }
    }
  }



  /**
   * Decodes the contents of the provided string as an attribute list.
   *
   * @param  s  The string to decode as an attribute list.
   *
   * @return  The array of decoded attribute names.
   *
   * @throws  LDAPException  If an error occurred while attempting to decode the
   *                         attribute list.
   */
  @NotNull()
  private static String[] decodeAttributes(@NotNull final String s)
          throws LDAPException
  {
    final int length = s.length();
    if (length == 0)
    {
      return DEFAULT_ATTRIBUTES;
    }

    final ArrayList<String> attrList = new ArrayList<>(10);
    int startPos = 0;
    while (startPos < length)
    {
      final int commaPos = s.indexOf(',', startPos);
      if (commaPos < 0)
      {
        // There are no more commas, so there can only be one attribute left.
        final String attrName = s.substring(startPos).trim();
        if (attrName.isEmpty())
        {
          // This is only acceptable if the attribute list is empty (there was
          // probably a space in the attribute list string, which is technically
          // not allowed, but we'll accept it).  If the attribute list is not
          // empty, then there were two consecutive commas, which is not
          // allowed.
          if (attrList.isEmpty())
          {
            return DEFAULT_ATTRIBUTES;
          }
          else
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                                    ERR_LDAPURL_ATTRLIST_ENDS_WITH_COMMA.get());
          }
        }
        else
        {
          attrList.add(attrName);
          break;
        }
      }
      else
      {
        final String attrName = s.substring(startPos, commaPos).trim();
        if (attrName.isEmpty())
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_LDAPURL_ATTRLIST_EMPTY_ATTRIBUTE.get());
        }
        else
        {
          attrList.add(attrName);
          startPos = commaPos+1;
          if (startPos >= length)
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                                    ERR_LDAPURL_ATTRLIST_ENDS_WITH_COMMA.get());
          }
        }
      }
    }

    final String[] attributes = new String[attrList.size()];
    attrList.toArray(attributes);
    return attributes;
  }



  /**
   * Decodes any percent-encoded values that may be contained in the provided
   * string.
   *
   * @param  s  The string to be decoded.
   *
   * @return  The percent-decoded form of the provided string.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode the
   *                         provided string.
   */
  @NotNull()
  public static String percentDecode(@NotNull final String s)
          throws LDAPException
  {
    // First, see if there are any percent characters at all in the provided
    // string.  If not, then just return the string as-is.
    int firstPercentPos = -1;
    final int length = s.length();
    for (int i=0; i < length; i++)
    {
      if (s.charAt(i) == '%')
      {
        firstPercentPos = i;
        break;
      }
    }

    if (firstPercentPos < 0)
    {
      return s;
    }

    int pos = firstPercentPos;
    final ByteStringBuffer buffer = new ByteStringBuffer(2 * length);
    buffer.append(s.substring(0, firstPercentPos));

    while (pos < length)
    {
      final char c = s.charAt(pos++);
      if (c == '%')
      {
        if (pos >= length)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_LDAPURL_HEX_STRING_TOO_SHORT.get(s));
        }

        final byte b;
        switch (s.charAt(pos++))
        {
          case '0':
            b = 0x00;
            break;
          case '1':
            b = 0x10;
            break;
          case '2':
            b = 0x20;
            break;
          case '3':
            b = 0x30;
            break;
          case '4':
            b = 0x40;
            break;
          case '5':
            b = 0x50;
            break;
          case '6':
            b = 0x60;
            break;
          case '7':
            b = 0x70;
            break;
          case '8':
            b = (byte) 0x80;
            break;
          case '9':
            b = (byte) 0x90;
            break;
          case 'a':
          case 'A':
            b = (byte) 0xA0;
            break;
          case 'b':
          case 'B':
            b = (byte) 0xB0;
            break;
          case 'c':
          case 'C':
            b = (byte) 0xC0;
            break;
          case 'd':
          case 'D':
            b = (byte) 0xD0;
            break;
          case 'e':
          case 'E':
            b = (byte) 0xE0;
            break;
          case 'f':
          case 'F':
            b = (byte) 0xF0;
            break;
          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                                    ERR_LDAPURL_INVALID_HEX_CHAR.get(
                                         s.charAt(pos-1)));
        }

        if (pos >= length)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_LDAPURL_HEX_STRING_TOO_SHORT.get(s));
        }

        switch (s.charAt(pos++))
        {
          case '0':
            buffer.append(b);
            break;
          case '1':
            buffer.append((byte) (b | 0x01));
            break;
          case '2':
            buffer.append((byte) (b | 0x02));
            break;
          case '3':
            buffer.append((byte) (b | 0x03));
            break;
          case '4':
            buffer.append((byte) (b | 0x04));
            break;
          case '5':
            buffer.append((byte) (b | 0x05));
            break;
          case '6':
            buffer.append((byte) (b | 0x06));
            break;
          case '7':
            buffer.append((byte) (b | 0x07));
            break;
          case '8':
            buffer.append((byte) (b | 0x08));
            break;
          case '9':
            buffer.append((byte) (b | 0x09));
            break;
          case 'a':
          case 'A':
            buffer.append((byte) (b | 0x0A));
            break;
          case 'b':
          case 'B':
            buffer.append((byte) (b | 0x0B));
            break;
          case 'c':
          case 'C':
            buffer.append((byte) (b | 0x0C));
            break;
          case 'd':
          case 'D':
            buffer.append((byte) (b | 0x0D));
            break;
          case 'e':
          case 'E':
            buffer.append((byte) (b | 0x0E));
            break;
          case 'f':
          case 'F':
            buffer.append((byte) (b | 0x0F));
            break;
          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                                    ERR_LDAPURL_INVALID_HEX_CHAR.get(
                                         s.charAt(pos-1)));
        }
      }
      else
      {
        buffer.append(c);
      }
    }

    return buffer.toString();
  }



  /**
   * Appends an encoded version of the provided string to the given buffer.  Any
   * special characters contained in the string will be replaced with byte
   * representations consisting of one percent sign and two hexadecimal digits
   * for each byte in the special character.
   *
   * @param  s       The string to be encoded.
   * @param  buffer  The buffer to which the encoded string will be written.
   */
  private static void percentEncode(@NotNull final String s,
                                    @NotNull final StringBuilder buffer)
  {
    final int length = s.length();
    for (int i=0; i < length; i++)
    {
      final char c = s.charAt(i);

      switch (c)
      {
        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
        case 'G':
        case 'H':
        case 'I':
        case 'J':
        case 'K':
        case 'L':
        case 'M':
        case 'N':
        case 'O':
        case 'P':
        case 'Q':
        case 'R':
        case 'S':
        case 'T':
        case 'U':
        case 'V':
        case 'W':
        case 'X':
        case 'Y':
        case 'Z':
        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
        case 'g':
        case 'h':
        case 'i':
        case 'j':
        case 'k':
        case 'l':
        case 'm':
        case 'n':
        case 'o':
        case 'p':
        case 'q':
        case 'r':
        case 's':
        case 't':
        case 'u':
        case 'v':
        case 'w':
        case 'x':
        case 'y':
        case 'z':
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
        case '-':
        case '.':
        case '_':
        case '~':
        case '!':
        case '$':
        case '&':
        case '\'':
        case '(':
        case ')':
        case '*':
        case '+':
        case ',':
        case ';':
        case '=':
          buffer.append(c);
          break;

        default:
          final byte[] charBytes =
               StaticUtils.getBytes(new String(new char[] { c }));
          for (final byte b : charBytes)
          {
            buffer.append('%');
            StaticUtils.toHex(b, buffer);
          }
          break;
      }
    }
  }



  /**
   * Retrieves the scheme for this LDAP URL.  It will either be "ldap", "ldaps",
   * or "ldapi".
   *
   * @return  The scheme for this LDAP URL.
   */
  @NotNull()
  public String getScheme()
  {
    return scheme;
  }



  /**
   * Retrieves the host for this LDAP URL.
   *
   * @return  The host for this LDAP URL, or {@code null} if the URL does not
   *          include a host and the client is supposed to have some external
   *          knowledge of what the host should be.
   */
  @Nullable()
  public String getHost()
  {
    return host;
  }



  /**
   * Indicates whether the URL explicitly included a host address.
   *
   * @return  {@code true} if the URL explicitly included a host address, or
   *          {@code false} if it did not.
   */
  public boolean hostProvided()
  {
    return (host != null);
  }



  /**
   * Retrieves the port for this LDAP URL.
   *
   * @return  The port for this LDAP URL.
   */
  public int getPort()
  {
    return port;
  }



  /**
   * Indicates whether the URL explicitly included a port number.
   *
   * @return  {@code true} if the URL explicitly included a port number, or
   *          {@code false} if it did not and the default should be used.
   */
  public boolean portProvided()
  {
    return portProvided;
  }



  /**
   * Retrieves the base DN for this LDAP URL.
   *
   * @return  The base DN for this LDAP URL.
   */
  @NotNull()
  public DN getBaseDN()
  {
    return baseDN;
  }



  /**
   * Indicates whether the URL explicitly included a base DN.
   *
   * @return  {@code true} if the URL explicitly included a base DN, or
   *          {@code false} if it did not and the default should be used.
   */
  public boolean baseDNProvided()
  {
    return baseDNProvided;
  }



  /**
   * Retrieves the attribute list for this LDAP URL.
   *
   * @return  The attribute list for this LDAP URL.
   */
  @NotNull()
  public String[] getAttributes()
  {
    return attributes;
  }



  /**
   * Indicates whether the URL explicitly included an attribute list.
   *
   * @return  {@code true} if the URL explicitly included an attribute list, or
   *          {@code false} if it did not and the default should be used.
   */
  public boolean attributesProvided()
  {
    return attributesProvided;
  }



  /**
   * Retrieves the scope for this LDAP URL.
   *
   * @return  The scope for this LDAP URL.
   */
  @NotNull()
  public SearchScope getScope()
  {
    return scope;
  }



  /**
   * Indicates whether the URL explicitly included a search scope.
   *
   * @return  {@code true} if the URL explicitly included a search scope, or
   *          {@code false} if it did not and the default should be used.
   */
  public boolean scopeProvided()
  {
    return scopeProvided;
  }



  /**
   * Retrieves the filter for this LDAP URL.
   *
   * @return  The filter for this LDAP URL.
   */
  @NotNull()
  public Filter getFilter()
  {
    return filter;
  }



  /**
   * Indicates whether the URL explicitly included a search filter.
   *
   * @return  {@code true} if the URL explicitly included a search filter, or
   *          {@code false} if it did not and the default should be used.
   */
  public boolean filterProvided()
  {
    return filterProvided;
  }



  /**
   * Creates a search request containing the base DN, scope, filter, and
   * requested attributes from this LDAP URL.
   *
   * @return  The search request created from the base DN, scope, filter, and
   *          requested attributes from this LDAP URL.
   */
  @NotNull()
  public SearchRequest toSearchRequest()
  {
    return new SearchRequest(baseDN.toString(), scope, filter, attributes);
  }



  /**
   * Retrieves a hash code for this LDAP URL.
   *
   * @return  A hash code for this LDAP URL.
   */
  @Override()
  public int hashCode()
  {
    return toNormalizedString().hashCode();
  }



  /**
   * Indicates whether the provided object is equal to this LDAP URL.  In order
   * to be considered equal, the provided object must be an LDAP URL with the
   * same normalized string representation.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is equal to this LDAP URL, or
   *          {@code false} if not.
   */
  @Override()
  public boolean equals(@Nullable final Object o)
  {
    if (o == null)
    {
      return false;
    }

    if (o == this)
    {
      return true;
    }

    if (! (o instanceof LDAPURL))
    {
      return false;
    }

    final LDAPURL url = (LDAPURL) o;
    return toNormalizedString().equals(url.toNormalizedString());
  }



  /**
   * Retrieves a string representation of this LDAP URL.
   *
   * @return  A string representation of this LDAP URL.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return urlString;
  }



  /**
   * Retrieves a normalized string representation of this LDAP URL.
   *
   * @return  A normalized string representation of this LDAP URL.
   */
  @NotNull()
  public String toNormalizedString()
  {
    if (normalizedURLString == null)
    {
      final StringBuilder buffer = new StringBuilder();
      toNormalizedString(buffer);
      normalizedURLString = buffer.toString();
    }

    return normalizedURLString;
  }



  /**
   * Appends a normalized string representation of this LDAP URL to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which to append the normalized string
   *                 representation of this LDAP URL.
   */
  public void toNormalizedString(@NotNull final StringBuilder buffer)
  {
    buffer.append(scheme);
    buffer.append("://");

    if (host != null)
    {
      if (host.indexOf(':') >= 0)
      {
        buffer.append('[');
        buffer.append(StaticUtils.toLowerCase(host));
        buffer.append(']');
      }
      else
      {
        buffer.append(StaticUtils.toLowerCase(host));
      }
    }

    if (! scheme.equals("ldapi"))
    {
      buffer.append(':');
      buffer.append(port);
    }

    buffer.append('/');
    percentEncode(baseDN.toNormalizedString(), buffer);
    buffer.append('?');

    for (int i=0; i < attributes.length; i++)
    {
      if (i > 0)
      {
        buffer.append(',');
      }

      buffer.append(StaticUtils.toLowerCase(attributes[i]));
    }

    buffer.append('?');
    switch (scope.intValue())
    {
      case 0:  // BASE
        buffer.append("base");
        break;
      case 1:  // ONE
        buffer.append("one");
        break;
      case 2:  // SUB
        buffer.append("sub");
        break;
      case 3:  // SUBORDINATE_SUBTREE
        buffer.append("subordinates");
        break;
    }

    buffer.append('?');
    percentEncode(filter.toNormalizedString(), buffer);
  }
}
