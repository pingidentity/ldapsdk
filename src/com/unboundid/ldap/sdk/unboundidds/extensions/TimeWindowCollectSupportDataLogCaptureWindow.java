/*
 * Copyright 2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2020 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.util.Date;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides a collect support data log capture window implementation
 * that indicates that the tool should capture information for a specified
 * window of time (between start and end times, inclusive) when processing a
 * {@link CollectSupportDataExtendedRequest}.
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
 *
 * @see  CollectSupportDataExtendedRequest
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class TimeWindowCollectSupportDataLogCaptureWindow
       extends CollectSupportDataLogCaptureWindow
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -989944420134047411L;



  // An ASN.1 element that provides an encoded representation of this time
  // window collect support data log capture window.
  private final ASN1Element encodedWindow;

  // The end time for the window.
  private final Long endTimeMillis;

  // The start time for the window.
  private final long startTimeMillis;



  /**
   * Creates a new instance of this collect support data log capture window
   * object that will capture log content within the specified window of time.
   *
   * @param  startTime  The time of the oldest log messages to include in the
   *                    support data archive.  It must be non-{@code null}, and
   *                    it must represent a time no earlier than midnight on
   *                    January 1, 1970, UTC.
   * @param  endTime    The time of the most recent log messages to include in
   *                    the support data archive.  This may be {@code null} if
   *                    the end time should be set to the time the
   *                    {@link CollectSupportDataExtendedRequest} was
   *                    received by the server.  If it is non-{@code null}, then
   *                    it must represent a time no earlier than the provided
   *                    start time.
   */
  public TimeWindowCollectSupportDataLogCaptureWindow(final Date startTime,
                                                      final Date endTime)
  {
    this(startTime.getTime(), (endTime == null ? null : endTime.getTime()));
  }



  /**
   * Creates a new instance of this collect support data log capture window
   * object that will capture log content within the specified window of time.
   *
   * @param  startTimeMillis  The time of the oldest log messages to include in
   *                          the support data archive, represented as the
   *                          number of milliseconds since midnight on January
   *                          1, 1970, UTC (i.e., the format used by
   *                          {@code System.currentTimeMillis()} and
   *                          {@code Date.getTime()}).
   * @param  endTimeMillis    The time of the most recent log messages to
   *                          include in the support data archive, represented
   *                          as the number of milliseconds since midnight on
   *                          January 1, 1970, UTC.  This may be {@code null} if
   *                          the end time should be set to the time the
   *                          {@link CollectSupportDataExtendedRequest} was
   *                          received by the server.  If it is
   *                          non-{@code null}, then it must be greater than or
   *                          equal to the provided start time.
   */
  public TimeWindowCollectSupportDataLogCaptureWindow(
              final long startTimeMillis, final Long endTimeMillis)
  {
    Validator.ensureTrue((startTimeMillis > 0),
         "TimeWindowCollectSupportDataLogCaptureWindow.startTimeMillis must " +
              "be greater than zero.");
    if (endTimeMillis != null)
    {
      Validator.ensureTrue((endTimeMillis >= startTimeMillis),
           "If it is provided, then" +
                "TimeWindowCollectSupportDataLogCaptureWindow.endTime must " +
                "greater than or equal to " +
                "TimeWindowCollectSupportDataLogCaptureWindow.endTime.");
    }

    this.startTimeMillis = startTimeMillis;
    this.endTimeMillis = endTimeMillis;

    if (endTimeMillis == null)
    {
      encodedWindow = new ASN1Sequence(TYPE_TIME_WINDOW,
           new ASN1OctetString(StaticUtils.encodeGeneralizedTime(
                startTimeMillis)));
    }
    else
    {
      encodedWindow = new ASN1Sequence(TYPE_TIME_WINDOW,
           new ASN1OctetString(StaticUtils.encodeGeneralizedTime(
                startTimeMillis)),
           new ASN1OctetString(StaticUtils.encodeGeneralizedTime(
                endTimeMillis)));
    }
  }



  /**
   * Retrieves the time of the oldest log messages to include in the support
   * data archive.
   *
   * @return  The time of the oldest log messages to include in the support data
   *          archive.
   */
  public Date getStartTime()
  {
    return new Date(startTimeMillis);
  }



  /**
   * Retrieves the time of the oldest log messages to include in the support
   * data archive, represented as the number of milliseconds since midnight on
   * January 1, 1970, UTC (i.e., the format used by
   * {@code System.currentTimeMillis()} and {@code Date.getTime()}).
   *
   * @return  The time of the oldest log messages to include in the support data
   *          archive, represented as the number of milliseconds since midnight
   *          on January 1, 1970, UTC.
   */
  public long getStartTimeMillis()
  {
    return startTimeMillis;
  }



  /**
   * Retrieves the time of the most recent log messages to include in the
   * support data archive, if specified.
   *
   * @return  The time of the most recent log messages to include in the
   *          support data archive, or {@code null} if the end time should be
   *          set to the time the {@link CollectSupportDataExtendedRequest} was
   *          received by the server.
   */
  public Date getEndTime()
  {
    if (endTimeMillis == null)
    {
      return null;
    }
    else
    {
      return new Date(endTimeMillis);
    }
  }



  /**
   * Retrieves the time of the most recent log messages to include in the
   * support data archive, if specified.  The value will represent the number of
   * milliseconds since midnight on January 1, 1970, UTC (i.e., the format used
   * by {@code System.currentTimeMillis()} and {@code Date.getTime()}).
   *
   * @return  The time of the most recent log messages to include in the
   *          support data archive, or {@code null} if the end time should be
   *          set to the time the {@link CollectSupportDataExtendedRequest} was
   *          received by the server.
   */
  public Long getEndTimeMillis()
  {
    return endTimeMillis;
  }



  /**
   * Decodes the provided ASN.1 element as a tool-default collect support data
   * log capture window object.
   *
   * @param  e  The ASN.1 element to be decoded.  It must not be {@code null}.
   *
   * @return  The tool-default collect support data log capture window object
   *          that was decoded.
   *
   * @throws  LDAPException  If the provided ASN.1 element cannot be decoded as
   *                         a valid tool-default collect support data log
   *                         capture window object.
   */
  static TimeWindowCollectSupportDataLogCaptureWindow
              decodeInternal(final ASN1Element e)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(e).elements();
      if (elements.length == 1)
      {
        final long startTimeMillis = decodeGeneralizedTimeString(elements[0]);
        return new TimeWindowCollectSupportDataLogCaptureWindow(startTimeMillis,
             null);
      }
      else if (elements.length == 2)
      {
        final long startTimeMillis = decodeGeneralizedTimeString(elements[0]);
        final long endTimeMillis = decodeGeneralizedTimeString(elements[1]);
        return new TimeWindowCollectSupportDataLogCaptureWindow(startTimeMillis,
             endTimeMillis);
      }
      else
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_TIME_WINDOW_CSD_LOG_WINDOW_INVALID_ELEMENT_COUNT.get(
                  elements.length));
      }
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw le;
    }
    catch (final Exception ex)
    {
      Debug.debugException(ex);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_TIME_WINDOW_CSD_LOG_WINDOW_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(ex)),
           ex);
    }
  }



  /**
   * Decodes the provided ASN.1 element as an octet string whose value is the
   * generalized time representation of a timestamp.
   *
   * @param  e  The element from which the timestamp should be extracted.
   *
   * @return  The time (in milliseconds since the epoch) represented by the
   *          timestamp.
   *
   * @throws  LDAPException  If the element value cannot be parsed as a valid
   *                         timestamp in the generalized time format.
   */
  private static long decodeGeneralizedTimeString(final ASN1Element e)
          throws LDAPException
  {
    final String timestampString =
         ASN1OctetString.decodeAsOctetString(e).stringValue();

    try
    {
      return StaticUtils.decodeGeneralizedTime(timestampString).getTime();
    }
    catch (final Exception ex)
    {
      Debug.debugException(ex);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_TIME_WINDOW_CSD_LOG_WINDOW_MALFORMED_GT.get(timestampString),
           ex);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ASN1Element encode()
  {
    return encodedWindow;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("TimeWindowCollectSupportDataLogCaptureWindow(startTime='");
    buffer.append(StaticUtils.encodeGeneralizedTime(startTimeMillis));
    buffer.append('\'');

    if (endTimeMillis != null)
    {
      buffer.append(", endTime='");
      buffer.append(StaticUtils.encodeGeneralizedTime(endTimeMillis));
      buffer.append('\'');
    }

    buffer.append(')');
  }
}
