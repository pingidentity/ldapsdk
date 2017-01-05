/*
 * Copyright 2010-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2017 UnboundID Corp.
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



import com.unboundid.ldap.sdk.IntermediateResponse;
import com.unboundid.util.Extensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This interface defines a set of methods that will be invoked when an
 * intermediate response is returned in the course of processing a get changelog
 * batch extended operation.  It may be used to process changelog entries as
 * they are returned by the server rather than accessing them in a list when the
 * extended result has been received.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class is part of the Commercial Edition of the UnboundID
 *   LDAP SDK for Java.  It is not available for use in applications that
 *   include only the Standard Edition of the LDAP SDK, and is not supported for
 *   use in conjunction with non-UnboundID products.
 * </BLOCKQUOTE>
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface ChangelogEntryListener
{
  /**
   * Performs any processing necessary for a changelog entry intermediate
   * response returned by the server.
   *
   * @param  ir  The changelog entry intermediate response that was returned by
   *            the server.
   */
  void handleChangelogEntry(final ChangelogEntryIntermediateResponse ir);



  /**
   * Performs any processing necessary for a missing changelog entries
   * intermediate response returned by the server.
   *
   * @param  ir  The missing changelog entries intermediate response that was
   *             returned by the server.
   */
  void handleMissingChangelogEntries(
            final MissingChangelogEntriesIntermediateResponse ir);



  /**
   * Performs any processing necessary for some other type of intermediate
   * response returned during processing for a get changelog batch extended
   * operation.  This method may do nothing if this implementation does not
   * provide support for any other types of intermediate responses.
   *
   * @param  ir  The generic entry intermediate response that was returned by
   *             the server.
   */
  void handleOtherIntermediateResponse(final IntermediateResponse ir);
}
