/*
 * Copyright 2016-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2016-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tools;



import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateExtendedRequest;



/**
 * This class provides a thread that may be used to parallelize the process of
 * invoking password policy state operations.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
 * </BLOCKQUOTE>
 */
final class ManageAccountProcessorThread
       extends Thread
{
  // The manage-account processor that will actually do the majority of the
  // work.
  private final ManageAccountProcessor processor;



  /**
   * Creates a new manage-account processor thread with the provided
   * information.
   *
   * @param  threadNumber  The thread number for this thread.  This will only be
   *                       used for informational purposes in the thread name.
   * @param  processor     The manage-account processor that will actually do
   *                       the majority of the work.  It must not be
   *                       {@code null}.
   */
  ManageAccountProcessorThread(final int threadNumber,
                               final ManageAccountProcessor processor)
  {
    setName("manage-account Processor Thread " + threadNumber);

    this.processor = processor;
  }



  /**
   * Performs the processing for this thread.
   */
  @Override()
  public void run()
  {
    while (true)
    {
      final PasswordPolicyStateExtendedRequest request =
           processor.getRequest();
      if (request == null)
      {
        return;
      }
      else
      {
        processor.process(request);
      }
    }
  }
}
