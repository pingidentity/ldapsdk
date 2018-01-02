/*
 * Copyright 2015-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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
package com.unboundid.util.ssl;



import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;



/**
 * This class provides a handshake completed listener for testing purposes.
 * It does nothing.
 */
public final class TestHandshakeCompletedListener
       implements HandshakeCompletedListener
{
  /**
   * Creates a new instance of this handshake completed listener.
   */
  public TestHandshakeCompletedListener()
  {
    // No implementation is required.
  }



  /**
   * Does nothing when the handshake is completed.
   *
   * @param  e  The handshake completed event.
   */
  public void handshakeCompleted(final HandshakeCompletedEvent e)
  {
    // No implementation is required.
  }
}
