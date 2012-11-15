/*
 * Copyright (c) 2012, United States Government, as represented by the Secretary of Health and Human Services.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above
 *       copyright notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the documentation
 *       and/or other materials provided with the distribution.
 *     * Neither the name of the United States Government nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE UNITED STATES GOVERNMENT BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package gov.hhs.fha.nhinc.direct;

import javax.mail.Address;
import javax.mail.Message;
import javax.mail.Message.RecipientType;
import javax.mail.MessagingException;
import javax.mail.internet.InternetAddress;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nhindirect.stagent.AddressSource;
import org.nhindirect.stagent.NHINDAddress;
import org.nhindirect.stagent.NHINDAddressCollection;

/**
 * Helper class to provide shared utility methods for interacting with the direct code.
 */
public class DirectClientUtils {

    private static final Log LOG = LogFactory.getLog(DirectClientUtils.class);
    
    /**
     * Extract the NHINDAddressCollection from the mime headers of the message.
     * @param message mime message
     * @return NHINDAddressCollection - collection of NHIND Addresses
     * @throws MessagingException if there was an exception
     */
    protected static NHINDAddressCollection getNhindRecipients(Message message) throws MessagingException {

        NHINDAddressCollection recipients = new NHINDAddressCollection();
        addRecipients(recipients, message, RecipientType.TO, AddressSource.To);
        addRecipients(recipients, message, RecipientType.CC, AddressSource.CC);
        addRecipients(recipients, message, RecipientType.BCC, AddressSource.BCC);
        
        if (recipients.isEmpty()) {
            throw new DirectException("No recipients found in message.");
        }
        
        return recipients;
    }

    /**
     * Extract the NHINDAddress sender from the mime headers of the message.
     * @param message mime message
     * @return NHINDAddress for the sender
     * @throws MessagingException if there was an error
     */
    protected static NHINDAddress getNhindSender(Message message) throws MessagingException {
        return new NHINDAddress(new InternetAddress(getSender(message).toString()), AddressSource.From);
    }
    
    /**
     * Extract the Address for the sender from the mime headers of the message. Ensures that one and only one Sender
     * is extracted.
     * @param message mime message
     * @return Address for the sender
     * @throws MessagingException if there was an error
     */
    protected static Address getSender(Message message) throws MessagingException {
        Address[] fromAddresses = message.getFrom();
        if (fromAddresses.length != 1) {
            throw new DirectException("Expected one from address, but encountered: " + fromAddresses.length);
        }
        
        return fromAddresses[0];
    }
    
    
    private static void addRecipients(NHINDAddressCollection recipients, Message message, RecipientType type,
            AddressSource source) throws MessagingException {

        Address[] addresses = null;
        addresses = message.getRecipients(type);            
        
        if (addresses == null) {
            return;
        }
        
        for (Address address : addresses) {
            recipients.add(new NHINDAddress(address.toString(), source));
        }
    }
}
