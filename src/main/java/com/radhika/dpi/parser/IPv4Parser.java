package com.radhika.dpi.parser;

import com.radhika.dpi.model.PacketInfo;

public class IPv4Parser {

    public static void parse(byte[] raw, PacketInfo info) {

        // Source IP
        info.sourceIP = (raw[26] & 0xFF) + "." +
                (raw[27] & 0xFF) + "." +
                (raw[28] & 0xFF) + "." +
                (raw[29] & 0xFF);

        // Destination IP
        info.destinationIP = (raw[30] & 0xFF) + "." +
                (raw[31] & 0xFF) + "." +
                (raw[32] & 0xFF) + "." +
                (raw[33] & 0xFF);

        // Protocol
        int protocol = raw[23] & 0xFF;

        if (protocol == 6)
            info.protocol = "TCP";
        else if (protocol == 17)
            info.protocol = "UDP";
        else
            info.protocol = "Unknown";

    }

}
