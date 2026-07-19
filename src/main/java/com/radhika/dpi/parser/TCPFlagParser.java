package com.radhika.dpi.parser;

import com.radhika.dpi.model.PacketInfo;

public class TCPFlagParser {

    public static void parse(byte[] raw, PacketInfo info) {

        // Parse only TCP packets
        if (!"TCP".equals(info.protocol)) {
            return;
        }

        // TCP Header starts after Ethernet + IPv4 Header
        int ipHeaderLength = (raw[14] & 0x0F) * 4;
        int tcpStart = 14 + ipHeaderLength;

        // TCP Flags
        int flags = raw[tcpStart + 13] & 0xFF;

        StringBuilder tcpFlags = new StringBuilder();

        if ((flags & 0x20) != 0)
            tcpFlags.append("URG ");

        if ((flags & 0x10) != 0)
            tcpFlags.append("ACK ");

        if ((flags & 0x08) != 0)
            tcpFlags.append("PSH ");

        if ((flags & 0x04) != 0)
            tcpFlags.append("RST ");

        if ((flags & 0x02) != 0)
            tcpFlags.append("SYN ");

        if ((flags & 0x01) != 0)
            tcpFlags.append("FIN ");

        info.tcpFlags = tcpFlags.toString().trim();
    }
}