package com.radhika.dpi.parser;

import com.radhika.dpi.model.PacketInfo;

public class DNSParser {

    public static boolean isDNS(PacketInfo info) {

        return info.sourcePort == 53 || info.destinationPort == 53;

    }

}