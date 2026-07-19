package com.radhika.dpi.parser;

import com.radhika.dpi.model.PacketInfo;

public class EthernetParser {

    public static void parse(byte[] raw, PacketInfo info) {

        // EtherType is stored in bytes 12 and 13
        int etherType = ((raw[12] & 0xFF) << 8) | (raw[13] & 0xFF);

        switch (etherType) {

            case 0x0800:
                info.ethernetType = "IPv4";
                break;

            case 0x86DD:
                info.ethernetType = "IPv6";
                break;

            case 0x0806:
                info.ethernetType = "ARP";
                break;

            default:
                info.ethernetType = "Unknown";
                break;
        }
    }
}