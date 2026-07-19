package com.radhika.dpi.parser;

import com.radhika.dpi.classifier.TrafficClassifier;
import com.radhika.dpi.model.PacketInfo;

public class UDPParser {

    public static void parse(byte[] raw, PacketInfo info) {

        if (!"UDP".equals(info.protocol)) {
            return;
        }

        // UDP Header starts immediately after IPv4 Header (20 bytes)
        // Ethernet Header = 14 bytes
        // Therefore UDP starts at byte 34

        info.sourcePort =
                ((raw[34] & 0xFF) << 8) | (raw[35] & 0xFF);

        info.destinationPort =
                ((raw[36] & 0xFF) << 8) | (raw[37] & 0xFF);

        info.service =
                TrafficClassifier.getServiceName(info.destinationPort);

        if ("Unknown".equals(info.service)) {

            info.service =
                    TrafficClassifier.getServiceName(info.sourcePort);

        }

        info.trafficType =
                TrafficClassifier.classifyTraffic(
                        17,
                        info.sourcePort,
                        info.destinationPort);

    }

}
