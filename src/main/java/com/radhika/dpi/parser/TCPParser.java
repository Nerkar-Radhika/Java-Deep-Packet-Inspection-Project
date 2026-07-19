package com.radhika.dpi.parser;

import com.radhika.dpi.classifier.TrafficClassifier;
import com.radhika.dpi.model.PacketInfo;

public class TCPParser {

    public static void parse(byte[] raw, PacketInfo info) {

        // Only parse TCP packets
        if (!"TCP".equals(info.protocol)) {
            return;
        }

        // Source Port
        info.sourcePort =
                ((raw[34] & 0xFF) << 8) | (raw[35] & 0xFF);

        // Destination Port
        info.destinationPort =
                ((raw[36] & 0xFF) << 8) | (raw[37] & 0xFF);

        // Service
        info.service =
                TrafficClassifier.getServiceName(info.destinationPort);

        if ("Unknown".equals(info.service)) {

            info.service =
                    TrafficClassifier.getServiceName(info.sourcePort);

        }

        // Traffic Type
        info.trafficType =
                TrafficClassifier.classifyTraffic(
                        6,
                        info.sourcePort,
                        info.destinationPort);

    }

}
