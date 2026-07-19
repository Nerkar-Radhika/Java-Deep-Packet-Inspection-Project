package com.radhika.dpi.flow;

import java.util.HashMap;
import java.util.Map;

import com.radhika.dpi.model.PacketInfo;

public class FlowManager {

    private static final Map<String, Flow> flows = new HashMap<>();

    public static void updateFlow(PacketInfo info, int packetLength) {

        String key = info.sourceIP + "-"
                + info.sourcePort + "-"
                + info.destinationIP + "-"
                + info.destinationPort + "-"
                + info.protocol;

        Flow flow = flows.get(key);

        if (flow == null) {

            flow = new Flow();

            flow.sourceIP = info.sourceIP;
            flow.destinationIP = info.destinationIP;

            flow.sourcePort = info.sourcePort;
            flow.destinationPort = info.destinationPort;

            flow.protocol = info.protocol;
            flow.service = info.service;

            flow.firstSeen = System.currentTimeMillis();
            flow.lastSeen = flow.firstSeen;

            flow.packetCount = 0;
            flow.totalBytes = 0;

            flows.put(key, flow);
        }

        flow.packetCount++;
        flow.totalBytes += packetLength;

        long now = System.currentTimeMillis();
        flow.lastSeen = now;

        // Update service if it becomes available later
        if (flow.service == null && info.service != null) {
            flow.service = info.service;
        }

        // Long-lived connection detection
        long duration = (now - flow.firstSeen) / 1000;

        if (duration >= 30 && !flow.alertShown) {

            System.out.println("\n========== SECURITY ALERT ==========");
            System.out.println("Long-Lived Connection Detected");
            System.out.println("Source      : " + flow.sourceIP + ":" + flow.sourcePort);
            System.out.println("Destination : " + flow.destinationIP + ":" + flow.destinationPort);
            System.out.println("Duration    : " + duration + " sec");
            System.out.println("====================================");

            flow.alertShown = true;
        }

        removeExpiredFlows();
    }

    private static void removeExpiredFlows() {

        long now = System.currentTimeMillis();

        flows.entrySet().removeIf(entry -> {

            Flow flow = entry.getValue();

            long idleTime = (now - flow.lastSeen) / 1000;

            return idleTime > 60;

        });
    }

    public static void printFlows() {

        System.out.println("\n========== ACTIVE FLOWS ==========");

        for (Flow flow : flows.values()) {

            System.out.println("--------------------------------");
            System.out.println("Source      : " + flow.sourceIP + ":" + flow.sourcePort);
            System.out.println("Destination : " + flow.destinationIP + ":" + flow.destinationPort);
            System.out.println("Protocol    : " + flow.protocol);
            System.out.println("Service     : " + flow.service);

            long duration = (flow.lastSeen - flow.firstSeen) / 1000;

            System.out.println("Duration    : " + duration + " sec");
            System.out.println("Packets     : " + flow.packetCount);
            System.out.println("Bytes       : " + flow.totalBytes);
        }

        System.out.println("==================================\n");
    }

    public static Map<String, Flow> getFlows() {
        return flows;
    }
}