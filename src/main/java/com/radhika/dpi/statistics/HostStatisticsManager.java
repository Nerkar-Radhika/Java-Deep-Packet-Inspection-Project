package com.radhika.dpi.statistics;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.HashMap;
import java.util.Map;

public class HostStatisticsManager {

    private static final Map<String, HostStatistics> hosts = new HashMap<>();

    public static void updateHost(String ip, int bytes) {

        HostStatistics host = hosts.get(ip);

        if (host == null) {

            host = new HostStatistics();
            hosts.put(ip, host);

        }

        host.packets++;
        host.bytes += bytes;
    }

    public static void printTopTalkers() {

        System.out.println("\n========== TOP TALKERS ==========");

        List<Map.Entry<String, HostStatistics>> sortedHosts = new ArrayList<>(hosts.entrySet());

        Collections.sort(sortedHosts, new Comparator<Map.Entry<String, HostStatistics>>() {
            @Override
            public int compare(Map.Entry<String, HostStatistics> e1,
                    Map.Entry<String, HostStatistics> e2) {

                return Long.compare(e2.getValue().bytes, e1.getValue().bytes);

            }
        });

        for (Map.Entry<String, HostStatistics> entry : sortedHosts) {

            System.out.println("---------------------------");
            System.out.println("Host    : " + entry.getKey());
            System.out.println("Packets : " + entry.getValue().packets);
            System.out.println("Bytes   : " + entry.getValue().bytes);
        }

        System.out.println("===============================\n");
    }

    public static String getTopTalker() {

        String topHost = "N/A";
        long maxBytes = 0;

        for (Map.Entry<String, HostStatistics> entry : hosts.entrySet()) {

            if (entry.getValue().bytes > maxBytes) {

                maxBytes = entry.getValue().bytes;
                topHost = entry.getKey();

            }
        }

        return topHost;
    }
}