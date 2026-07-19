package com.radhika.dpi.security;

import java.util.HashMap;
import java.util.Map;

import com.radhika.dpi.model.PacketInfo;

public class PortScanDetector {

    private static final Map<String, PortScanInfo> scanners = new HashMap<>();

    public static void detect(PacketInfo info) {

        // Detect only TCP packets
        if (!"TCP".equals(info.protocol)) {
            return;
        }

        String sourceIP = info.sourceIP;

        PortScanInfo scanner = scanners.get(sourceIP);

        if (scanner == null) {
            scanner = new PortScanInfo();
            scanners.put(sourceIP, scanner);
        }

        scanner.packets++;

        // Generic Port Scan
        scanner.ports.add(info.destinationPort);

        // ---------------- SYN Scan ----------------
        if (info.tcpFlags != null
                && info.tcpFlags.contains("SYN")
                && !info.tcpFlags.contains("ACK")) {

            scanner.synPorts.add(info.destinationPort);

            if (scanner.synPorts.size() >= 10) {

                System.out.println("\n========== SECURITY ALERT ==========");
                System.out.println("Possible SYN Scan Detected");
                System.out.println("Scanner IP : " + sourceIP);
                System.out.println("Unique SYN Ports : " + scanner.synPorts.size());
                System.out.println("====================================");

                scanner.alerts++;
                scanner.synPorts.clear();
            }
        }

        // ---------------- FIN Scan ----------------
        if (info.tcpFlags != null
                && "FIN".equals(info.tcpFlags)) {

            scanner.finPorts.add(info.destinationPort);

            if (scanner.finPorts.size() >= 10) {

                System.out.println("\n========== SECURITY ALERT ==========");
                System.out.println("Possible FIN Scan Detected");
                System.out.println("Scanner IP : " + sourceIP);
                System.out.println("Unique FIN Ports : " + scanner.finPorts.size());
                System.out.println("====================================");

                scanner.alerts++;
                scanner.finPorts.clear();
            }
        }

        // ---------------- NULL Scan ----------------
        if (info.tcpFlags == null || info.tcpFlags.isEmpty()) {

            scanner.nullPorts.add(info.destinationPort);

            if (scanner.nullPorts.size() >= 10) {

                System.out.println("\n========== SECURITY ALERT ==========");
                System.out.println("Possible NULL Scan Detected");
                System.out.println("Scanner IP : " + sourceIP);
                System.out.println("Unique NULL Ports : " + scanner.nullPorts.size());
                System.out.println("====================================");

                scanner.alerts++;
                scanner.nullPorts.clear();
            }
        }

        // ---------------- XMAS Scan ----------------
        if (info.tcpFlags != null
                && info.tcpFlags.contains("FIN")
                && info.tcpFlags.contains("PSH")
                && info.tcpFlags.contains("URG")) {

            scanner.xmasPorts.add(info.destinationPort);

            if (scanner.xmasPorts.size() >= 10) {

                System.out.println("\n========== SECURITY ALERT ==========");
                System.out.println("Possible XMAS Scan Detected");
                System.out.println("Scanner IP : " + sourceIP);
                System.out.println("Unique XMAS Ports : " + scanner.xmasPorts.size());
                System.out.println("====================================");

                scanner.alerts++;
                scanner.xmasPorts.clear();
            }
        }

        // ---------------- Generic Port Scan ----------------
        if (scanner.ports.size() >= 10) {

            System.out.println("\n========== SECURITY ALERT ==========");
            System.out.println("Possible Port Scan Detected");
            System.out.println("Scanner IP : " + sourceIP);
            System.out.println("Unique Ports : " + scanner.ports.size());
            System.out.println("====================================");

            scanner.alerts++;

            scanner.ports.clear();
            scanner.packets = 0;
        }
    }

    public static int getTotalAlerts() {

        int total = 0;

        for (PortScanInfo info : scanners.values()) {
            total += info.alerts;
        }

        return total;
    }

    public static int getSuspiciousHosts() {

        int count = 0;

        for (PortScanInfo info : scanners.values()) {

            if (info.alerts > 0) {
                count++;
            }
        }

        return count;
    }
}