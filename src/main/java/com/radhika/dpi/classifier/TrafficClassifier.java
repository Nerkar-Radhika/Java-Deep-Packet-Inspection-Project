package com.radhika.dpi.classifier;

public class TrafficClassifier {

    public static String getServiceName(int port) {

        switch (port) {

            case 80:
                return "HTTP";

            case 443:
                return "HTTPS";

            case 53:
                return "DNS";

            case 67:
                return "DHCP";

            case 68:
                return "DHCP";

            case 5353:
                return "mDNS";

            case 1900:
                return "SSDP";

            case 21:
                return "FTP";

            case 22:
                return "SSH";

            case 25:
                return "SMTP";

            case 8009:
                return "Apache Tomcat (AJP)";

            case 5355:
                return "LLMNR";

            case 137:
                return "NetBIOS Name Service";

            default:
                return "Unknown";
        }
    }

    public static String classifyTraffic(int protocol,
            int srcPort,
            int dstPort) {

        if (protocol == 6) {

            if (srcPort == 443 || dstPort == 443)
                return "Secure Web Traffic (HTTPS)";

            if (srcPort == 80 || dstPort == 80)
                return "Web Traffic (HTTP)";

            if (srcPort == 22 || dstPort == 22)
                return "Remote Login (SSH)";

            if (srcPort == 21 || dstPort == 21)
                return "File Transfer (FTP)";

            if (srcPort == 8009 || dstPort == 8009)
                return "Apache Tomcat Traffic";
        }

        if (protocol == 17) {

            if (srcPort == 53 || dstPort == 53)
                return "DNS Query";

            if (srcPort == 67 || dstPort == 67 ||
                    srcPort == 68 || dstPort == 68)
                return "DHCP";

            if (srcPort == 5353 || dstPort == 5353)
                return "Local Network Discovery (mDNS)";

            if (srcPort == 1900 || dstPort == 1900)
                return "UPnP Device Discovery (SSDP)";

            if (srcPort == 5355 || dstPort == 5355)
                return "Local Name Resolution (LLMNR)";
        }

        return "Other Traffic";
    }

}
