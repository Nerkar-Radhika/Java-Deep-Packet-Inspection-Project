package com.radhika.dpi.parser;

import com.radhika.dpi.model.PacketInfo;

public class HTTPParser {

    private static int httpRequests = 0;

    public static void parse(byte[] raw, PacketInfo info) {

        // Parse only TCP packets
        if (!"TCP".equals(info.protocol)) {
            return;
        }

        // Parse only HTTP (Port 80)
        if (info.sourcePort != 80 && info.destinationPort != 80) {
            return;
        }

        // Minimum Ethernet + IPv4 + TCP header
        if (raw.length < 54) {
            return;
        }

        int ipHeaderLength = (raw[14] & 0x0F) * 4;
        int tcpStart = 14 + ipHeaderLength;

        // Safety check
        if (tcpStart + 13 >= raw.length) {
            return;
        }

        int tcpHeaderLength = ((raw[tcpStart + 12] >> 4) & 0x0F) * 4;
        int payloadStart = tcpStart + tcpHeaderLength;

        // No payload
        if (payloadStart >= raw.length) {
            return;
        }

        String payload = new String(
                raw,
                payloadStart,
                raw.length - payloadStart);

        String[] lines = payload.split("\r\n");

        // ---------------- HTTP REQUEST ----------------

        if (payload.startsWith("GET")
                || payload.startsWith("POST")
                || payload.startsWith("PUT")
                || payload.startsWith("DELETE")
                || payload.startsWith("HEAD")) {

            httpRequests++;

            String[] firstLine = lines[0].split(" ");

            if (firstLine.length >= 3) {

                info.httpMethod = firstLine[0];
                info.httpPath = firstLine[1];
                info.httpVersion = firstLine[2];
            }

            for (String line : lines) {

                if (line.startsWith("Host:")) {
                    info.httpHost = line.substring(5).trim();
                }

                if (line.startsWith("User-Agent:")) {
                    info.httpUserAgent = line.substring(11).trim();
                }
            }

            System.out.println("\n========== HTTP REQUEST ==========");
            System.out.println("Method      : " + info.httpMethod);
            System.out.println("Path        : " + info.httpPath);
            System.out.println("Version     : " + info.httpVersion);
            System.out.println("Host        : " + info.httpHost);
            System.out.println("User-Agent  : " + info.httpUserAgent);
            System.out.println("==================================");
        }
    }

    public static int getHttpRequests() {
        return httpRequests;
    }
}