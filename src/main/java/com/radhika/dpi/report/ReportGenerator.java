package com.radhika.dpi.report;

import java.io.FileWriter;
import java.io.IOException;
import java.util.Map;
import com.radhika.dpi.parser.HTTPParser;
import com.radhika.dpi.security.PortScanDetector;

import com.radhika.dpi.statistics.HostStatisticsManager;
import com.radhika.dpi.flow.Flow;
import com.radhika.dpi.flow.FlowManager;

public class ReportGenerator {

    public static void exportCSV() {

        try {

            FileWriter writer = new FileWriter("dpi_report.csv");

            writer.write(
                    "Source IP,Destination IP,Source Port,Destination Port,Protocol,Service,Packets,Bytes,Duration(sec)\n");

            for (Map.Entry<String, Flow> entry : FlowManager.getFlows().entrySet()) {

                Flow flow = entry.getValue();

                long duration = (flow.lastSeen - flow.firstSeen) / 1000;

                writer.write(
                        flow.sourceIP + "," +
                                flow.destinationIP + "," +
                                flow.sourcePort + "," +
                                flow.destinationPort + "," +
                                flow.protocol + "," +
                                flow.service + "," +
                                flow.packetCount + "," +
                                flow.totalBytes + "," +
                                duration + "\n");
            }

            writer.close();

            System.out.println("\nCSV Report Generated Successfully!");

        } catch (IOException e) {

            e.printStackTrace();

        }

    }

    public static void exportHTML() {

        try {

            int totalFlows = FlowManager.getFlows().size();

            int tcpFlows = 0;
            int udpFlows = 0;

            long totalPackets = 0;
            long totalBytes = 0;

            int portScanAlerts = PortScanDetector.getTotalAlerts();
            int suspiciousHosts = PortScanDetector.getSuspiciousHosts();
            int httpRequests = HTTPParser.getHttpRequests();
            String topTalker = HostStatisticsManager.getTopTalker();

            for (Flow flow : FlowManager.getFlows().values()) {

                if ("TCP".equals(flow.protocol))
                    tcpFlows++;

                if ("UDP".equals(flow.protocol))
                    udpFlows++;

                totalPackets += flow.packetCount;
                totalBytes += flow.totalBytes;
            }

            FileWriter writer = new FileWriter("dpi_dashboard.html");
            writer.write("<!DOCTYPE html>");
            writer.write("<html>");
            writer.write("<head>");

            writer.write("<meta charset='UTF-8'>");
            writer.write("<meta name='viewport' content='width=device-width, initial-scale=1.0'>");

            writer.write("<title>DPI Dashboard</title>");

            writer.write("<script src='https://cdn.jsdelivr.net/npm/chart.js'></script>");

            writer.write("<style>");
            writer.write("*{margin:0;padding:0;box-sizing:border-box;}");

            writer.write("body{");
            writer.write("font-family:Arial,Helvetica,sans-serif;");
            writer.write("background:#eef2f7;");
            writer.write("padding:30px;");
            writer.write("color:#333;");
            writer.write("}");

            writer.write("h1{");
            writer.write("text-align:center;");
            writer.write("margin-bottom:25px;");
            writer.write("color:#2c3e50;");
            writer.write("}");

            writer.write(".summary{");
            writer.write("display:flex;");
            writer.write("justify-content:space-between;");
            writer.write("gap:20px;");
            writer.write("flex-wrap:wrap;");
            writer.write("margin-bottom:30px;");
            writer.write("}");

            writer.write(".card{");
            writer.write("flex:1;");
            writer.write("min-width:180px;");
            writer.write("min-height:100px;");
            writer.write("background:white;");
            writer.write("padding:15px;");
            writer.write("border-radius:12px;");
            writer.write("box-shadow:0 3px 10px rgba(0,0,0,0.15);");
            writer.write("text-align:center;");
            writer.write("transition:0.3s;");
            writer.write("}");

            writer.write(".card:hover{");
            writer.write("transform:translateY(-5px);");
            writer.write("}");

            writer.write(".card h2{");
            writer.write("font-size:18px;");
            writer.write("margin-bottom:12px;");
            writer.write("color:#3498db;");
            writer.write("}");

            writer.write(".card p{");
            writer.write("font-size:28px;");
            writer.write("font-weight:bold;");
            writer.write("}");

            writer.write(".chart-container{");
            writer.write("display:flex;");
            writer.write("justify-content:space-between;");
            writer.write("gap:30px;");
            writer.write("margin-bottom:30px;");
            writer.write("flex-wrap:wrap;");
            writer.write("}");

            writer.write(".chart-box{");
            writer.write("flex:1;");
            writer.write("min-width:420px;");
            writer.write("background:white;");
            writer.write("padding:20px;");
            writer.write("height:380px;");
            writer.write("position:relative;");
            writer.write("border-radius:12px;");
            writer.write("box-shadow:0 3px 10px rgba(0,0,0,0.15);");
            writer.write("}");

            writer.write("input{");
            writer.write("width:100%;");
            writer.write("padding:12px;");
            writer.write("font-size:16px;");
            writer.write("margin-bottom:20px;");
            writer.write("border:1px solid #ccc;");
            writer.write("border-radius:8px;");
            writer.write("}");

            writer.write("table{");
            writer.write("width:100%;");
            writer.write("border-collapse:collapse;");
            writer.write("background:white;");
            writer.write("box-shadow:0 3px 10px rgba(0,0,0,0.15);");
            writer.write("}");

            writer.write("th{");
            writer.write("background:#3498db;");
            writer.write("color:white;");
            writer.write("padding:12px;");
            writer.write("}");

            writer.write("td{");
            writer.write("padding:10px;");
            writer.write("border-bottom:1px solid #ddd;");
            writer.write("text-align:center;");
            writer.write("}");

            writer.write("tr:hover{");
            writer.write("background:#f5f5f5;");
            writer.write("}");

            writer.write(".tcp{");
            writer.write("background:#3498db;");
            writer.write("color:white;");
            writer.write("padding:4px 10px;");
            writer.write("border-radius:15px;");
            writer.write("}");

            writer.write(".udp{");
            writer.write("background:#2ecc71;");
            writer.write("color:white;");
            writer.write("padding:4px 10px;");
            writer.write("border-radius:15px;");
            writer.write("}");

            writer.write(".http{");
            writer.write("background:#f39c12;");
            writer.write("color:white;");
            writer.write("padding:4px 10px;");
            writer.write("border-radius:15px;");
            writer.write("}");

            writer.write(".https{");
            writer.write("background:#9b59b6;");
            writer.write("color:white;");
            writer.write("padding:4px 10px;");
            writer.write("border-radius:15px;");
            writer.write("}");

            writer.write("@media(max-width:900px){");
            writer.write(".summary{flex-direction:column;}");
            writer.write(".chart-container{flex-direction:column;}");
            writer.write("}");

            writer.write(".danger{border-top:5px solid #e74c3c;}");
            writer.write(".warning{border-top:5px solid #f39c12;}");
            writer.write(".success{border-top:5px solid #27ae60;}");
            writer.write(".info{border-top:5px solid #8e44ad;}");
            writer.write(".primary{border-top:5px solid #2980b9;}");

            writer.write("</style>");
            writer.write("</head>");
            writer.write("<body>");

            writer.write("<h2 style='text-align:center;color:#2c3e50;'>Threat Dashboard</h2>");

            writer.write("<div class='summary'>");

            writer.write("<div class='card danger'>");
            writer.write("<h3>🚨 Port Scan Alerts</h3>");
            writer.write("<h1>" + portScanAlerts + "</h1>");
            writer.write("</div>");

            writer.write("<div class='card warning'>");
            writer.write("<h3>🌐 HTTP Requests</h3>");
            writer.write("<h1>" + httpRequests + "</h1>");
            writer.write("</div>");

            writer.write("<div class='card success'>");
            writer.write("<h3>🔄 Active Flows</h3>");
            writer.write("<h1>" + totalFlows + "</h1>");
            writer.write("</div>");

            writer.write("<div class='card info'>");
            writer.write("<h3>⚠️ Suspicious Hosts</h3>");
            writer.write("<h1>" + suspiciousHosts + "</h1>");
            writer.write("</div>");

            writer.write("<div class='card primary'>");
            writer.write("<h3>🖥 Top Talker</h3>");
            writer.write("<h4>" + topTalker + "</h4>");
            writer.write("</div>");

            writer.write("</div>");

            writer.write("<h1>Deep Packet Inspection Dashboard</h1>");

            writer.write("<div class='summary'>");

            writer.write("<div class='card'>");
            writer.write("<h2>Total Flows</h2>");
            writer.write("<p>" + totalFlows + "</p>");
            writer.write("</div>");

            writer.write("<div class='card'>");
            writer.write("<h2>TCP Flows</h2>");
            writer.write("<p>" + tcpFlows + "</p>");
            writer.write("</div>");

            writer.write("<div class='card'>");
            writer.write("<h2>UDP Flows</h2>");
            writer.write("<p>" + udpFlows + "</p>");
            writer.write("</div>");

            writer.write("<div class='card'>");
            writer.write("<h2>Total Packets</h2>");
            writer.write("<p>" + totalPackets + "</p>");
            writer.write("</div>");

            writer.write("<div class='card'>");
            writer.write("<h2>Total Bytes</h2>");
            writer.write("<p>" + totalBytes + "</p>");
            writer.write("</div>");

            writer.write("<div class='chart-container'>");

            writer.write("<div class='chart-box'>");
            writer.write("<canvas id='protocolChart'></canvas>");
            writer.write("</div>");

            writer.write("<div class='chart-box'>");
            writer.write("<canvas id='trafficChart'></canvas>");
            writer.write("</div>");

            writer.write("</div>");

            /* ================= SEARCH ================= */

            writer.write("<input type='text' id='searchBox' ");
            writer.write("placeholder='Search by IP, Protocol or Service...' ");
            writer.write("onkeyup='searchTable()'>");

            /* ================= TABLE ================= */

            writer.write("<table id='flowTable'>");

            writer.write("<thead>");

            writer.write("<tr>");

            writer.write("<th>Source IP</th>");
            writer.write("<th>Destination IP</th>");
            writer.write("<th>Source Port</th>");
            writer.write("<th>Destination Port</th>");
            writer.write("<th>Protocol</th>");
            writer.write("<th>Service</th>");
            writer.write("<th>Packets</th>");
            writer.write("<th>Bytes</th>");
            writer.write("<th>Duration(s)</th>");

            writer.write("</tr>");

            writer.write("</thead>");

            writer.write("<tbody>");

            for (Map.Entry<String, Flow> entry : FlowManager.getFlows().entrySet()) {

                Flow flow = entry.getValue();

                long duration = (flow.lastSeen - flow.firstSeen) / 1000;

                String protocolBadge;

                if ("TCP".equalsIgnoreCase(flow.protocol)) {

                    protocolBadge = "<span class='tcp'>TCP</span>";

                } else if ("UDP".equalsIgnoreCase(flow.protocol)) {

                    protocolBadge = "<span class='udp'>UDP</span>";

                } else {

                    protocolBadge = flow.protocol;

                }

                String service = flow.service;

                if (service == null || service.isEmpty()) {
                    service = "-";
                }

                writer.write("<tr>");

                writer.write("<td>" + flow.sourceIP + "</td>");

                writer.write("<td>" + flow.destinationIP + "</td>");

                writer.write("<td>" + flow.sourcePort + "</td>");

                writer.write("<td>" + flow.destinationPort + "</td>");

                writer.write("<td>" + protocolBadge + "</td>");

                writer.write("<td>" + service + "</td>");

                writer.write("<td>" + flow.packetCount + "</td>");

                writer.write("<td>" + flow.totalBytes + "</td>");

                writer.write("<td>" + duration + "</td>");

                writer.write("</tr>");

            }

            writer.write("</tbody>");

            writer.write("</table>");

            writer.write("<script>");

            /* ================= SEARCH ================= */

            writer.write("function searchTable(){");
            writer.write("let input=document.getElementById('searchBox').value.toUpperCase();");
            writer.write("let table=document.getElementById('flowTable');");
            writer.write("let tr=table.getElementsByTagName('tr');");

            writer.write("for(let i=1;i<tr.length;i++){");
            writer.write("let td=tr[i].getElementsByTagName('td');");
            writer.write("let found=false;");

            writer.write("for(let j=0;j<td.length;j++){");
            writer.write("if(td[j]){");
            writer.write("let txt=td[j].innerText;");
            writer.write("if(txt.toUpperCase().indexOf(input)>-1){");
            writer.write("found=true;");
            writer.write("}");
            writer.write("}");
            writer.write("}");

            writer.write("tr[i].style.display=found?'':'none';");
            writer.write("}");
            writer.write("}");

            /* ================= PIE CHART ================= */

            writer.write("new Chart(document.getElementById('protocolChart'),{");
            writer.write("type:'pie',");
            writer.write("data:{");
            writer.write("labels:['TCP','UDP'],");
            writer.write("datasets:[{");
            writer.write("data:[" + tcpFlows + "," + udpFlows + "],");
            writer.write("backgroundColor:['#3498db','#2ecc71']");
            writer.write("}]");
            writer.write("},");
            writer.write("options:{");
            writer.write("plugins:{");
            writer.write("title:{");
            writer.write("display:true,");
            writer.write("text:'Protocol Distribution'");
            writer.write("}");
            writer.write("}");
            writer.write("}");
            writer.write("});");

            /* ================= BAR CHART ================= */

            writer.write("new Chart(document.getElementById('trafficChart'),{");
            writer.write("type:'bar',");
            writer.write("data:{");
            writer.write("labels:['Packets','Bytes'],");
            writer.write("datasets:[{");
            writer.write("label:'Traffic Statistics',");
            writer.write("data:[" + totalPackets + "," + totalBytes + "],");
            writer.write("backgroundColor:['#f39c12','#9b59b6']");
            writer.write("}]");
            writer.write("},");
            writer.write("options:{");
            writer.write("responsive:true,");
            writer.write("plugins:{");
            writer.write("title:{");
            writer.write("display:true,");
            writer.write("text:'Traffic Overview'");
            writer.write("}");
            writer.write("}");
            writer.write("}");
            writer.write("});");

            writer.write("</script>");

            writer.write("</body>");
            writer.write("</html>");

            writer.close();

            System.out.println("HTML Dashboard Generated Successfully!");

        } catch (

        IOException e) {

            e.printStackTrace();

        }

    }
}