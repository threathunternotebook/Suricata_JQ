# Suricata_JQ
## The following are some helpful JSON parsing commands to read Suricata JSON formatted alert files. All IP addresses in these examples are not representitave of any organizational network and are for demonstration purposes only.

Search for alerts with a specific signature.  Print out the Source and destination IP along with the alert signature along with a header.
<pre><code>echo -e "  Count\tSourceIP\tDestIP\t\tAlertSignature\n" && cat eve-2020-01-27-03:11.json | jq -j 'select(.alert.signature == "ET USER_AGENTS WinRM User Agent Detected - Possible Lateral Movement") | .src_ip, "\t", .dest_ip, "\t", .alert.signature, "\n"' | sort | uniq -c | sort -nr</code></pre>

Search for all alerts with a severity of 1.  Print out the Source and destination IP along with the alert signature along with a header.
<pre><code>echo -e "  Count\tSourceIP\tDestIP\t\tAlertSignature\n" && cat eve-2020-01-27-03:11.json | jq -j 'select(.alert.severity == 1) | .src_ip, "\t", .dest_ip, "\t", .alert.signature, "\n"' | sort | uniq -c | sort -nr</code></pre>

Search for all alerts with a signature severity of "Major".  Print out the Source and destination IP address along with the alert signature # and severity along with a header.
<pre><code>echo -e "  Count\tSourceIP\tDestIP\t\tAlertSignature\t\tSignatureSeverity\n" && cat eve-2020-01-27-03:11.json | jq -j 'select(.alert.metadata.signature_severity[0] == "Major") | .src_ip, "\t", .dest_ip, "\t", .alert.signature, "\t", .alert.metadata.signature_severity[0], "\n"' | sort | uniq -c | sort -nr</code></pre>

Print out the payload of a specific signature alert
<pre><code>cat eve-2020-01-27-03:11.json | jq 'select(.alert.signature_id == 2009702) |.payload_printable'</code></pre>

Sort alerts with an alert severity of 1
<pre><code>cat eve-2020-01-27-03:11.json | jq 'select(.alert.severity == 1) | .alert.signature' | sort | uniq</code></pre>

Search for an alert severity of 1 or 2 and print out the alert signature with the severity
<pre><code>cat eve-2020-01-27-03:11.json | jq -j 'select((.alert.severity == 1) or .alert.severity == 2) | .alert.signature, "\t", .alert.severity, "\n"'</code></pre>

Search for all suricata Major signature severities and print them out to a csv file called top_alerts.csv
<pre><code>echo -e "  Count,SourceIP,DestIP,AlertSignature,SignatureSeverity\n" > /home/hunter/top_alerts.csv && cat *.json | jq -j 'select(.alert.metadata.signature_severity[0] == "Major") | ",", .src_ip, ",", .dest_ip, ",", .alert.signature, ",", .alert.metadata.signature_severity[0], "\n"' | sort | uniq -c | sort -nr >> /home/hunter/top_alerts.csv</code></pre>

Print Suricata alert signatures and signature IDs in tab-delimited format. 
<pre><code>zcat *.gz | jq -j '"\t", .alert.signature_id, "\t", .alert.signature, "\n"' | sort | uniq -c | sort -nr</code></pre>

Search all Suricata logs looking for alert signatures and IDs. Do not print out network scanners 192.168.50.50-59
<pre><code>zcat *.gz | jq -j 'select((.src_ip != "192.168.50.50") and (.src_ip != "192.168.50.51") and (.src_ip != "192.168.50.52") and (.src_ip != "192.168.50.53") and (.src_ip != "192.168.50.54") and (.src_ip != "192.168.50.55") and (.src_ip != "192.168.50.56") and (.src_ip != "192.168.50.57") and (.src_ip != "192.168.50.58") and (.src_ip != "192.168.50.59"))  | "\t", .src_ip, "\t", .dest_ip, "\t", .alert.signature_id, "\t", .alert.signature, "\n"' | sort | uniq -c | sort -nr</code></pre>

Pull the source IP address from Suricata alerts and correlate with Zeek Conn log activity.
<pre><code>cat *.json | jq '.src_ip' | tr -d "\"" | sort -u | while read line; do ls -ld /nsm/zeek/logs/2022-* | awk '{print $9}' | while read line2; do zcat $line2/conn.* | jq -j --arg src_ip $line 'select(.["id.orig_h"] == $src_ip) | "\t", .["id.orig_h"], "\t", .["id.orig_p"], "\t", .["id.resp_h"], "\t", .["id.resp_p"], "\t", .proto, "\n"' ;done;done | sort | uniq -c | sort -nr</code></pre>
    
