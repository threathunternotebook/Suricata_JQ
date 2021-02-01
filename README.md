# Suricata_JQ
## The following are some helpful JSON parsing commands to read Suricata JSON formatted alert files

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
