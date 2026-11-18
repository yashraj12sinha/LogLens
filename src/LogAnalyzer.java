
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class LogAnalyzer {

    // Count total requests
    public int getTotalRequests(ArrayList<LogEntry> logs) {

        return logs.size();
    }

    // Count requests based on status code
    public int countStatusCode(ArrayList<LogEntry> logs,
                               int statusCode) {

        int count = 0;

        for (LogEntry entry : logs) {

            if (entry.getStatusCode() == statusCode) {
                count++;
            }
        }

        return count;
    }

    // Count unique IP addresses
    public int getUniqueIpCount(ArrayList<LogEntry> logs) {

        Set<String> uniqueIPs = new HashSet<>();

        for (LogEntry entry : logs) {

            uniqueIPs.add(entry.getIpAddress());
        }

        return uniqueIPs.size();
    }

    // Count server errors
    public int countServerErrors(ArrayList<LogEntry> logs) {

        int count = 0;

        for (LogEntry entry : logs) {

            if (entry.getStatusCode() == 500) {
                count++;
            }
        }

        return count;
    }

    // Count slow requests
    public int countSlowRequests(ArrayList<LogEntry> logs) {

        int count = 0;

        for (LogEntry entry : logs) {

            if (entry.getResponseTime() > 1000) {
                count++;
            }
        }

        return count;
    }

    // Detect repeated failed login attempts
    public Map<String, Integer> detectFailedLogins(
            ArrayList<LogEntry> logs) {

        Map<String, Integer> failedLogins = new HashMap<>();

        for (LogEntry entry : logs) {

            if (entry.getStatusCode() == 401 &&
                entry.getEndpoint().equals("/login")) {

                String ip = entry.getIpAddress();

                failedLogins.put(
                    ip,
                    failedLogins.getOrDefault(ip, 0) + 1
                );
            }
        }

        return failedLogins;
    }

    // Display suspicious IP addresses
    public void displaySuspiciousIPs(ArrayList<LogEntry> logs) {

        Map<String, Integer> failedLogins =
                detectFailedLogins(logs);

        System.out.println("\nRepeated Failed Login Attempts:");

        boolean found = false;

        for (String ip : failedLogins.keySet()) {

            if (failedLogins.get(ip) >= 3) {

                System.out.println(
                    "IP: " + ip +
                    " | Failed Attempts: " + failedLogins.get(ip)
                );

                found = true;
            }
        }

        if (!found) {
            System.out.println("No suspicious IP addresses found.");
        }
    }
}
