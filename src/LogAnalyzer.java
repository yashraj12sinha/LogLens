
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class LogAnalyzer {

    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("HH:mm:ss");

    // 1. Count requests by HTTP status code
    public static void countStatusCodes(List<LogEntry> logs) {

        Map<Integer, Integer> statusCounts = new HashMap<>();

        for (LogEntry log : logs) {
            int status = log.getStatusCode();

            statusCounts.put(
                status,
                statusCounts.getOrDefault(status, 0) + 1
            );
        }

        System.out.println("\n===== REQUESTS BY STATUS CODE =====");

        statusCounts.entrySet()
            .stream()
            .sorted(Map.Entry.comparingByKey())
            .forEach(entry ->
                System.out.println(
                    entry.getKey() + ": " + entry.getValue()
                )
            );
    }

    // 2. Display the top five IP addresses and endpoints
    public static void showTopFive(List<LogEntry> logs) {

        Map<String, Integer> ipCounts = new HashMap<>();
        Map<String, Integer> endpointCounts = new HashMap<>();

        for (LogEntry log : logs) {

            String ip = log.getIpAddress();
            String endpoint = log.getEndpoint();

            ipCounts.put(
                ip,
                ipCounts.getOrDefault(ip, 0) + 1
            );

            endpointCounts.put(
                endpoint,
                endpointCounts.getOrDefault(endpoint, 0) + 1
            );
        }

        System.out.println("\n===== TOP FIVE IP ADDRESSES =====");

        ipCounts.entrySet()
            .stream()
            .sorted(
                Map.Entry.<String, Integer>comparingByValue()
                    .reversed()
            )
            .limit(5)
            .forEach(entry ->
                System.out.println(
                    entry.getKey() + ": " + entry.getValue()
                )
            );

        System.out.println("\n===== TOP FIVE ENDPOINTS =====");

        endpointCounts.entrySet()
            .stream()
            .sorted(
                Map.Entry.<String, Integer>comparingByValue()
                    .reversed()
            )
            .limit(5)
            .forEach(entry ->
                System.out.println(
                    entry.getKey() + ": " + entry.getValue()
                )
            );
    }

    // 3. Count HTTP errors for each hour
    public static void showHourlyErrors(List<LogEntry> logs) {

        Map<Integer, Integer> hourlyErrors = new HashMap<>();

        for (LogEntry log : logs) {

            if (log.getStatusCode() >= 400) {

                int hour = Integer.parseInt(
                    log.getTime().substring(0, 2)
                );

                hourlyErrors.put(
                    hour,
                    hourlyErrors.getOrDefault(hour, 0) + 1
                );
            }
        }

        System.out.println("\n===== ERRORS PER HOUR =====");

        for (int hour = 0; hour < 24; hour++) {

            System.out.printf(
                "%02d:00 - %d errors%n",
                hour,
                hourlyErrors.getOrDefault(hour, 0)
            );
        }
    }

    // 4. Find the five endpoints with the highest average response time
    public static void showSlowestEndpoints(List<LogEntry> logs) {

        Map<String, Double> totalResponseTimes = new HashMap<>();
        Map<String, Integer> endpointCounts = new HashMap<>();

        for (LogEntry log : logs) {

            String endpoint = log.getEndpoint();

            totalResponseTimes.put(
                endpoint,
                totalResponseTimes.getOrDefault(endpoint, 0.0)
                    + log.getResponseTime()
            );

            endpointCounts.put(
                endpoint,
                endpointCounts.getOrDefault(endpoint, 0) + 1
            );
        }

        System.out.println(
            "\n===== TOP FIVE SLOWEST ENDPOINTS ====="
        );

        totalResponseTimes.keySet()
            .stream()
            .map(endpoint -> Map.entry(
                endpoint,
                totalResponseTimes.get(endpoint)
                    / endpointCounts.get(endpoint)
            ))
            .sorted(
                Map.Entry.<String, Double>comparingByValue()
                    .reversed()
            )
            .limit(5)
            .forEach(entry ->
                System.out.printf(
                    "%s: %.2f ms average%n",
                    entry.getKey(),
                    entry.getValue()
                )
            );
    }

    // 5A. Generate structured security alert objects
    public static List<SecurityAlert> getSecurityAlerts(
            List<LogEntry> logs) {

        final int THRESHOLD = 5;
        final int WINDOW_SECONDS = 120;

        List<SecurityAlert> alerts = new ArrayList<>();

        Map<String, List<Integer>> failedLogins =
                new HashMap<>();

        if (logs == null || logs.isEmpty()) {
            return alerts;
        }

        // Collect failed login timestamps by IP address
        for (LogEntry log : logs) {

            if ("/api/login".equals(log.getEndpoint())
                    && log.getStatusCode() == 401) {

                try {

                    LocalTime time = LocalTime.parse(
                        log.getTime(),
                        TIME_FORMAT
                    );

                    int seconds = time.toSecondOfDay();

                    failedLogins.computeIfAbsent(
                        log.getIpAddress(),
                        key -> new ArrayList<>()
                    ).add(seconds);

                } catch (DateTimeParseException e) {

                    System.out.println(
                        "Skipping invalid login timestamp."
                    );
                }
            }
        }

        // Analyse failed login attempts for each IP
        for (Map.Entry<String, List<Integer>> entry
                : failedLogins.entrySet()) {

            List<Integer> seconds = entry.getValue();

            seconds.sort(Integer::compareTo);

            // Duplicate timestamps with an additional day
            List<Integer> extended = new ArrayList<>(seconds);

            for (int second : seconds) {
                extended.add(second + 86400);
            }

            // Check every possible two-minute window
            for (int i = 0; i < seconds.size(); i++) {

                int attempts = 0;

                for (int j = i; j < extended.size(); j++) {

                    int difference =
                        extended.get(j) - extended.get(i);

                    if (difference > WINDOW_SECONDS) {
                        break;
                    }

                    attempts++;
                }

                if (attempts >= THRESHOLD) {

                    LocalTime detectedAt =
                        LocalTime.ofSecondOfDay(seconds.get(i));

                    SecurityAlert alert = new SecurityAlert(
                        entry.getKey(),
                        "Potential Brute-Force Attack",
                        attempts,
                        "HIGH",
                        "Five or more failed login attempts "
                        + "detected within two minutes.",
                        detectedAt
                    );

                    alerts.add(alert);

                    // One alert per IP address
                    break;
                }
            }
        }

        return alerts;
    }

    // 5B. Display security alerts in the console
    public static void detectSuspiciousIPs(List<LogEntry> logs) {

        List<SecurityAlert> alerts = getSecurityAlerts(logs);

        System.out.println(
            "\n===== SECURITY MONITORING ALERTS ====="
        );

        if (alerts.isEmpty()) {

            System.out.println(
                "No suspicious login activity detected."
            );

            return;
        }

        for (SecurityAlert alert : alerts) {

            System.out.println(
                "ALERT: " + alert.getAlertType()
            );

            System.out.println(
                "IP Address: " + alert.getIpAddress()
            );

            System.out.println(
                "Failed Attempts: " + alert.getFailedAttempts()
            );

            System.out.println(
                "Severity: " + alert.getSeverity()
            );

            System.out.println(
                "Description: " + alert.getDescription()
            );

            System.out.println(
                "Detected At: " + alert.getDetectedAt()
            );

            System.out.println("-----------------------------");
        }
    }

    // 6. Filter log records by start and end times
    public static List<LogEntry> filterByTime(
            List<LogEntry> logs,
            String startTime,
            String endTime) {

        try {

            LocalTime start =
                LocalTime.parse(startTime, TIME_FORMAT);

            LocalTime end =
                LocalTime.parse(endTime, TIME_FORMAT);

            List<LogEntry> filteredLogs = new ArrayList<>();

            for (LogEntry log : logs) {

                LocalTime logTime =
                    LocalTime.parse(log.getTime(), TIME_FORMAT);

                boolean matches;

                if (!end.isBefore(start)) {

                    matches = !logTime.isBefore(start)
                            && !logTime.isAfter(end);

                } else {

                    matches = !logTime.isBefore(start)
                            || !logTime.isAfter(end);
                }

                if (matches) {
                    filteredLogs.add(log);
                }
            }

            System.out.println(
                "Records matching the time range: "
                + filteredLogs.size()
            );

            return filteredLogs;

        } catch (DateTimeParseException e) {

            System.out.println(
                "Invalid time format. Use HH:mm:ss."
            );

            return new ArrayList<>();
        }
    }

    // 7. Calculate HTTP error rate
    public static double calculateErrorRate(List<LogEntry> logs) {

        if (logs == null || logs.isEmpty()) {
            return 0.0;
        }

        long errorCount = logs.stream()
            .filter(log -> log.getStatusCode() >= 400)
            .count();

        return (errorCount * 100.0) / logs.size();
    }

    // 8. Calculate average response time
    public static double calculateAverageResponseTime(
            List<LogEntry> logs) {

        if (logs == null || logs.isEmpty()) {
            return 0.0;
        }

        return logs.stream()
            .mapToDouble(LogEntry::getResponseTime)
            .average()
            .orElse(0.0);
    }

    // 9. Calculate maximum response time
    public static double calculateMaxResponseTime(
            List<LogEntry> logs) {

        if (logs == null || logs.isEmpty()) {
            return 0.0;
        }

        return logs.stream()
            .mapToDouble(LogEntry::getResponseTime)
            .max()
            .orElse(0.0);
    }
}
