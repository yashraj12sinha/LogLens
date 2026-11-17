
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

            ipCounts.put(ip, ipCounts.getOrDefault(ip, 0) + 1);
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

    // 5. Detect five failed logins within two minutes
    public static void detectSuspiciousIPs(List<LogEntry> logs) {

        final int THRESHOLD = 5;
        final int WINDOW_SECONDS = 120;

        Map<String, List<LocalTime>> failedLogins =
                new HashMap<>();

        for (LogEntry log : logs) {

            if ("/api/login".equals(log.getEndpoint())
                    && log.getStatusCode() == 401) {

                String ip = log.getIpAddress();

                try {
                    LocalTime time =
                            LocalTime.parse(log.getTime(), TIME_FORMAT);

                    failedLogins
                        .computeIfAbsent(
                            ip, key -> new ArrayList<>()
                        )
                        .add(time);

                } catch (DateTimeParseException e) {
                    System.out.println(
                        "Skipping invalid time for IP: " + ip
                    );
                }
            }
        }

        System.out.println(
            "\n===== SECURITY MONITORING ALERTS ====="
        );

        boolean found = false;

        for (Map.Entry<String, List<LocalTime>> entry
                : failedLogins.entrySet()) {

            List<LocalTime> times = entry.getValue();

            times.sort(LocalTime::compareTo);

            for (int i = 0; i < times.size(); i++) {

                int attempts = 1;

                for (int j = i + 1; j < times.size(); j++) {

                    long seconds = Math.abs(
                        java.time.Duration.between(
                            times.get(i), times.get(j)
                        ).getSeconds()
                    );

                    // Account for a window crossing midnight
                    seconds = Math.min(seconds, 86400 - seconds);

                    if (seconds <= WINDOW_SECONDS) {
                        attempts++;
                    } else {
                        break;
                    }
                }

                if (attempts >= THRESHOLD) {

                    System.out.println(
                        "ALERT: Potential brute-force activity"
                    );

                    System.out.println(
                        "IP Address: " + entry.getKey()
                    );

                    System.out.println(
                        "Failed Attempts: " + attempts
                    );

                    System.out.println(
                        "Time Window: 2 minutes"
                    );

                    System.out.println(
                        "Severity: HIGH"
                    );

                    System.out.println("-----------------------------");

                    found = true;
                    break;
                }
            }
        }

        if (!found) {
            System.out.println(
                "No suspicious login activity detected."
            );
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
