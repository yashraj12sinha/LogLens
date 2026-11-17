
import java.time.LocalTime;

public class SecurityAlert {

    private String ipAddress;
    private String alertType;
    private int failedAttempts;
    private String severity;
    private String description;
    private LocalTime detectedAt;

    // Constructor
    public SecurityAlert(
            String ipAddress,
            String alertType,
            int failedAttempts,
            String severity,
            String description,
            LocalTime detectedAt) {

        this.ipAddress = ipAddress;
        this.alertType = alertType;
        this.failedAttempts = failedAttempts;
        this.severity = severity;
        this.description = description;
        this.detectedAt = detectedAt;
    }

    // Getters
    public String getIpAddress() {
        return ipAddress;
    }

    public String getAlertType() {
        return alertType;
    }

    public int getFailedAttempts() {
        return failedAttempts;
    }

    public String getSeverity() {
        return severity;
    }

    public String getDescription() {
        return description;
    }

    public LocalTime getDetectedAt() {
        return detectedAt;
    }
}
