
public class LogEntry {

    private String timestamp;
    private String ipAddress;
    private String method;
    private String endpoint;
    private int statusCode;
    private int responseTime;

    // Constructor
    public LogEntry(String timestamp, String ipAddress,
                    String method, String endpoint,
                    int statusCode, int responseTime) {

        this.timestamp = timestamp;
        this.ipAddress = ipAddress;
        this.method = method;
        this.endpoint = endpoint;
        this.statusCode = statusCode;
        this.responseTime = responseTime;
    }

    // Getter methods
    public String getTimestamp() {
        return timestamp;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getMethod() {
        return method;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public int getResponseTime() {
        return responseTime;
    }
}
